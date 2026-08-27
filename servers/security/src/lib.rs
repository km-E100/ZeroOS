//! # zero-securityd —— Zero OS 用户与安全策略守护进程（EL0 服务）
//!
//! 由 launchd 经系统调用 20（`SpawnService`）从 rootfs
//! （`/System/Core/zero-securityd`）拉起，监听
//! `SECURITY_USER_REQ`/`SECURITY_USER_RESP`(0x230/0x231) 通道，
//! 提供用户增删/密码/校验/列表命令。
//!
//! ## 启动数据
//!
//! 内核 `spawn_user_from_bootfs` 以 x0/x1 传入本进程私有的 bootfs
//! 文件表（`UserBootFs`，见 zero-abi::bootfs）：用户数据库默认值从
//! 表内 `/etc/users` 读取。**不引用内核专属符号**
//! `__zero_rootfs_image`——那是内核 .rodata.boot 段的符号，用户态
//! ELF 链接期无法解析（历史遗留缺陷，本轮改为 bootfs 参数契约）。
//!
//! ## 持久化
//!
//! 用户库落盘为固定布局（跨启动 ABI，编解码在 [`zero_abi::userdb`]）：
//! LBA 4096 起头部扇区（magic `SUD1` + 版本 + 记录区扇区数），随后是
//! 记录扇区（`name:encoded-password:role\n` 行集）。写入顺序**先记录后头部**
//! （头部即提交标记）；写后读回逐字节自检。加载时 magic 校验失败
//! ⇒ 视为首启/损坏，用内置默认表播种并写回。选址避开 virtio-blk
//! 自检扇区（LBA 2048）与旧版 userdb 区（LBA 128），依据见
//! `zero_abi::userdb` 模块文档。无盘环境下读写失败均优雅降级：
//! 内存态继续服务，控制台如实告警。
#![no_std]

use core::cmp::min;
use core::slice;
use ed25519_dalek::{Signature, VerifyingKey};

use heapless::{String, Vec};
use spin::Mutex;
use userlib;
use zero_abi::bootfs::UserBootFile;
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::security::{
    self, encode_token, parse_cap_issue, parse_token, CapIssueRequest,
};
use zero_zfs_core::crypto::sha256;

const USERNAME_MAX: usize = 16;
const PASSWORD_INPUT_MAX: usize = 64;
const PASSWORD_MAX: usize = 80;
const PASSWORD_PREFIX: &str = "$zero$sha256$";
const PASSWORD_DOMAIN: &[u8] = b"zero-os-userdb-v2";
const USER_CAPACITY: usize = 8;
const LIST_BUFFER: usize = 256;
const PKG_TRUST_ORIGIN: &[u8] = b"zero-os";
const PKG_ZERO_OS_PUBLIC_KEY: [u8; 32] = [
    0x5e, 0x0a, 0x4d, 0x36, 0xe2, 0x2c, 0x3a, 0xf5, 0x5b, 0xad, 0xa3, 0xf8, 0x81, 0x45, 0xe3, 0x22,
    0xfe, 0x3c, 0xca, 0x8a, 0x0c, 0x3c, 0x06, 0xfe, 0x8b, 0x14, 0x35, 0x1e, 0x91, 0xef, 0x2a, 0xd2,
];

/// 能力令牌台账容量（与内核 MAX_GRANTS 同量级；heapless 定长无堆）。
const CAP_LEDGER_CAP: usize = 16;

// ── userdb 磁盘布局（第七刀，编解码契约在 zero_abi::userdb）────────
//   LBA 4096      头部扇区：magic "SUD1" | version | 记录区扇区数
//   LBA 4097..    记录区：USERDB_RECORD_SECTORS 个扇区的文本行集
// 选址依据（避开三方数据，详见 zero_abi::userdb 模块文档）：
//   MBR/GPT 区 < LBA 2048（驱动自检扇区）< LBA 4096（本区）。
//   旧版布局（LBA 128 起、无头部裸文本）废弃；旧数据区不迁移——
//   首启时本区无有效 magic，自动走默认表播种 + 写回。
const USERDB_HDR_LBA: u64 = zero_abi::userdb::HDR_LBA;
const USERDB_RECORD_LBA: u64 = USERDB_HDR_LBA + 1;
const USERDB_SECTOR_SIZE: usize = zero_abi::userdb::SECTOR;
/// 记录区扇区数（容量 4KiB ≈ 百余条用户记录，远超 USER_CAPACITY）。
const USERDB_RECORD_SECTORS: usize = 8;
/// 记录区字节容量。
const USERDB_RECORD_BYTES: usize = USERDB_SECTOR_SIZE * USERDB_RECORD_SECTORS;

/// 512 字节对齐缓冲：块层传输缓冲必须按扇区对齐（当前内核经弹跳区
/// 拷贝，用户侧对齐属纵深防御——未来直通 DMA 时调用方无需改动）。
#[repr(C, align(512))]
struct SectorAligned<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SectorAligned<N> {
    fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserRole {
    Admin,
    User,
}

impl UserRole {
    fn from_str(value: &str) -> Option<Self> {
        match value {
            "admin" => Some(Self::Admin),
            "user" => Some(Self::User),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
        }
    }
}

#[derive(Copy, Clone)]
struct AuthRecord {
    pid: u64,
    role: UserRole,
}

const AUTH_CAPACITY: usize = 32;
static AUTHZ: Mutex<Vec<AuthRecord, AUTH_CAPACITY>> = Mutex::new(Vec::new());

fn remember_authenticated(pid: u64, role: UserRole) {
    let mut auth = AUTHZ.lock();
    if let Some(row) = auth.iter_mut().find(|r| r.pid == pid) {
        row.role = role;
        return;
    }
    if auth.len() == auth.capacity() {
        // Bounded table: evict the oldest row rather than silently granting nobody.
        auth.remove(0);
    }
    let _ = auth.push(AuthRecord { pid, role });
}

fn authenticated_role(pid: u64) -> Option<UserRole> {
    AUTHZ.lock().iter().find(|r| r.pid == pid).map(|r| r.role)
}

fn is_admin(pid: u64) -> bool {
    authenticated_role(pid) == Some(UserRole::Admin)
}

fn cap_issue_allowed(sender: u64, role: Option<UserRole>, req: &CapIssueRequest) -> bool {
    let login_self =
        req.caps == zero_abi::cap::CAP_SESSION && req.target_pid == sender && role.is_some();
    let admin_grant = role == Some(UserRole::Admin) && req.caps != zero_abi::cap::CAP_SESSION;
    login_self || admin_grant
}

fn password_digest(username: &str, password: &str) -> Option<[u8; 32]> {
    if password.is_empty() || password.len() > PASSWORD_INPUT_MAX || username.len() > USERNAME_MAX {
        return None;
    }
    // Fixed stack buffer: avoid target-dependent collection behavior in the
    // credential hot path. Layout is exactly:
    // domain || NUL || username || NUL || password.
    let mut input = [0u8; 160];
    let mut n = 0usize;
    let mut append = |bytes: &[u8]| -> Option<()> {
        let end = n.checked_add(bytes.len())?;
        if end > input.len() {
            return None;
        }
        input[n..end].copy_from_slice(bytes);
        n = end;
        Some(())
    };
    append(PASSWORD_DOMAIN)?;
    append(&[0])?;
    append(username.as_bytes())?;
    append(&[0])?;
    append(password.as_bytes())?;
    Some(sha256(&input[..n]))
}

fn password_hash(username: &str, password: &str) -> Option<String<PASSWORD_MAX>> {
    let digest = password_digest(username, password)?;
    let mut encoded = [0u8; PASSWORD_MAX];
    let prefix = PASSWORD_PREFIX.as_bytes();
    encoded[..prefix.len()].copy_from_slice(prefix);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut off = prefix.len();
    for byte in digest {
        encoded[off] = HEX[(byte >> 4) as usize];
        encoded[off + 1] = HEX[(byte & 0xf) as usize];
        off += 2;
    }
    let text = core::str::from_utf8(&encoded[..off]).ok()?;
    let mut out = String::<PASSWORD_MAX>::new();
    out.push_str(text).ok()?;
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_encoded_digest(field: &str) -> Option<[u8; 32]> {
    let hex = field.strip_prefix(PASSWORD_PREFIX)?.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(hex[i * 2])? << 4) | hex_nibble(hex[i * 2 + 1])?;
    }
    Some(out)
}

fn encoded_password(field: &str) -> bool {
    parse_encoded_digest(field).is_some()
}

fn normalize_password(username: &str, field: &str) -> Option<String<PASSWORD_MAX>> {
    if encoded_password(field) {
        let mut out = String::<PASSWORD_MAX>::new();
        out.push_str(field).ok()?;
        Some(out)
    } else {
        password_hash(username, field)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Clone)]
struct UserRecord {
    username: String<USERNAME_MAX>,
    password: String<PASSWORD_MAX>,
    role: UserRole,
}

impl UserRecord {
    fn build(username: &str, password: &str, role: UserRole) -> Result<Self, ()> {
        if username.is_empty()
            || username.len() > USERNAME_MAX
            || password.is_empty()
            || !username
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err(());
        }
        let mut name = String::<USERNAME_MAX>::new();
        name.push_str(username).map_err(|_| ())?;
        let pwd = normalize_password(username, password).ok_or(())?;
        Ok(Self {
            username: name,
            password: pwd,
            role,
        })
    }
}

struct UserStore {
    records: Vec<UserRecord, USER_CAPACITY>,
}

impl UserStore {
    const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    fn find_index(&self, name: &str) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.username.as_str() == name)
    }
}

static USERS: Mutex<UserStore> = Mutex::new(UserStore::new());
static PASSWORD_MIGRATION_NEEDED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// 能力令牌台账行（securityd 侧镜像）：内核台账（号位 40/41 落账）
/// 是唯一权威，本表只服务 `CMD_CAP_LIST`/`CMD_CAP_VERIFY` 的可观测性
/// 与审计——两侧一致性由"签发即落账、撤销即标废"的操作顺序保证。
#[derive(Copy, Clone)]
struct CapLedgerEntry {
    token: u64,
    target_pid: u64,
    caps: u32,
    /// 已撤销（CMD_CAP_REVOKE 成功后置位；不删行保留审计痕迹）。
    revoked: bool,
}

static CAP_LEDGER: Mutex<Vec<CapLedgerEntry, CAP_LEDGER_CAP>> = Mutex::new(Vec::new());

/// 控制台横幅/告警（log crate 无 logger 后端时是静默 no-op，
/// 生命周期关键行必须走 console_write 才能上串口）。
fn println(text: &str) {
    let _ = userlib::console_write(text.as_bytes());
    let _ = userlib::console_write(b"\r\n");
}

pub extern "C" fn server_main(bootfs_ptr: u64, bootfs_len: u64) -> ! {
    init_user_store(bootfs_ptr, bootfs_len);
    println("Zero OS securityd (EL0 service) online");
    println("  channel req=0x230 resp=0x231; auth/userdb/cap-issuance ready");
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive_from(channels::SECURITY_USER_REQ, &mut message) {
            Ok(sender) => {
                process_command(sender, &mut message);
                // SECURITY_USER_RESP is shared by shell/pkgd/other clients.
                // Replies must be targeted to the kernel-authenticated requester;
                // an untargeted envelope can be consumed by another CPU/client.
                let _ = userlib::ipc_send_to(channels::SECURITY_USER_RESP, sender, &message);
            }
            Err(_) => userlib::yield_now(),
        }
    }
}

/// 启动期用户库装载结果（决定横幅文案与是否回写默认表）。
enum RestoreOutcome {
    /// 从盘恢复成功：携带 (记录数, 用户名清单) 供横幅展示——清单
    /// 直接证明数据来自盘而非默认表（跨启动持久化的实机验收点）。
    Restored {
        count: usize,
        names: String<LIST_BUFFER>,
    },
    /// 块设备在但无有效 SUD1 头部（首启/旧布局/损坏）→ 播种默认表。
    NoValidHeader,
    /// 块设备不可用（ISO 直启、未挂盘）→ 降级为内存态并告警。
    IoUnavailable,
}

fn init_user_store(bootfs_ptr: u64, bootfs_len: u64) {
    match load_persisted_records() {
        RestoreOutcome::Restored { count, names } => {
            println("securityd: userdb restored from persistent store");
            // names 来自盘上记录区——若默认表已不含其中某个名字而它仍在，
            // 即为跨启动持久化成立的直接证据（第七刀实机验证项）。
            println("  LBA=4096 records; users:");
            println(names.as_str());
            let _ = count;
            if PASSWORD_MIGRATION_NEEDED.swap(false, core::sync::atomic::Ordering::SeqCst) {
                println("securityd: migrating legacy plaintext credentials");
                persist_users();
            }
            return;
        }
        RestoreOutcome::NoValidHeader => {
            println("securityd: no valid userdb header on blk (first boot?)");
        }
        RestoreOutcome::IoUnavailable => {
            println("securityd: warning: block device unavailable for userdb");
        }
    }
    if load_rootfs_defaults(bootfs_ptr, bootfs_len) {
        println("securityd: seeded default users from /etc/users");
        // 把默认用户写进持久层；无盘环境下失败仅告警，不影响在线。
        persist_users();
    } else {
        println("securityd: warning: user database empty; provisioning required");
    }
}

/// 从块设备加载用户库：校验头部 magic/版本 → 读记录区 → 解析入内存。
fn load_persisted_records() -> RestoreOutcome {
    let mut header = SectorAligned::<{ USERDB_SECTOR_SIZE }>::zeroed();
    if userlib::block_read(USERDB_HDR_LBA, &mut header.bytes).is_err() {
        return RestoreOutcome::IoUnavailable;
    }
    let Some(record_sectors) = zero_abi::userdb::parse_header(&header.bytes) else {
        return RestoreOutcome::NoValidHeader;
    };
    // 头部声明超出本进程布局上限 ⇒ 视为损坏（不信任外来计数越界读）。
    if record_sectors as usize > USERDB_RECORD_SECTORS {
        return RestoreOutcome::NoValidHeader;
    }
    let region_len = record_sectors as usize * USERDB_SECTOR_SIZE;
    let mut data = SectorAligned::<USERDB_RECORD_BYTES>::zeroed();
    if userlib::block_read(USERDB_RECORD_LBA, &mut data.bytes[..region_len]).is_err() {
        return RestoreOutcome::IoUnavailable;
    }
    let used = match data.bytes[..region_len].iter().rposition(|byte| *byte != 0) {
        Some(pos) => pos + 1,
        None => return RestoreOutcome::NoValidHeader,
    };
    if !apply_user_blob(&data.bytes[..used]) {
        return RestoreOutcome::NoValidHeader;
    }
    let store = USERS.lock();
    let mut names = String::<LIST_BUFFER>::new();
    for record in store.records.iter() {
        if !names.is_empty() {
            let _ = names.push_str(", ");
        }
        let _ = names.push_str(record.username.as_str());
    }
    let count = store.records.len();
    drop(store);
    RestoreOutcome::Restored { count, names }
}

/// 从本进程 bootfs 文件表读取 `/etc/users` 默认用户库。
///
/// 表布局见 `zero_abi::bootfs::UserBootFile`：路径与内容都给出物理/
/// 虚拟两套地址，用户态一律使用已映射的 `*_ptr` 系列。
fn load_rootfs_defaults(bootfs_ptr: u64, bootfs_len: u64) -> bool {
    if bootfs_ptr == 0 || bootfs_len == 0 {
        return false;
    }
    let entries =
        unsafe { slice::from_raw_parts(bootfs_ptr as *const UserBootFile, bootfs_len as usize) };
    for entry in entries {
        let path_bytes =
            unsafe { slice::from_raw_parts(entry.path_ptr as *const u8, entry.path_len as usize) };
        let Ok(path) = core::str::from_utf8(path_bytes) else {
            continue;
        };
        if path == "/etc/users" {
            let data = unsafe {
                slice::from_raw_parts(entry.data_ptr as *const u8, entry.data_len as usize)
            };
            return apply_user_blob(data);
        }
    }
    false
}

fn apply_user_blob(blob: &[u8]) -> bool {
    let text = match core::str::from_utf8(blob) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut parsed = Vec::<UserRecord, USER_CAPACITY>::new();
    let mut migrated = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split(':');
        let (Some(name), Some(password), Some(role_text)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let Some(role) = UserRole::from_str(role_text.trim()) else {
            continue;
        };
        if parsed.len() == parsed.capacity() {
            break;
        }
        let password = password.trim();
        if !encoded_password(password) {
            migrated = true;
        }
        if let Ok(record) = UserRecord::build(name.trim(), password, role) {
            let _ = parsed.push(record);
        }
    }
    if parsed.is_empty() {
        return false;
    }
    let mut store = USERS.lock();
    store.records.clear();
    for record in parsed {
        let _ = store.records.push(record);
    }
    PASSWORD_MIGRATION_NEEDED.store(migrated, core::sync::atomic::Ordering::SeqCst);
    true
}

fn process_command(sender: u64, msg: &mut Message) {
    match msg.code {
        // Credential verification is the only unauthenticated operation. A
        // successful check binds the resulting role to the kernel-supplied PID.
        security::CMD_USER_VERIFY => handle_verify(sender, msg),
        security::CMD_USER_LIST if is_admin(sender) => handle_list(msg),
        security::CMD_USER_ADD if is_admin(sender) => handle_add(msg),
        security::CMD_USER_DELETE if is_admin(sender) => handle_delete(msg),
        security::CMD_USER_PASSWD if is_admin(sender) => handle_passwd(msg),
        security::CMD_CAP_ISSUE => handle_cap_issue(sender, msg),
        security::CMD_CAP_REVOKE if is_admin(sender) => handle_cap_revoke(msg),
        security::CMD_CAP_LIST if is_admin(sender) => handle_cap_list(msg),
        security::CMD_CAP_VERIFY if is_admin(sender) => handle_cap_verify(msg),
        security::CMD_PKG_VERIFY => handle_pkg_verify(msg),
        _ => {
            msg.payload.fill(0);
            msg.code = 3; // authenticated/authorization policy denied
        }
    }
}

fn handle_pkg_verify(msg: &mut Message) {
    let origin_len = msg.payload[0] as usize;
    let needed = 1usize
        .saturating_add(origin_len)
        .saturating_add(32)
        .saturating_add(64);
    let ok = if origin_len == PKG_TRUST_ORIGIN.len()
        && needed <= msg.payload.len()
        && &msg.payload[1..1 + origin_len] == PKG_TRUST_ORIGIN
    {
        let hash_off = 1 + origin_len;
        let sig_off = hash_off + 32;
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&msg.payload[sig_off..sig_off + 64]);
        match VerifyingKey::from_bytes(&PKG_ZERO_OS_PUBLIC_KEY) {
            Ok(key) => key
                .verify_strict(
                    &msg.payload[hash_off..hash_off + 32],
                    &Signature::from_bytes(&sig_bytes),
                )
                .is_ok(),
            Err(_) => false,
        }
    } else {
        false
    };
    msg.payload.fill(0);
    msg.code = if ok { 0 } else { 1 };
}

fn handle_list(msg: &mut Message) {
    let store = USERS.lock();
    let mut text = String::<LIST_BUFFER>::new();
    for (index, record) in store.records.iter().enumerate() {
        if index > 0 {
            let _ = text.push('\n');
        }
        let _ = text.push_str(record.username.as_str());
        let _ = text.push(':');
        let _ = text.push_str(record.role.as_str());
    }
    msg.payload.fill(0);
    let bytes = text.as_bytes();
    let len = min(bytes.len(), msg.payload.len().saturating_sub(1));
    msg.payload[..len].copy_from_slice(&bytes[..len]);
    msg.code = 0;
}

fn handle_add(msg: &mut Message) {
    let fields = parse_fields(&msg.payload);
    let Some(username) = fields.get(0) else {
        msg.code = 2;
        return;
    };
    let Some(password) = fields.get(1) else {
        msg.code = 2;
        return;
    };
    let role_value = fields.get(2).copied().unwrap_or("user");
    let Some(role) = UserRole::from_str(role_value) else {
        msg.code = 2;
        return;
    };

    let mut store = USERS.lock();
    if store.records.len() == store.records.capacity() || store.find_index(username).is_some() {
        msg.code = 1;
        return;
    }
    match UserRecord::build(username, password, role) {
        Ok(record) => {
            let _ = store.records.push(record);
            msg.code = 0;
        }
        Err(_) => {
            msg.code = 2;
            return;
        }
    }
    drop(store);
    persist_users();
}

fn handle_delete(msg: &mut Message) {
    let fields = parse_fields(&msg.payload);
    let Some(target) = fields.get(0) else {
        msg.code = 2;
        return;
    };
    let mut store = USERS.lock();
    let Some(index) = store.find_index(target) else {
        msg.code = 1;
        return;
    };
    store.records.swap_remove(index);
    msg.code = 0;
    drop(store);
    persist_users();
}

fn handle_passwd(msg: &mut Message) {
    let fields = parse_fields(&msg.payload);
    let (Some(username), Some(password)) = (fields.get(0), fields.get(1)) else {
        msg.code = 2;
        return;
    };
    let mut store = USERS.lock();
    let Some(index) = store.find_index(username) else {
        msg.code = 1;
        return;
    };
    let Some(pwd) = password_hash(username, password) else {
        msg.code = 2;
        return;
    };
    store.records[index].password = pwd;
    msg.code = 0;
    drop(store);
    persist_users();
}

fn handle_verify(sender: u64, msg: &mut Message) {
    let fields = parse_fields(&msg.payload);
    let (Some(username), Some(password)) = (fields.get(0), fields.get(1)) else {
        msg.code = 2;
        return;
    };
    let store = USERS.lock();
    let Some(index) = store.find_index(username) else {
        msg.code = 1;
        return;
    };
    let Some(candidate_digest) = password_digest(username, password) else {
        msg.code = 1;
        return;
    };
    let Some(stored_digest) = parse_encoded_digest(store.records[index].password.as_str()) else {
        msg.code = 1;
        return;
    };
    if constant_time_eq(&stored_digest, &candidate_digest) {
        let role = store.records[index].role;
        drop(store);
        remember_authenticated(sender, role);
        msg.code = 0;
    } else {
        msg.code = 1;
    }
}

/// CMD_CAP_ISSUE：解析请求 → 内核号位 40 落账 → 台账镜像 + 回令牌。
///
/// 响应：code=0 且 payload=`token\0`；code=1 参数解析失败；
/// code=2 内核拒绝（非 ISSUER / scope 非法 / 台账满）。
///
/// 调用者身份由内核 IPC envelope 提供，不能由 payload 伪造。普通已认证
/// 用户只能给**自己**申请 CAP_SESSION；其余能力签发仅 admin 身份可用。
/// 内核仍做第二道防线：CAP_ISSUER 不可转授、授予按 PID/会话绑定。
fn handle_cap_issue(sender: u64, msg: &mut Message) {
    let Some(req) = parse_cap_issue(&msg.payload) else {
        msg.code = 1;
        return;
    };
    let CapIssueRequest {
        target_pid,
        caps,
        ttl,
    } = req;
    if !cap_issue_allowed(sender, authenticated_role(sender), &req) {
        msg.payload.fill(0);
        msg.code = 3;
        return;
    }
    match userlib::cap_grant(target_pid, caps, ttl) {
        Ok(token) => {
            // 台账镜像满：内核授予已生效，仅审计缺行——如实告警但不
            // 回滚（内核台账是权威，撤销仍可用 token 操作）。
            let mut ledger = CAP_LEDGER.lock();
            if ledger.len() < ledger.capacity() {
                let _ = ledger.push(CapLedgerEntry {
                    token,
                    target_pid,
                    caps,
                    revoked: false,
                });
            } else {
                println("securityd: warning: cap ledger mirror full");
            }
            drop(ledger);
            if encode_token(&mut msg.payload, token) {
                msg.code = 0;
            } else {
                msg.code = 2;
            }
        }
        Err(_) => msg.code = 2,
    }
}

/// CMD_CAP_REVOKE：payload `token\0`。先内核撤销（权威），成功后标废
/// 台账行。code=0 成功；1=未知令牌；2=payload 解析失败。
fn handle_cap_revoke(msg: &mut Message) {
    let Some(token) = parse_token(&msg.payload) else {
        msg.code = 2;
        return;
    };
    match userlib::cap_revoke(token) {
        Ok(()) => {
            let mut ledger = CAP_LEDGER.lock();
            if let Some(entry) = ledger.iter_mut().find(|e| e.token == token) {
                entry.revoked = true;
            }
            drop(ledger);
            msg.payload.fill(0);
            msg.code = 0;
        }
        Err(zero_abi::syscall::SysError::NotFound) => msg.code = 1,
        Err(_) => msg.code = 2,
    }
}

/// CMD_CAP_LIST：台账文本（`token=T pid=P caps=0x.. [active|revoked]\n`
/// 行集，截断到缓冲容量）。
fn handle_cap_list(msg: &mut Message) {
    use core::fmt::Write as _;
    let ledger = CAP_LEDGER.lock();
    let mut text = String::<LIST_BUFFER>::new();
    for entry in ledger.iter() {
        let mut line = String::<64>::new();
        if write!(
            line,
            "token={} pid={} caps=0x{:x} {}",
            entry.token,
            entry.target_pid,
            entry.caps,
            if entry.revoked {
                "[revoked]"
            } else {
                "[active]"
            }
        )
        .is_err()
        {
            break;
        }
        if !text.is_empty() {
            let _ = text.push('\n');
        }
        if text.push_str(line.as_str()).is_err() {
            break;
        }
    }
    drop(ledger);
    if text.is_empty() {
        let _ = text.push_str("(no capability tokens issued)");
    }
    msg.payload.fill(0);
    let bytes = text.as_bytes();
    let len = min(bytes.len(), msg.payload.len().saturating_sub(1));
    msg.payload[..len].copy_from_slice(&bytes[..len]);
    msg.code = 0;
}

/// CMD_CAP_VERIFY：payload `token\0`；code=0 在账未撤销、1 不在账/
/// 已撤销、2 解析失败。（只查本地镜像；权威状态以内核活算为准。）
fn handle_cap_verify(msg: &mut Message) {
    let Some(token) = parse_token(&msg.payload) else {
        msg.code = 2;
        return;
    };
    let ledger = CAP_LEDGER.lock();
    match ledger.iter().find(|e| e.token == token) {
        Some(entry) if !entry.revoked => msg.code = 0,
        _ => msg.code = 1,
    }
}

fn parse_fields(payload: &[u8]) -> Vec<&str, 4> {
    let mut fields = Vec::<&str, 4>::new();
    let mut start = 0;
    while start < payload.len() {
        while start < payload.len() && payload[start] == 0 {
            start += 1;
        }
        if start >= payload.len() {
            break;
        }
        let mut end = start;
        while end < payload.len() && payload[end] != 0 {
            end += 1;
        }
        if let Ok(text) = core::str::from_utf8(&payload[start..end]) {
            if text.is_empty() {
                break;
            }
            let _ = fields.push(text);
        }
        start = end + 1;
    }
    fields
}

/// 持久化用户库并做写后读自检；成功/失败都上控制台（生命周期关键行
/// 必须可见，log 后端缺失时 println 才能上串口）。返回是否落盘成功。
fn persist_users() -> bool {
    let store = USERS.lock();
    match write_user_blob(&store.records) {
        Ok(bytes) => {
            println("securityd: userdb persisted to blk (verify ok)");
            let _ = bytes; // 细节在 write_user_blob 内部自检，横幅保持一行
            true
        }
        Err(()) => {
            println("securityd: warning: failed to persist user database (no blk device?)");
            false
        }
    }
}

/// 序列化 + 落盘 + 读回校验：
/// 1. 记录文本写入记录区缓冲（512 对齐、整扇区长度）；
/// 2. **先写记录区、后写头部**——头部是提交标记（zero_abi::userdb 布局
///    约定）：中途失败只留旧头部/无头部，下次启动按 magic 失败回退
///    默认表重播，绝不读到半截新数据；
/// 3. 写后读回头部与已写记录区逐字节比对，不一致视为失败。
fn write_user_blob(records: &Vec<UserRecord, USER_CAPACITY>) -> Result<usize, ()> {
    let mut data = SectorAligned::<USERDB_RECORD_BYTES>::zeroed();
    let mut offset = 0;
    for record in records.iter() {
        let mut line = String::<{ USERNAME_MAX + PASSWORD_MAX + 8 }>::new();
        line.push_str(record.username.as_str()).map_err(|_| ())?;
        line.push(':').map_err(|_| ())?;
        line.push_str(record.password.as_str()).map_err(|_| ())?;
        line.push(':').map_err(|_| ())?;
        line.push_str(record.role.as_str()).map_err(|_| ())?;
        line.push('\n').map_err(|_| ())?;
        let bytes = line.as_bytes();
        if offset + bytes.len() > data.bytes.len() {
            return Err(());
        }
        data.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
    }
    // 整扇区写：尾部零填充到扇区边界（至少 1 扇区，空库也有合法记录区）。
    let used_sectors = core::cmp::max(offset.div_ceil(USERDB_SECTOR_SIZE), 1);
    let write_len = used_sectors * USERDB_SECTOR_SIZE;
    userlib::block_write(USERDB_RECORD_LBA, &data.bytes[..write_len]).map_err(|_| ())?;

    // 提交标记：头部最后写。
    let mut header = SectorAligned::<{ USERDB_SECTOR_SIZE }>::zeroed();
    zero_abi::userdb::encode_header(&mut header.bytes, USERDB_RECORD_SECTORS as u32);
    userlib::block_write(USERDB_HDR_LBA, &header.bytes).map_err(|_| ())?;

    // ── 写后读自检 ────────────────────────────────────────────────
    let mut rheader = SectorAligned::<{ USERDB_SECTOR_SIZE }>::zeroed();
    userlib::block_read(USERDB_HDR_LBA, &mut rheader.bytes).map_err(|_| ())?;
    if rheader.bytes != header.bytes {
        return Err(());
    }
    let mut rdata = SectorAligned::<USERDB_RECORD_BYTES>::zeroed();
    userlib::block_read(USERDB_RECORD_LBA, &mut rdata.bytes[..write_len]).map_err(|_| ())?;
    if rdata.bytes[..write_len] != data.bytes[..write_len] {
        return Err(());
    }
    Ok(write_len)
}

// ═══ 主机单测（第十三刀）════════════════════════════════════════════
// 台账镜像与协议编解码的纯逻辑面：内核权威状态不可在宿主复现，
// 这里钉住 securityd 侧自己的决策与簿记行为。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_ledger_upsert_and_revoke_marking() {
        let mut ledger: Vec<CapLedgerEntry, CAP_LEDGER_CAP> = Vec::new();
        let _ = ledger.push(CapLedgerEntry {
            token: 7,
            target_pid: 42,
            caps: 0x50,
            revoked: false,
        });
        // 在账未撤销 → 有效
        assert!(ledger
            .iter()
            .find(|e| e.token == 7)
            .map(|e| !e.revoked)
            .unwrap_or(false));
        // 撤销标废（保留行，不删——审计痕迹）
        if let Some(entry) = ledger.iter_mut().find(|e| e.token == 7) {
            entry.revoked = true;
        }
        assert!(ledger
            .iter()
            .find(|e| e.token == 7)
            .map(|e| e.revoked)
            .unwrap_or(false));
        // 未知 token 查无此行
        assert!(ledger.iter().find(|e| e.token == 8).is_none());
    }

    #[test]
    fn cap_ledger_mirror_full_keeps_kernel_authoritative() {
        // 镜像满时的策略：不再 push（缺行告警），但绝不妨碍已生效授予。
        let mut ledger: Vec<CapLedgerEntry, CAP_LEDGER_CAP> = Vec::new();
        for token in 0..CAP_LEDGER_CAP as u64 {
            assert!(ledger
                .push(CapLedgerEntry {
                    token,
                    target_pid: 1,
                    caps: 1,
                    revoked: false,
                })
                .is_ok());
        }
        assert_eq!(ledger.len(), ledger.capacity());
        // 第 CAP_LEDGER_CAP+1 枚令牌：push 失败即跳过（handle_cap_issue
        // 的 else 分支语义），台账仍完整可读。
        assert!(ledger
            .push(CapLedgerEntry {
                token: 999,
                target_pid: 1,
                caps: 1,
                revoked: false,
            })
            .is_err());
        assert_eq!(ledger.len(), CAP_LEDGER_CAP);
    }

    #[test]
    fn issue_request_roundtrip_via_abi_codec() {
        // securityd 与 shell 共用 zero_abi 编解码——同一测试双端对齐。
        let req = CapIssueRequest {
            target_pid: 1234,
            caps: 0x50,
            ttl: 500_000,
        };
        let mut payload = [0u8; 128];
        assert!(security::encode_cap_issue(&mut payload, &req));
        assert_eq!(parse_cap_issue(&payload), Some(req));
    }
    #[test]
    fn password_storage_never_keeps_plaintext() {
        let root = UserRecord::build("root", "zero", UserRole::Admin).unwrap();
        assert!(root.password.as_str().starts_with(PASSWORD_PREFIX));
        assert_ne!(root.password.as_str(), "zero");
        let again = UserRecord::build("root", root.password.as_str(), UserRole::Admin).unwrap();
        assert_eq!(again.password.as_str(), root.password.as_str());
        let stored = parse_encoded_digest(root.password.as_str()).unwrap();
        assert!(constant_time_eq(
            &stored,
            &password_digest("root", "zero").unwrap()
        ));
        assert!(!constant_time_eq(
            &stored,
            &password_digest("root", "wrong").unwrap()
        ));
    }

    #[test]
    fn capability_policy_binds_identity_to_kernel_sender() {
        let sender = 42;
        let login = CapIssueRequest {
            target_pid: sender,
            caps: zero_abi::cap::CAP_SESSION,
            ttl: 0,
        };
        assert!(!cap_issue_allowed(sender, None, &login));
        assert!(cap_issue_allowed(sender, Some(UserRole::User), &login));
        let forged_login = CapIssueRequest {
            target_pid: 99,
            ..login
        };
        assert!(!cap_issue_allowed(
            sender,
            Some(UserRole::User),
            &forged_login
        ));
        let powerful = CapIssueRequest {
            target_pid: 99,
            caps: zero_abi::cap::CAP_BLOCK_DEV,
            ttl: 100,
        };
        assert!(!cap_issue_allowed(sender, Some(UserRole::User), &powerful));
        assert!(cap_issue_allowed(sender, Some(UserRole::Admin), &powerful));
    }

    #[test]
    fn rootfs_default_credentials_verify_after_pre_hashing() {
        let blob = include_bytes!("../../../kernel/rootfs/etc/users");
        assert!(apply_user_blob(blob));
        let mut msg = Message::empty();
        msg.payload[..4].copy_from_slice(b"root");
        msg.payload[5..9].copy_from_slice(b"zero");
        handle_verify(42, &mut msg);
        assert_eq!(msg.code, 0);
        assert_eq!(authenticated_role(42), Some(UserRole::Admin));

        let mut guest = Message::empty();
        guest.payload[..5].copy_from_slice(b"guest");
        guest.payload[6..11].copy_from_slice(b"guest");
        handle_verify(43, &mut guest);
        assert_eq!(guest.code, 0);
        assert_eq!(authenticated_role(43), Some(UserRole::User));
    }
}
