//! # zero-launchd —— Zero OS 系统初始化守护进程
//!
//! launchd 由内核引导期经 `services::launch_core` 以特权进程身份从
//! rootfs（`/System/Core/zero-launchd`）加载，是第一个进入用户态
//! EL0 的系统服务。
//!
//! ## 职责（本轮）
//!
//! 1. 启动横幅打印（console）；
//! 2. 占用 `LAUNCHD_CMD_REQ`(0x240) / `LAUNCHD_CMD_RESP`(0x241) 通道，
//!    应答用户态命令（`list` / `status` / `spawn`）；
//! 3. `spawn` 经系统调用 20（`SpawnService`）拉起内核登记的服务并记账。
//!
//! ## 禁令
//!
//! 用户态**禁止直写 MMIO**（旧版 blob 在 EL0 裸读 0x9000000 被内核
//! 终止）。一切外设访问只允许走 userlib 包装的系统调用。
//!
//! ## 协议（与 `zero-abi::protocol::launchd` 对齐）
//!
//! 请求走 `LAUNCHD_CMD_REQ`，响应原样回塞到 `LAUNCHD_CMD_RESP`：
//! - `code == 0` 成功，`payload` 为结果文本（NUL 结尾）；
//! - `code != 0` 失败，`payload` 为错误说明文本。
//!
//! | 命令码 | 含义                           | 请求 payload          |
//! |--------|--------------------------------|-----------------------|
//! | 0x10   | `list` 列出已登记服务          | 空                    |
//! | 0x11   | `restart <name>` 重启服务      | `name\0`              |
//! | 0x12   | `spawn <binary>` 启动应用      | `name\0binary\0flags` |
//! | 0x13   | `reload-fs` 重载 rootfs（预留）| 空                    |
//! | 0x14   | `status` 查询 launchd 状态     | 空                    |
//!
//! ## 内存模型
//!
//! 本进程**不设堆**（不依赖 global allocator）：全部状态为栈上/静态
//! 固定数组，`allocation` 类 crate 一概不用。

#![no_std]

use userlib::{
    console_write, extract_payload_text, ipc_receive, ipc_send, service_spawn, yield_now,
};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::launchd::{
    CMD_LIST_SERVICES, CMD_RELOAD_FS, CMD_RESTART_SERVICE, CMD_START_APPLICATION, CMD_STATUS,
};
use zero_abi::syscall::SysError;

/// 服务表容量。
const SERVICE_TABLE_CAP: usize = 16;

/// 服务名/路径最大长度。
const NAME_MAX: usize = 64;

/// 响应文本缓冲区容量（对齐 payload 128 字节）。
const BUF_MAX: usize = 128;

/// 登记的服务记录。
#[derive(Clone, Copy)]
struct ServiceRecord {
    name: [u8; NAME_MAX],
    name_len: usize,
    /// 最近一次 spawn 返回的 PID。
    pid: Option<u64>,
    /// 状态：0=idle 1=starting 2=running 3=failed（与
    /// `zero_abi::protocol::service_control::STATUS_*` 对齐）。
    status: u8,
}

impl ServiceRecord {
    const fn new() -> Self {
        Self {
            name: [0; NAME_MAX],
            name_len: 0,
            pid: None,
            status: 0,
        }
    }

    fn set_name(&mut self, name: &str) -> bool {
        if name.is_empty() || name.len() > NAME_MAX {
            return false;
        }
        self.name[..name.len()].copy_from_slice(name.as_bytes());
        self.name_len = name.len();
        true
    }

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<bad utf8>")
    }
}

/// 状态常量（与 `ServiceRecord.status` 字段注释及
/// `zero_abi::protocol::service_control::STATUS_*` 对齐）：
/// 1=starting 2=running 3=failed 4=not-installed（0=idle 暂未使用）。
const STATUS_STARTING: u8 = 1;
const STATUS_RUNNING: u8 = 2;
const STATUS_FAILED: u8 = 3;
/// 已规划、但内核未登记或二进制尚未嵌入 rootfs。
const STATUS_NOT_INSTALLED: u8 = 4;

/// 已规划服务清单。二进制就绪并由内核登记前以 [not-installed] 呈现，
/// 让 `launchd list` 如实反映系统蓝图而非空白。
const KNOWN_SERVICES: [&str; 10] = [
    "blkdrv",
    "fsd",
    "securityd",
    "inputd",
    "windowserver",
    "netd",
    "pkgd",
    "audiod",
    "service-controller",
    "ipcrouter",
];

/// 服务表：全部状态驻留在 `server_main` 栈帧，单线程无需锁。
struct ServiceTable {
    records: [Option<ServiceRecord>; SERVICE_TABLE_CAP],
}

impl ServiceTable {
    const fn new() -> Self {
        Self {
            records: [None; SERVICE_TABLE_CAP],
        }
    }

    /// 按名插入或更新记录。
    fn upsert(&mut self, name: &str, pid: Option<u64>, status: u8) {
        if let Some(slot) = self
            .records
            .iter_mut()
            .find(|slot| slot.as_ref().map(|r| r.name() == name).unwrap_or(false))
        {
            let rec = slot.as_mut().unwrap();
            rec.pid = pid;
            rec.status = status;
        } else if let Some(slot) = self.records.iter_mut().find(|slot| slot.is_none()) {
            let mut rec = ServiceRecord::new();
            if rec.set_name(name) {
                rec.pid = pid;
                rec.status = status;
                *slot = Some(rec);
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = &ServiceRecord> {
        self.records.iter().flatten()
    }
}

/// 栈上文本缓冲（无堆版 String：用于组装响应/日志文本）。
struct TextBuf {
    buf: [u8; BUF_MAX],
    len: usize,
}

impl TextBuf {
    const fn new() -> Self {
        Self {
            buf: [0; BUF_MAX],
            len: 0,
        }
    }

    fn push_str(&mut self, text: &str) {
        let bytes = text.as_bytes();
        let remain = self.buf.len().saturating_sub(self.len);
        let take = bytes.len().min(remain);
        self.buf[self.len..self.len + take].copy_from_slice(&bytes[..take]);
        self.len += take;
    }

    fn push_u64(&mut self, mut value: u64) {
        if value == 0 {
            self.push_str("0");
            return;
        }
        let mut digits = [0u8; 20];
        let mut i = digits.len();
        while value > 0 {
            i -= 1;
            digits[i] = b'0' + (value % 10) as u8;
            value /= 10;
        }
        self.push_str(core::str::from_utf8(&digits[i..]).unwrap());
    }

    fn push_hex(&mut self, value: u32) {
        if value == 0 {
            self.push_str("0");
            return;
        }
        let mut digits = [0u8; 8];
        let mut i = digits.len();
        let mut v = value;
        while v > 0 {
            i -= 1;
            let nibble = (v & 0xf) as u8;
            digits[i] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + nibble - 10
            };
            v >>= 4;
        }
        self.push_str(core::str::from_utf8(&digits[i..]).unwrap());
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

/// 引导入口（链接脚本 `ENTRY(_start)`，基址 0x200000）：
/// 先清 `.bss`（内核加载器不保证清零），再进入服务主循环。
#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        extern "C" {
            static mut __bss_start: u8;
            static mut __bss_end: u8;
        }
        let mut p = &raw mut __bss_start as *mut u8;
        let end = &raw mut __bss_end as *mut u8;
        while p < end {
            core::ptr::write_volatile(p, 0);
            p = p.add(1);
        }
    }
    server_main()
}

/// 服务主循环：等待 `LAUNCHD_CMD_REQ` 命令并应答。
pub extern "C" fn server_main() -> ! {
    let mut table = ServiceTable::new();

    // 预登记已规划服务（not-installed），随后逐个向内核发起一次 spawn 对账：
    // 内核 SERVICE_REGISTRY 已登记且 blob 已嵌入 rootfs 的服务会被真正拉起，
    // 记为 [running pid=N]；未登记的以 NotFound 拒绝、保持 [not-installed]。
    // 这样 `launchd list` 无需手动 spawn 即反映系统真实状态，也保证内核与
    // launchd 之间只有一份实例（记账 pid 唯一）。
    for name in KNOWN_SERVICES {
        table.upsert(name, None, STATUS_NOT_INSTALLED);
        match service_spawn(name) {
            Ok(pid) => {
                table.upsert(name, Some(pid), STATUS_RUNNING);
                announce_online(name, pid);
            }
            Err(_) => {} // 保持 not-installed 占位，如实呈现蓝图
        }
    }

    println("Zero OS launchd (EL0 service) online");
    println("  channel req=0x240 resp=0x241; spawn via syscall 20");

    loop {
        let mut message = Message::empty();
        match ipc_receive(channels::LAUNCHD_CMD_REQ, &mut message) {
            Ok(_) => dispatch(&mut table, &message),
            Err(SysError::WouldBlock) => yield_now(),
            Err(_) => {
                println("launchd: receive error, retrying");
                yield_now();
            }
        }
    }
}

/// 分发一条用户态命令并把结果应答到 `LAUNCHD_CMD_RESP`。
fn dispatch(table: &mut ServiceTable, request: &Message) {
    let mut text = TextBuf::new();
    let code = match request.code {
        CMD_LIST_SERVICES => handle_list(table, &mut text),
        CMD_STATUS => handle_status(table, &mut text),
        CMD_START_APPLICATION => handle_start_application(table, request, &mut text),
        CMD_RESTART_SERVICE => handle_restart(table, request, &mut text),
        CMD_RELOAD_FS => {
            text.push_str("reload-fs reserved: not implemented this round");
            2
        }
        other => {
            text.push_str("unknown launchd command 0x");
            text.push_hex(other);
            2
        }
    };
    respond(code, text.as_str());
    println("launchd: command processed");
}

fn handle_list(table: &ServiceTable, text: &mut TextBuf) -> u32 {
    for rec in table.iter() {
        text.push_str(rec.name());
        text.push_str(" ");
        text.push_str(match rec.status {
            0 => "[idle]",
            1 => "[starting]",
            2 => "[running]",
            4 => "[not-installed]",
            _ => "[failed]",
        });
        if let Some(pid) = rec.pid {
            text.push_str(" pid=");
            text.push_u64(pid);
        }
        text.push_str("\n");
    }
    if text.is_empty() {
        text.push_str("(no services registered yet)");
    }
    0
}

fn handle_status(table: &ServiceTable, text: &mut TextBuf) -> u32 {
    text.push_str("launchd up; services registered=");
    text.push_u64(table.iter().count() as u64);
    0
}

/// 启动应用（payload 布局 `name\0binary\0flags`，对齐历史格式；
/// flags 本轮只解析不强制）。
fn handle_start_application(
    table: &mut ServiceTable,
    request: &Message,
    text: &mut TextBuf,
) -> u32 {
    if let Some((_name, binary)) = split_fields(&request.payload) {
        spawn_and_record(table, binary, text)
    } else {
        text.push_str("malformed start payload (need name\\0binary\\0flags)");
        2
    }
}

/// 重启服务（payload 布局 `name\0`）。
fn handle_restart(table: &mut ServiceTable, request: &Message, text: &mut TextBuf) -> u32 {
    let name = extract_payload_text(&request.payload);
    if name.is_empty() {
        text.push_str("restart requires a service name");
        return 2;
    }
    spawn_and_record(table, name, text)
}

/// 调用 `SpawnService`（syscall 20）并按结果记账。
///
/// - 成功：upsert 为 [running pid=N]；
/// - NotFound（未在内核 SERVICE_REGISTRY 登记或 blob 未嵌入 rootfs）：
///   保持 [not-installed]，如实呈现蓝图而非谎报 failed；
/// - 其他错误：记 [failed] 并回传错误名。
///
/// 幂等保护：已在运行/启动中的服务直接友好回报、不重复 spawn
/// （内核侧无实例去重，重复 spawn 会产生第二份进程）。
fn spawn_and_record(table: &mut ServiceTable, name: &str, text: &mut TextBuf) -> u32 {
    if let Some(rec) = table.iter().find(|rec| rec.name() == name) {
        if rec.pid.is_some() && (rec.status == STATUS_RUNNING || rec.status == STATUS_STARTING) {
            text.push_str(name);
            text.push_str(" already running pid=");
            text.push_u64(rec.pid.unwrap_or(0));
            return 1;
        }
    }
    match service_spawn(name) {
        Ok(pid) => {
            table.upsert(name, Some(pid), STATUS_RUNNING);
            text.push_str("spawning ");
            text.push_str(name);
            text.push_str(" pid=");
            text.push_u64(pid);
            0
        }
        Err(SysError::NotFound) => {
            table.upsert(name, None, STATUS_NOT_INSTALLED);
            text.push_str("spawn failed: not found (not registered in kernel registry)");
            2
        }
        Err(err) => {
            table.upsert(name, None, STATUS_FAILED);
            text.push_str("spawn failed: ");
            text.push_str(err.as_str());
            2
        }
    }
}

/// 服务上线横幅（启动对账成功时打印，含内核分配的 pid）。
fn announce_online(name: &str, pid: u64) {
    let mut text = TextBuf::new();
    text.push_str("launchd: service online: ");
    text.push_str(name);
    text.push_str(" pid=");
    text.push_u64(pid);
    println(text.as_str());
}

/// 把结果文本应答到 `LAUNCHD_CMD_RESP`（超长自动截断，NUL 收尾）。
fn respond(code: u32, text: &str) {
    let mut payload = [0u8; 128];
    let len = text.len().min(127);
    payload[..len].copy_from_slice(&text.as_bytes()[..len]);
    let message = Message { code, payload };
    let _ = ipc_send(channels::LAUNCHD_CMD_RESP, &message);
}

/// 按第一个 NUL 把 payload 切成前两个字段（`name` / `binary`）。
fn split_fields(payload: &[u8]) -> Option<(&str, &str)> {
    let mut start = 0;
    let mut fields: [&str; 2] = ["", ""];
    let mut count = 0;
    while start < payload.len() && count < 2 {
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
        let field = core::str::from_utf8(&payload[start..end]).ok()?;
        if !field.is_empty() {
            fields[count] = field;
            count += 1;
        }
        start = end + 1;
    }
    if count >= 2 {
        Some((fields[0], fields[1]))
    } else {
        None
    }
}

fn println(text: &str) {
    let _ = console_write(text.as_bytes());
    let _ = console_write(b"\r\n");
}
