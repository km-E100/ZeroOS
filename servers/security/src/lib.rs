#![no_std]

use core::cmp::min;

use heapless::{String, Vec};
use log::{info, warn};
use spin::Mutex;
use userlib;
use zero_abi::boot::{RootFsEntry, RootFsImage};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::security;

const USERNAME_MAX: usize = 16;
const PASSWORD_MAX: usize = 32;
const USER_CAPACITY: usize = 8;
const LIST_BUFFER: usize = 256;
const USERDB_LBA: u64 = 128;
const USERDB_SECTOR_SIZE: usize = 512;
const USERDB_SECTORS: usize = 8;
const USERDB_CAPACITY: usize = USERDB_SECTOR_SIZE * USERDB_SECTORS;

#[derive(Clone, Copy, PartialEq, Eq)]
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
            || password.len() > PASSWORD_MAX
            || !username
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        {
            return Err(());
        }
        let mut name = String::<USERNAME_MAX>::new();
        name.push_str(username).map_err(|_| ())?;
        let mut pwd = String::<PASSWORD_MAX>::new();
        pwd.push_str(password).map_err(|_| ())?;
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

extern "C" {
    static __zero_rootfs_image: RootFsImage;
}

pub extern "C" fn server_main() -> ! {
    init_user_store();
    info!("securityd ready for authentication and policy enforcement");
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::SECURITY_USER_REQ, &mut message) {
            Ok(_) => {
                process_command(&mut message);
                let _ = userlib::ipc_send(channels::SECURITY_USER_RESP, &message);
            }
            Err(_) => userlib::yield_now(),
        }
    }
}

fn init_user_store() {
    if load_persisted_records() {
        info!("securityd: restored users from persistent store");
        return;
    }
    if load_rootfs_defaults() {
        info!("securityd: loaded default users");
        persist_users();
    } else {
        warn!("securityd: user database empty; provisioning required");
    }
}

fn load_persisted_records() -> bool {
    let mut buffer = [0u8; USERDB_CAPACITY];
    if userlib::block_read(USERDB_LBA, &mut buffer).is_err() {
        return false;
    }
    let used = match buffer.iter().rposition(|byte| *byte != 0) {
        Some(pos) => pos + 1,
        None => return false,
    };
    let blob = &buffer[..used];
    apply_user_blob(blob)
}

fn load_rootfs_defaults() -> bool {
    unsafe {
        let image = &__zero_rootfs_image;
        let Some(entries) = rootfs_entries(image) else {
            return false;
        };
        for entry in entries {
            let path = entry.path();
            if path == "/etc/users" {
                let data = entry.data();
                return apply_user_blob(data);
            }
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
        if let Ok(record) = UserRecord::build(name.trim(), password.trim(), role) {
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
    true
}

fn process_command(msg: &mut Message) {
    match msg.code {
        security::CMD_USER_LIST => handle_list(msg),
        security::CMD_USER_ADD => handle_add(msg),
        security::CMD_USER_DELETE => handle_delete(msg),
        security::CMD_USER_PASSWD => handle_passwd(msg),
        security::CMD_USER_VERIFY => handle_verify(msg),
        _ => {
            msg.code = 2;
        }
    }
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
    if password.is_empty() || password.len() > PASSWORD_MAX {
        msg.code = 2;
        return;
    }
    let mut pwd = String::<PASSWORD_MAX>::new();
    if pwd.push_str(password).is_err() {
        msg.code = 2;
        return;
    }
    store.records[index].password = pwd;
    msg.code = 0;
    drop(store);
    persist_users();
}

fn handle_verify(msg: &mut Message) {
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
    if store.records[index].password.as_str() == *password {
        msg.code = 0;
    } else {
        msg.code = 1;
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

fn persist_users() {
    let store = USERS.lock();
    if let Err(_) = write_user_blob(&store.records) {
        warn!("securityd: failed to persist user database");
    }
}

fn write_user_blob(records: &Vec<UserRecord, USER_CAPACITY>) -> Result<(), ()> {
    let mut buffer = [0u8; USERDB_CAPACITY];
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
        if offset + bytes.len() > buffer.len() {
            return Err(());
        }
        buffer[offset..offset + bytes.len()].copy_from_slice(bytes);
        offset += bytes.len();
    }
    userlib::block_write(USERDB_LBA, &buffer).map_err(|_| ())
}

unsafe fn rootfs_entries(image: &RootFsImage) -> Option<&'static [RootFsEntry]> {
    if image.entry_count == 0 {
        None
    } else {
        Some(image.as_slice())
    }
}
