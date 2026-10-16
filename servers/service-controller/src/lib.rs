#![no_std]

use heapless::{String, Vec};
use itoa;
use log::{info, warn};
use spin::Mutex;
use userlib::{self, service_spawn, yield_now};
use zero_abi::channels;
use zero_abi::ipc::Message;
use zero_abi::protocol::service_control::{
    self, FLAG_FOREGROUND, FLAG_KEEPALIVE, STATUS_FAILED, STATUS_IDLE, STATUS_RUNNING,
    STATUS_STARTING,
};
use zero_abi::syscall::SysError;

const RESPONSE_TEXT_MAX: usize = 96;
const SERVICE_NAME_MAX: usize = 96;
const MAX_SERVICES: usize = 16;

type SmallString = String<SERVICE_NAME_MAX>;

#[derive(Clone)]
struct ServiceRecord {
    name: SmallString,
    keep_alive: bool,
    foreground: bool,
    last_request: u32,
    restarts: u32,
    status: u8,
    message: SmallString,
    pid: Option<u64>,
}

static SERVICES: Mutex<Vec<ServiceRecord, MAX_SERVICES>> = Mutex::new(Vec::new());

pub extern "C" fn server_main() -> ! {
    info!("service-controller online");
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::SERVICE_CONTROL_BUS, &mut message) {
            Ok(_) => handle_message(&message),
            Err(SysError::WouldBlock) => yield_now(),
            Err(err) => {
                warn!("service-controller: receive error {:?}", err);
                yield_now();
            }
        }
    }
}

fn handle_message(request: &Message) {
    let Some(parsed) = parse_request(request) else {
        warn!("service-controller: malformed request payload");
        return;
    };
    let mut response_text = String::<RESPONSE_TEXT_MAX>::new();
    let outcome = match parsed.command {
        CommandKind::Start => handle_start(&parsed, &mut response_text),
        CommandKind::Restart => handle_restart(&parsed, &mut response_text),
        CommandKind::StatusReport => handle_status_report(&parsed, &mut response_text),
        CommandKind::QueryStatus => handle_query_status(&parsed, &mut response_text),
        CommandKind::Unknown(raw) => {
            let _ = response_text.push_str("unsupported command ");
            let _ = response_text.push_str(itoa::Buffer::new().format(raw));
            DispatchAction::Respond(2)
        }
    };
    match outcome {
        DispatchAction::Respond(code) => {
            let text = if response_text.is_empty() {
                "ok"
            } else {
                response_text.as_str()
            };
            send_response(parsed.request_id, code, text);
        }
    }
}

enum DispatchAction {
    Respond(u32),
}

fn append_flags(text: &mut String<RESPONSE_TEXT_MAX>, keep_alive: bool, foreground: bool) {
    if keep_alive {
        let _ = text.push_str(" [keepalive]");
    }
    if foreground {
        let _ = text.push_str(" [foreground]");
    }
}

fn send_response(request_id: u32, code: u32, text: &str) {
    let mut message = Message::empty();
    message.code = code;
    message.payload[..4].copy_from_slice(&request_id.to_le_bytes());
    let bytes = text.as_bytes();
    let len = bytes.len().min(message.payload.len().saturating_sub(5));
    message.payload[4..4 + len].copy_from_slice(&bytes[..len]);
    message.payload[4 + len] = 0;
    let _ = userlib::ipc_send(channels::SERVICE_CONTROL_RESP, &message);
}

struct ControlRequest {
    request_id: u32,
    path: String<96>,
    keep_alive: bool,
    foreground: bool,
    payload: [u8; 128],
    command: CommandKind,
}

fn parse_request(message: &Message) -> Option<ControlRequest> {
    if message.payload.len() < 6 {
        return None;
    }
    let mut id_bytes = [0u8; 4];
    id_bytes.copy_from_slice(&message.payload[..4]);
    let request_id = u32::from_le_bytes(id_bytes);
    let flags = message.payload[4];
    let keep_alive = (flags & FLAG_KEEPALIVE) != 0;
    let foreground = (flags & FLAG_FOREGROUND) != 0;
    let text = extract_string(&message.payload[5..]);
    if text.is_empty() {
        return None;
    }
    let mut path = String::<96>::new();
    path.push_str(text).ok()?;
    let mut payload = [0u8; 128];
    payload.copy_from_slice(&message.payload);
    Some(ControlRequest {
        request_id,
        path,
        keep_alive,
        foreground,
        payload,
        command: CommandKind::from_code(message.code),
    })
}

fn extract_string(payload: &[u8]) -> &str {
    let len = payload
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(payload.len());
    core::str::from_utf8(&payload[..len]).unwrap_or("")
}

enum CommandKind {
    Start,
    Restart,
    StatusReport,
    QueryStatus,
    Unknown(u32),
}

impl CommandKind {
    fn from_code(code: u32) -> Self {
        match code {
            service_control::CMD_START => CommandKind::Start,
            service_control::CMD_RESTART => CommandKind::Restart,
            service_control::CMD_STATUS_REPORT => CommandKind::StatusReport,
            service_control::CMD_QUERY_STATUS => CommandKind::QueryStatus,
            other => CommandKind::Unknown(other),
        }
    }
}

fn handle_start(req: &ControlRequest, msg: &mut String<RESPONSE_TEXT_MAX>) -> DispatchAction {
    match service_spawn(req.path.as_str()) {
        Ok(pid) => {
            update_service_record(req, STATUS_STARTING, "starting", Some(pid));
            let _ = msg.push_str("starting ");
            let _ = msg.push_str(req.path.as_str());
            append_flags(msg, req.keep_alive, req.foreground);
            let _ = msg.push_str(" pid=");
            let mut buffer = itoa::Buffer::new();
            let _ = msg.push_str(buffer.format(pid));
            emit_event(
                req.path.as_str(),
                req.request_id,
                Some(pid),
                STATUS_STARTING,
                msg.as_str(),
            );
            DispatchAction::Respond(0)
        }
        Err(err) => {
            let _ = msg.push_str("spawn failed: ");
            let _ = msg.push_str(err.as_str());
            update_service_record(req, STATUS_FAILED, "spawn failed", None);
            emit_event(
                req.path.as_str(),
                req.request_id,
                None,
                STATUS_FAILED,
                msg.as_str(),
            );
            DispatchAction::Respond(2)
        }
    }
}

fn handle_restart(req: &ControlRequest, msg: &mut String<RESPONSE_TEXT_MAX>) -> DispatchAction {
    match service_spawn(req.path.as_str()) {
        Ok(pid) => {
            update_service_record(req, STATUS_STARTING, "restarting", Some(pid));
            let _ = msg.push_str("restarting ");
            let _ = msg.push_str(req.path.as_str());
            append_flags(msg, req.keep_alive, req.foreground);
            let _ = msg.push_str(" pid=");
            let mut buffer = itoa::Buffer::new();
            let _ = msg.push_str(buffer.format(pid));
            emit_event(
                req.path.as_str(),
                req.request_id,
                Some(pid),
                STATUS_STARTING,
                msg.as_str(),
            );
            DispatchAction::Respond(0)
        }
        Err(err) => {
            let _ = msg.push_str("restart failed: ");
            let _ = msg.push_str(err.as_str());
            update_service_record(req, STATUS_FAILED, "restart failed", None);
            emit_event(
                req.path.as_str(),
                req.request_id,
                None,
                STATUS_FAILED,
                msg.as_str(),
            );
            DispatchAction::Respond(2)
        }
    }
}

fn handle_status_report(
    req: &ControlRequest,
    msg: &mut String<RESPONSE_TEXT_MAX>,
) -> DispatchAction {
    if req.payload.len() < 6 {
        let _ = msg.push_str("status report payload too small");
        return DispatchAction::Respond(2);
    }
    let status = req.payload[4];
    let path_len = req.path.len();
    let mut offset = 5 + path_len + 1;
    if offset > req.payload.len() {
        offset = req.payload.len();
    }
    let reason = extract_string(&req.payload[offset..]);
    let mut services = SERVICES.lock();
    if let Some(record) = services
        .iter_mut()
        .find(|rec| rec.last_request == req.request_id)
    {
        record.status = status;
        record.last_request = req.request_id;
        record.message.clear();
        let _ = record.message.push_str(reason);
        if status == STATUS_RUNNING {
            record.restarts = record.restarts.saturating_add(1);
        }
        emit_event(
            record.name.as_str(),
            req.request_id,
            record.pid,
            status,
            reason,
        );
        let _ = msg.push_str("status updated");
        return DispatchAction::Respond(if status == STATUS_RUNNING { 0 } else { 2 });
    }
    if let Some(record) = services.iter_mut().find(|rec| rec.name == req.path) {
        record.status = status;
        record.last_request = req.request_id;
        record.message.clear();
        let _ = record.message.push_str(reason);
        emit_event(
            record.name.as_str(),
            req.request_id,
            record.pid,
            status,
            reason,
        );
        let _ = msg.push_str("status updated");
        return DispatchAction::Respond(if status == STATUS_RUNNING { 0 } else { 2 });
    }
    drop(services);
    let _ = msg.push_str("unknown service");
    DispatchAction::Respond(2)
}

fn handle_query_status(
    req: &ControlRequest,
    msg: &mut String<RESPONSE_TEXT_MAX>,
) -> DispatchAction {
    let name = req.path.as_str();
    let services = SERVICES.lock();
    if let Some(record) = services.iter().find(|r| r.name.as_str() == name) {
        msg.clear();
        let _ = msg.push_str("status=");
        let _ = msg.push_str(match record.status {
            STATUS_STARTING => "starting",
            STATUS_RUNNING => "running",
            STATUS_FAILED => "failed",
            STATUS_IDLE => "idle",
            _ => "unknown",
        });
        if let Some(pid) = record.pid {
            let _ = msg.push_str(" pid=");
            let mut buffer = itoa::Buffer::new();
            let _ = msg.push_str(buffer.format(pid));
        }
        let _ = msg.push_str(" restarts=");
        let mut buffer = itoa::Buffer::new();
        let _ = msg.push_str(buffer.format(record.restarts));
        if !record.message.is_empty() {
            let _ = msg.push_str(" msg=");
            let _ = msg.push_str(record.message.as_str());
        }
        return DispatchAction::Respond(0);
    }
    let _ = msg.push_str("service not registered");
    DispatchAction::Respond(2)
}

fn update_service_record(req: &ControlRequest, status: u8, note: &str, pid: Option<u64>) {
    let mut table = SERVICES.lock();
    if let Some(record) = table.iter_mut().find(|rec| rec.name == req.path) {
        record.keep_alive = req.keep_alive;
        record.foreground = req.foreground;
        record.last_request = req.request_id;
        record.status = status;
        record.message.clear();
        let _ = record.message.push_str(note);
        if let Some(new_pid) = pid {
            record.pid = Some(new_pid);
        } else if status == STATUS_FAILED {
            record.pid = None;
        }
    } else {
        if table.len() == table.capacity() {
            let _ = table.pop();
        }
        let mut name = SmallString::new();
        let _ = name.push_str(req.path.as_str());
        let mut msg = SmallString::new();
        let _ = msg.push_str(note);
        let record = ServiceRecord {
            name,
            keep_alive: req.keep_alive,
            foreground: req.foreground,
            last_request: req.request_id,
            restarts: 0,
            status,
            message: msg,
            pid,
        };
        let _ = table.push(record);
    }
}

fn emit_event(name: &str, request_id: u32, pid: Option<u64>, status: u8, message: &str) {
    let mut payload = [0u8; 128];
    payload[..4].copy_from_slice(&request_id.to_le_bytes());
    payload[4] = status;
    let pid_bytes = pid.unwrap_or(0).to_le_bytes();
    payload[5..13].copy_from_slice(&pid_bytes);
    let mut offset = 13usize;
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(31);
    payload[offset..offset + name_len].copy_from_slice(&name_bytes[..name_len]);
    offset += name_len;
    if offset < payload.len() {
        payload[offset] = 0;
        offset += 1;
    }
    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len().min(payload.len().saturating_sub(offset));
    payload[offset..offset + msg_len].copy_from_slice(&msg_bytes[..msg_len]);
    let mut event = Message::empty();
    event.code = status as u32;
    event.payload.copy_from_slice(&payload);
    let _ = userlib::ipc_send(channels::SERVICE_CONTROL_EVENT, &event);
}
