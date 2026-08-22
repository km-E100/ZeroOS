//! zero-shell —— 交互式用户态控制台（ELF 基址 0x200000，见 link-user.ld）。
//!
//! 全部 syscall 均在 0-20 号位内：`ConsoleWrite`(9)、`ConsoleRead`(6)、
//! `Yield`(svc #1 快捷入口)、`Exit`(svc #2 快捷入口)、`SendMessage`(0)、
//! `ReceiveMessage`(1)。禁止 MMIO（用户态无 MMIO 权限）。
//!
//! 入口参数（由内核 `set_initial_user_args` 提供）：
//! - `x0` = bootfs 文件表首地址（`UserBootFs.entries_ptr`）
//! - `x1` = bootfs 条目数（`UserBootFs.entries_len`）
//! - `x2` / `x3` = 0（预留）

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use userlib::{console_read, console_write, encode_message, exit, extract_payload_text};
use zero_abi::channels::{LAUNCHD_CMD_REQ, LAUNCHD_CMD_RESP};
use zero_abi::ipc::Message;
use zero_abi::protocol::launchd::{CMD_LIST_SERVICES, CMD_RESTART_SERVICE, CMD_STATUS};
use zero_abi::syscall::SysError;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let msg = b"\nshell panic\n";
    let _ = console_write(msg);
    exit(1);
}

extern "C" {
    static mut __bss_start: u8;
    static mut __bss_end: u8;
}

#[no_mangle]
pub unsafe extern "C" fn _start(a0: u64, a1: u64, a2: u64, a3: u64) -> ! {
    // 清 .bss：内核加载器不保证清零
    let mut p = &raw mut __bss_start as *mut u8;
    let end = &raw mut __bss_end as *mut u8;
    while p < end {
        core::ptr::write_volatile(p, 0);
        p = p.add(1);
    }

    // 内核以 x0-x3 传入启动参数（x0/x1 = bootfs 表地址/条目数）
    user_entry(a0, a1, a2, a3);

    exit(0);
}

/// 主循环：回显键盘输入，支持内建命令。
pub fn user_entry(bootfs_ptr: u64, bootfs_len: u64, a2: u64, _a3: u64) -> u64 {
    println("\r\nZero OS console (user shell)");
    println("Type 'help' for commands.");

    let mut line: [u8; 256] = [0; 256];
    loop {
        print("zero> ");
        let n = read_line(&mut line);
        if n == 0 {
            continue;
        }
        // 去掉末尾 CR/LF
        let mut end = n;
        while end > 0 && (line[end - 1] == b'\r' || line[end - 1] == b'\n') {
            end -= 1;
        }
        let cmd = &line[..end];

        if cmd == b"exit" {
            println("bye");
            break;
        } else if cmd == b"help" || cmd == b"?" {
            println("commands: help info echo whoami launchd exit");
        } else if cmd.starts_with(b"echo ") {
            println_bytes(&cmd[5..]);
        } else if cmd == b"whoami" {
            println("console");
        } else if cmd == b"info" {
            // 打印启动参数（bootfs 表地址/条目数 + 预留位）
            print("bootfs_ptr=0x");
            print_hex(bootfs_ptr);
            print(" bootfs_len=");
            print_u64(bootfs_len);
            print(" x2=0x");
            print_hex(a2);
            println(" x3=0x0");
        } else if cmd == b"launchd" || cmd.starts_with(b"launchd ") {
            launchd_command(cmd);
        } else if cmd.len() > 0 {
            print_bytes(b"unknown command: ");
            println_bytes(cmd);
        }
    }
    0
}

/// `launchd list` / `launchd status` / `launchd spawn <服务名>`。
/// 协议对齐 `zero-abi::protocol::launchd`，走 0x240/0x241 通道。
fn launchd_command(cmd: &[u8]) {
    let rest = if cmd == b"launchd" {
        &cmd[7..]
    } else {
        &cmd[8..]
    };
    if rest == b"list" {
        request(CMD_LIST_SERVICES, &[]);
    } else if rest == b"status" {
        request(CMD_STATUS, &[]);
    } else if rest.starts_with(b"spawn ") {
        // payload：name\0
        let name = &rest[6..];
        if name.is_empty() {
            println("usage: launchd spawn <service-name>");
            return;
        }
        let mut payload = [0u8; 64];
        if name.len() + 1 > payload.len() {
            println("service name too long");
            return;
        }
        payload[..name.len()].copy_from_slice(name);
        request(CMD_RESTART_SERVICE, &payload[..name.len() + 1]);
    } else {
        println("usage: launchd <list|status|spawn <name>>");
    }
}

/// 发一条 launchd 请求并等待响应打印结果。
fn request(code: u32, payload: &[u8]) {
    let message = encode_message(code, payload);
    match userlib::ipc_send(LAUNCHD_CMD_REQ, &message) {
        Ok(_) => {}
        Err(SysError::ChannelUnavailable) => {
            println("launchd: request queue full");
            return;
        }
        Err(_) => {
            println("launchd: send failed (is launchd online?)");
            return;
        }
    }
    loop {
        let mut response = Message::empty();
        match userlib::ipc_receive(LAUNCHD_CMD_RESP, &mut response) {
            Ok(_) => {
                let text = extract_payload_text(&response.payload);
                print("launchd: [");
                print_u64(response.code as u64);
                print("] ");
                println(text);
                return;
            }
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => {
                println("launchd: receive failed");
                return;
            }
        }
    }
}

fn read_line(buf: &mut [u8]) -> usize {
    let mut i = 0usize;
    while i < buf.len() {
        let mut c: [u8; 1] = [0];
        match console_read(&mut c) {
            Ok(0) => {
                // 无输入兜底：让出 CPU 避免空转
                userlib::yield_now();
            }
            Err(SysError::WouldBlock) => {
                // yield_now 永不返回，切走后在调度器恢复时从循环头继续
                userlib::yield_now();
            }
            Err(_) => return i,
            Ok(_) => {}
        }
        let ch = c[0];
        if ch == b'\n' || ch == b'\r' {
            buf[i] = ch;
            i += 1;
            break;
        } else if ch == 0x7f || ch == 0x08 {
            // backspace
            if i > 0 {
                i -= 1;
                let _ = console_write(b"\x08 \x08");
            }
        } else {
            buf[i] = ch;
            i += 1;
            let _ = console_write(&c);
        }
    }
    i
}

fn print(text: &str) {
    let _ = console_write(text.as_bytes());
}

fn println(text: &str) {
    print(text);
    let _ = console_write(b"\r\n");
}

fn print_bytes(text: &[u8]) {
    let _ = console_write(text);
}

fn println_bytes(text: &[u8]) {
    print_bytes(text);
    let _ = console_write(b"\r\n");
}

fn print_u64(mut v: u64) {
    if v == 0 {
        let _ = console_write(b"0");
        return;
    }
    let mut digits: [u8; 20] = [0; 20];
    let mut i = digits.len();
    while v > 0 {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let _ = console_write(&digits[i..]);
}

fn print_hex(mut v: u64) {
    if v == 0 {
        let _ = console_write(b"0");
        return;
    }
    let mut digits: [u8; 16] = [0; 16];
    let mut i = digits.len();
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
    let _ = console_write(&digits[i..]);
}