#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use core::panic::PanicInfo;
use useralloc::StaticFreeList;

#[global_allocator]
static ALLOCATOR: StaticFreeList<{ 32 * 1024 }> = StaticFreeList::new();

use libfsclient::{
    delete_file, install_device, list_devices, list_entries, open, write_file, DeviceSummary,
};
use userlib::{console_read, console_write, exit};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut buffer = [0u8; 512];
    loop {
        write_line("\r\nfsctl> ");
        let line = read_line(&mut buffer);
        if line.is_empty() {
            continue;
        }
        match line.trim() {
            "list" => cmd_list(),
            "devices" => cmd_devices(),
            cmd if cmd.starts_with("cat ") => cmd_cat(&cmd[4..]),
            cmd if cmd.starts_with("write ") => cmd_write(&cmd[6..]),
            cmd if cmd.starts_with("rm ") => cmd_remove(&cmd[3..]),
            cmd if cmd.starts_with("install ") => cmd_install(&cmd[8..]),
            "help" => show_help(),
            "exit" | "quit" => exit(0),
            _ => write_line("Unknown command. Type 'help'.\r\n"),
        }
    }
}

fn cmd_list() {
    let mut buffer = [0u8; 512];
    match list_entries(&mut buffer) {
        Ok(len) => {
            if len == 0 {
                write_line("(no entries)\r\n");
            } else if let Ok(text) = core::str::from_utf8(&buffer[..len]) {
                write_line(text);
            }
        }
        Err(err) => {
            let mut msg = String::from("list failed: ");
            format_error(&mut msg, err);
            msg.push_str("\r\n");
            write_line(&msg);
        }
    }
}

fn cmd_cat(path: &str) {
    match open(path) {
        Ok(mut handle) => {
            let mut buffer = [0u8; 128];
            loop {
                match handle.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = console_write(&buffer[..n]);
                    }
                    Err(err) => {
                        let mut msg = String::from("read failed: ");
                        format_error(&mut msg, err);
                        msg.push_str("\r\n");
                        write_line(&msg);
                        break;
                    }
                }
            }
            let _ = handle.close();
            write_line("\r\n");
        }
        Err(err) => {
            let mut msg = String::from("open failed: ");
            format_error(&mut msg, err);
            msg.push_str("\r\n");
            write_line(&msg);
        }
    }
}

fn show_help() {
    write_line(
        "Commands:\r\n  help             Show this help\r\n  list             List files\r\n  cat <path>       Dump file contents\r\n  write <path> <text>  Write/replace file\r\n  rm <path>        Delete file\r\n  devices          List block devices\r\n  install <index>  Format + install to device\r\n  exit             Quit\r\n",
    );
}

fn cmd_devices() {
    let mut entries = [DeviceSummary::default(); 8];
    match list_devices(&mut entries) {
        Ok(count) if count == 0 => write_line("no devices\r\n"),
        Ok(count) => {
            write_line("index  type  block  capacity(blocks)\r\n");
            for info in entries.iter().take(count) {
                let _ = core::fmt::Write::write_fmt(
                    &mut ConsoleWriter,
                    format_args!(
                        "{:>5}  {:>4}  {:>5}  {:>16}\r\n",
                        info.index, info.device_type, info.block_size, info.capacity_blocks
                    ),
                );
            }
        }
        Err(err) => {
            let mut msg = String::from("devices failed: ");
            format_error(&mut msg, err);
            msg.push_str("\r\n");
            write_line(&msg);
        }
    }
}

fn cmd_install(arg: &str) {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        write_line("usage: install <index>\r\n");
        return;
    }
    match parse_u8(trimmed) {
        Some(index) => match install_device(index) {
            Ok(_) => write_line("install completed\r\n"),
            Err(err) => {
                let mut msg = String::from("install failed: ");
                format_error(&mut msg, err);
                msg.push_str("\r\n");
                write_line(&msg);
            }
        },
        None => write_line("invalid index\r\n"),
    }
}

fn cmd_write(args: &str) {
    match split_arg(args) {
        Some((path, data)) => match write_file(path, data.as_bytes()) {
            Ok(_) => write_line("write complete\r\n"),
            Err(err) => {
                let mut msg = String::from("write failed: ");
                format_error(&mut msg, err);
                msg.push_str("\r\n");
                write_line(&msg);
            }
        },
        None => write_line("usage: write <path> <text>\r\n"),
    }
}

fn cmd_remove(args: &str) {
    let path = args.trim();
    if path.is_empty() {
        write_line("usage: rm <path>\r\n");
        return;
    }
    match delete_file(path) {
        Ok(_) => write_line("removed\r\n"),
        Err(err) => {
            let mut msg = String::from("rm failed: ");
            format_error(&mut msg, err);
            msg.push_str("\r\n");
            write_line(&msg);
        }
    }
}

fn parse_u8(text: &str) -> Option<u8> {
    let mut value: u32 = 0;
    for byte in text.bytes() {
        if !(b'0'..=b'9').contains(&byte) {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((byte - b'0') as u32)?;
    }
    if value <= u8::MAX as u32 {
        Some(value as u8)
    } else {
        None
    }
}

fn split_arg(input: &str) -> Option<(&str, &str)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut split = None;
    for (idx, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_whitespace() {
            split = Some(idx);
            break;
        }
    }
    if let Some(idx) = split {
        let path = trimmed[..idx].trim();
        let rest = trimmed[idx..].trim();
        if path.is_empty() || rest.is_empty() {
            None
        } else {
            Some((path, rest))
        }
    } else {
        None
    }
}

struct ConsoleWriter;

impl core::fmt::Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let _ = console_write(s.as_bytes());
        Ok(())
    }
}

fn read_line(buffer: &mut [u8]) -> &str {
    let mut len = 0;
    loop {
        let mut byte = [0u8; 1];
        if console_read(&mut byte).is_ok() && byte[0] != 0 {
            match byte[0] {
                b'\r' | b'\n' => {
                    write_line("\r\n");
                    break;
                }
                8 | 127 => {
                    if len > 0 {
                        len -= 1;
                        let _ = console_write(b"\x08 \x08");
                    }
                }
                _ => {
                    if len < buffer.len() {
                        buffer[len] = byte[0];
                        len += 1;
                        let _ = console_write(&byte);
                    }
                }
            }
        }
    }
    core::str::from_utf8(&buffer[..len]).unwrap_or("")
}

fn write_line(text: &str) {
    let _ = console_write(text.as_bytes());
}

fn format_error(msg: &mut String, err: libfsclient::FsError) {
    use libfsclient::FsError::*;
    match err {
        NotFound => msg.push_str("not found"),
        Invalid => msg.push_str("invalid request"),
        NoDescriptor => msg.push_str("bad descriptor"),
        DeviceError => msg.push_str("device error"),
        Ipc(_) => msg.push_str("ipc error"),
        Syscall(_) => msg.push_str("syscall error"),
        Unknown(code) => {
            msg.push_str("code ");
            let _ = core::fmt::Write::write_fmt(msg, format_args!("{}", code));
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
