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

/// 命令历史：内存态最近 8 条（环形）。单核 shell 独占执行，静态可变安全。
static mut HISTORY: [[u8; 128]; 8] = [[0; 128]; 8];
static mut HIST_LEN: [usize; 8] = [0; 8];
static mut HIST_HEAD: usize = 0;
static mut HIST_TOTAL: usize = 0;

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
        record_history(cmd);

        if cmd == b"exit" {
            println("bye");
            break;
        } else if cmd == b"help" || cmd == b"?" {
            println("commands: help info echo whoami pid forktest waittest clear history launchd exit");
        } else if cmd.starts_with(b"echo ") {
            println_bytes(&cmd[5..]);
        } else if cmd == b"whoami" {
            println("console");
        } else if cmd == b"pid" {
            match userlib::getpid() {
                Ok(p) => {
                    print("pid=");
                    print_u64(p);
                    println("");
                }
                Err(e) => {
                    print("pid: syscall failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"forktest" {
            // 端到端 fork 验证：svc #0 / x0=2。
            // 返回值区分父子：父=Ok(child_pid)，子=Ok(0)。
            // 子分支打印后立即 exit，绝不回到主循环——否则两个 shell
            // 会并发抢终端（read_line 双消费者）。[P]/[C] 前缀用于在
            // 并发输出交错时辨识来源行（console_write 无进程级串行化）。
            match userlib::fork() {
                Ok(0) => {
                    print("[C] child: alive (pid via getpid)=");
                    match userlib::getpid() {
                        Ok(p) => print_u64(p),
                        Err(e) => {
                            print("syscall failed (");
                            print_hex(e.code());
                            print(")");
                        }
                    }
                    println("");
                    exit(0); // -> ! ：子进程到此终结，永不返回主循环
                }
                Ok(child_pid) => {
                    print("[P] parent: child_pid=");
                    print_u64(child_pid);
                    println("");
                    // 子已 exit ⇒ 收尸，避免 zombie 占槽（wait4 语义上线后
                    // 不收尸的 fork 会泄漏进程表槽位）。
                    match userlib::wait_pid(child_pid) {
                        Ok((pid, code)) => {
                            print("[P] forktest: collected pid=");
                            print_u64(pid);
                            print(" code=");
                            print_i32(code);
                            println("");
                        }
                        Err(e) => {
                            print("[P] forktest: wait failed (");
                            print_hex(e.code());
                            println(")");
                        }
                    }
                }
                Err(e) => {
                    print("[P] forktest: fork failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"waittest" {
            // wait4 端到端验证：fork 出的子进程 sleep-ish 延时后
            // exit(42)；父进程 wait_pid 阻塞收集并打印 collected 行。
            // 子分支绝不回到主循环（同 forktest：防止双 shell 抢终端）。
            match userlib::fork() {
                Ok(0) => {
                    println("[C] waittest: child alive, delaying before exit(42)");
                    // 用户态无时钟源：易失黑盒递减近似延时（QEMU TCG 下约
                    // 数百毫秒），期间周期性 yield。目的仅是保证父进程先
                    // 进入 WaitPid 阻塞（fork→wait 路径仅数微秒），从而覆盖
                    // “挂起→子退出唤醒”路径；即使时序反转，内核快路径
                    // （子已成尸直接收集）同样正确。
                    let mut spin = 25_000_000u64;
                    while spin > 0 {
                        spin -= 1;
                        if spin & 0xFF == 0 {
                            core::hint::black_box(spin);
                        }
                        if spin % (1 << 22) == 0 {
                            userlib::yield_now();
                        }
                    }
                    userlib::exit(42);
                }
                Ok(child_pid) => {
                    print("[P] waittest: forked child ");
                    print_u64(child_pid);
                    println("");
                    match userlib::wait_pid(child_pid) {
                        Ok((pid, code)) => {
                            print("collected pid=");
                            print_u64(pid);
                            print(" code=");
                            print_i32(code);
                            println("");
                        }
                        Err(e) => {
                            print("[P] waittest: wait failed (");
                            print_hex(e.code());
                            println(")");
                        }
                    }
                }
                Err(e) => {
                    print("[P] waittest: fork failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"clear" {
            // ANSI：清屏 + 光标归位
            let _ = console_write(b"\x1b[2J\x1b[H");
        } else if cmd == b"history" {
            print_history();
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

/// 记录一条命令进历史（单核 shell：静态可变安全由独占执行保证）。
fn record_history(cmd: &[u8]) {
    if cmd.is_empty() {
        return;
    }
    unsafe {
        let head = HIST_HEAD;
        let slot = &mut HISTORY[head];
        let n = cmd.len().min(slot.len());
        slot[..n].copy_from_slice(&cmd[..n]);
        HIST_LEN[head] = n;
        HIST_HEAD = (head + 1) % HISTORY.len();
        HIST_TOTAL = (HIST_TOTAL + 1).min(HISTORY.len());
    }
}

fn print_history() {
    unsafe {
        let total = HIST_TOTAL;
        let head = HIST_HEAD;
        let start = (head + HISTORY.len() - total) % HISTORY.len();
        for k in 0..total {
            let idx = (start + k) % HISTORY.len();
            let len = HIST_LEN[idx];
            print_u64((k + 1) as u64);
            print(": ");
            println_bytes(&HISTORY[idx][..len]);
        }
        if total == 0 {
            println("(empty)");
        }
    }
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
                userlib::yield_now();
                continue;
            }
            Err(SysError::WouldBlock) => {
                // ⚠ 必须 continue：yield 会返回到 match 之后的语句，若不加
                // continue 就会贯穿到 ch=c[0]，把缓冲区残留的 0 当成收到的
                // 字节 —— 缓冲区被 NUL 填满、真实命令永远匹配不上。
                // （旧代码靠 yield_now 的错误 -> ! 标注掩盖了这一逻辑。）
                userlib::yield_now();
                continue;
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

/// 有符号整数打印（退出码可能为负）。
fn print_i32(v: i32) {
    if v < 0 {
        let _ = console_write(b"-");
        print_u64((-(v as i64)) as u64);
    } else {
        print_u64(v as u64);
    }
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