//! zero-shell —— 交互式用户态控制台（ELF 基址 0x200000，见 link-user.ld）。
//!
//! 全部 syscall 均在 0-22 号位内：`ConsoleWrite`(9)、`ConsoleRead`(6)、
//! `Yield`(svc #1 快捷入口)、`Exit`(svc #2 快捷入口)、`SendMessage`(0)、
//! `ReceiveMessage`(1)、`BlockRead`(7)/`BlockWrite`(8，仅 blktest
//! 的 raw 扇区回环验证使用)、`Exec`(3，execdemo 经 fork 子进程使用)。
//! 禁止 MMIO（用户态无 MMIO 权限）。
//!
//! 【exec 自检协议】本二进制同时是 execdemo 的重载目标：内核 exec 把调用方
//! 透传值放在 x2——非 0 即"被 exec 启动的演示实例"，打印新地址空间证据行
//! 后以该值作为退出码结束进程；x2=0 走正常交互主循环。详见 _start 与
//! execdemo_command 注释。
//!
//! 入口参数（由内核 `set_initial_user_args` 提供）：
//! - `x0` = bootfs 文件表首地址（`UserBootFs.entries_ptr`）
//! - `x1` = bootfs 条目数（`UserBootFs.entries_len`）
//! - `x2` / `x3` = 0（预留）

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use userlib::{
    console_read, console_write, encode_message, exec, exit, extract_payload_text, wait_pid,
    wait_pid_flags, WAIT_NOHANG,
};
use zero_abi::channels::{FS_REQ, FS_RESP, LAUNCHD_CMD_REQ, LAUNCHD_CMD_RESP};
use zero_abi::ipc::Message;
use zero_abi::protocol::fs as fs_proto;
use zero_abi::protocol::fs::vtable as fs_vt;
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

    // ── exec 自检协议（execdemo 配套，见 execdemo_command 注释）──
    // 内核 exec 把调用方透传值放在 x2：非 0 即"被 exec 启动的演示实例"
    // ——打印新地址空间证据行后以该值为退出码结束，绝不进入交互主循环
    // （否则 exec 出的子 shell 会与父 shell 抢终端）。正常引导与普通
    // 重载 x2=0，走主循环。此分支运行在 exec 刚换上的全新地址空间里
    // （全新页表 + 全新用户栈 + 重新映射的 bootfs），能打印即证明
    // 地址空间更换成功。
    if a2 != 0 {
        print("[C] exec-image: fresh AS! bootfs=0x");
        print_hex(a0);
        print(" marker=");
        print_u64(a2);
        println("");
        exit(a2 as i32);
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
            // 分组总览：process（进程语义）/ storage（块与文件）/ system（其余）。
            println("commands:");
            println("  process: forktest/waittest/nohangtest/orphantest/waitspec/execdemo/pid");
            println("  storage: fstest/blktest");
            println("  system: launchd/pid/clear/history/echo/whoami/help/exit");
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
        } else if cmd == b"nohangtest" {
            // WNOHANG 端到端（第七刀）：fork 子延时 exit(7)；父以
            // wait_pid_flags(0, WAIT_NOHANG) 轮询——子存活期间必须返回
            // Ok(None)（内核回 0、不挂起），子成尸后同一调用收集 (pid,7)。
            // 若轮询语义回归成挂起，父会卡死、提示符不再出现，实机一眼可判。
            match userlib::fork() {
                Ok(0) => {
                    println("[C] nohangtest: child alive, delaying before exit(7)");
                    delay_cycles(8_000_000);
                    userlib::exit(7);
                }
                Ok(child_pid) => {
                    print("[P] nohangtest: forked child ");
                    print_u64(child_pid);
                    println("");
                    let mut misses = 0u64;
                    let mut done = false;
                    for _ in 0..400 {
                        match wait_pid_flags(0, WAIT_NOHANG) {
                            Ok(None) => {
                                misses += 1;
                                userlib::yield_now();
                            }
                            Ok(Some((pid, code))) => {
                                print("[P] nohangtest: polls-missed=");
                                print_u64(misses);
                                print(" collected pid=");
                                print_u64(pid);
                                print(" code=");
                                print_i32(code);
                                println("");
                                if misses > 0 && code == 7 && pid == child_pid {
                                    println("[P] nohangtest: PASS");
                                } else {
                                    println("[P] nohangtest: FAIL (bad sequence)");
                                }
                                done = true;
                                break;
                            }
                            Err(e) => {
                                print("[P] nohangtest: poll failed (");
                                print_hex(e.code());
                                println(")");
                                done = true;
                                break;
                            }
                        }
                    }
                    if !done {
                        println("[P] nohangtest: FAIL (never collected within budget)");
                    }
                }
                Err(e) => {
                    print("[P] nohangtest: fork failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"orphantest" {
            // 孤儿收养端到端（第七刀）：四代进程链 P→A→B→C。
            //   A exit(5) → 父 P 收尸（BecomeZombie→Collect）；
            //   B exit(9) 时其父 A 已不在表 → ReapImmediately → full_reap(B)，
            //     此刻 C 还活着 ⇒ 命中 AdoptToInit：内核串口打
            //     "process .. orphaned: parent .. died, adopted by init(pid=2)"；
            //   C exit(11)：adopted=true ⇒ 防御回收（跳过 Zombie 直接完全回收）。
            // 收养/防御回收的证据行在内核日志（qemu 串口）而非 shell 输出。
            match userlib::fork() {
                Ok(0) => {
                    // A：中间代
                    match userlib::fork() {
                        Ok(0) => {
                            // B：将在无父状态下退出并触发对 C 的收养
                            match userlib::fork() {
                                Ok(0) => {
                                    // C：将成孤儿的第四代
                                    println("[GG] orphantest: great-grandchild alive, delaying before exit(11)");
                                    delay_cycles(20_000_000);
                                    userlib::exit(11);
                                }
                                Ok(grand_pid) => {
                                    print("[G] orphantest: B forked C pid=");
                                    print_u64(grand_pid);
                                    println(", delaying before exit(9)");
                                    delay_cycles(6_000_000);
                                    userlib::exit(9);
                                }
                                Err(e) => {
                                    print("[G] orphantest: fork C failed (");
                                    print_hex(e.code());
                                    println(")");
                                    userlib::exit(6);
                                }
                            }
                        }
                        Ok(child_pid) => {
                            print("[C] orphantest: A forked B pid=");
                            print_u64(child_pid);
                            println(", exiting now (5) to start the chain");
                            userlib::exit(5);
                        }
                        Err(e) => {
                            print("[C] orphantest: fork B failed (");
                            print_hex(e.code());
                            println(")");
                            userlib::exit(6);
                        }
                    }
                }
                Ok(child_pid) => {
                    print("[P] orphantest: forked A pid=");
                    print_u64(child_pid);
                    println("");
                    match wait_pid(child_pid) {
                        Ok((pid, code)) => {
                            print("[P] orphantest: collected A pid=");
                            print_u64(pid);
                            print(" code=");
                            print_i32(code);
                            println("");
                            if code == 5 {
                                println("[P] orphantest: PASS (see kernel log for adopted-by-init + defensive reap)");
                            } else {
                                println("[P] orphantest: FAIL (unexpected exit code)");
                            }
                        }
                        Err(e) => {
                            print("[P] orphantest: wait failed (");
                            print_hex(e.code());
                            println(")");
                        }
                    }
                }
                Err(e) => {
                    print("[P] orphantest: fork failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"waitspec" {
            // 精确目标 wait 端到端（第九刀）：fork 两个子进程**乱序**退出
            //   A：长延时 → exit(33)；B：短延时 → exit(66)（B 必先死）。
            // 父随后立刻 wait_pid(A)，阻塞在精确目标上——期间 B 先退出，
            // 这正是“bool 单标记误投递”的历史缺口场景：旧内核会把 B 的
            // (pid,66) 写进等 A 的父帧并误消费 B 尸体；新内核只认登记的
            // 目标，父睡到 A 真正退出才收到 (A,33)。随后 wait_pid(B)
            // 快路径收走留表的 B 尸体得 (B,66)。两行 collected 各归其主
            // ⇒ 不误投。
            match userlib::fork() {
                Ok(0) => {
                    // 子 A：长延时后 exit(33)
                    println("[A] waitspec: child A alive, long delay then exit(33)");
                    delay_cycles(20_000_000);
                    userlib::exit(33);
                }
                Ok(a_pid) => match userlib::fork() {
                    Ok(0) => {
                        // 子 B：短延时后 exit(66)，必先于 A 死亡
                        println("[B] waitspec: child B alive, short delay then exit(66)");
                        delay_cycles(3_000_000);
                        userlib::exit(66);
                    }
                    Ok(b_pid) => {
                        print("[P] waitspec: A=");
                        print_u64(a_pid);
                        print(" B=");
                        print_u64(b_pid);
                        println("");
                        let mut pass = true;
                        // ① 先等 A（精确 pid）：阻塞期间 B 会先退出。
                        match userlib::wait_pid(a_pid) {
                            Ok((pid, code)) => {
                                print("collected pid=");
                                print_u64(pid);
                                print(" code=");
                                print_i32(code);
                                println("");
                                if pid != a_pid || code != 33 {
                                    pass = false;
                                }
                            }
                            Err(e) => {
                                print("[P] waitspec: wait(A) failed (");
                                print_hex(e.code());
                                println(")");
                                pass = false;
                            }
                        }
                        // ② 再等 B：尸体应原样留在表里（未被①误消费），
                        //    快路径收取。若①被误投，这里要么 NotFound
                        //    （尸体已被错拿）要么拿到错的码。
                        match userlib::wait_pid(b_pid) {
                            Ok((pid, code)) => {
                                print("collected pid=");
                                print_u64(pid);
                                print(" code=");
                                print_i32(code);
                                println("");
                                if pid != b_pid || code != 66 {
                                    pass = false;
                                }
                            }
                            Err(e) => {
                                print("[P] waitspec: wait(B) failed (");
                                print_hex(e.code());
                                println(")");
                                pass = false;
                            }
                        }
                        if pass {
                            println("[P] waitspec: PASS (two precise collects, out-of-order exits)");
                        } else {
                            println("[P] waitspec: FAIL (misdelivered or wrong-code collect)");
                        }
                    }
                    Err(e) => {
                        print("[P] waitspec: fork B failed (");
                        print_hex(e.code());
                        println(")");
                    }
                },
                Err(e) => {
                    print("[P] waitspec: fork failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"execdemo" {
            // execve 端到端验证（第九刀）：真换地址空间。见 execdemo_command。
            execdemo_command();
        } else if cmd == b"fstest" {
            // 端到端文件语义验证（第七刀）：经 launchd list 预检 fsd/
            // blkdrv 在线后，向 FS_REQ 发 open/create → write("ZERO-FSD")
            // → read 回读比对 → close 序列，逐步打印结果。
            fstest_command();
        } else if cmd == b"blktest" || cmd.starts_with(b"blktest ") {
            // raw 块设备端到端验证：号位 7/8 内核直通（绕过 fsd 卷语义）。
            blktest_command(cmd);
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

/// 用户态近似延时（易失黑盒递减 + 周期性 yield）。环境无时钟源，
/// 与 waittest 内联循环同源写法；仅用于让父进程先抵达等待点 /
/// 拉开多代退出次序。
fn delay_cycles(mut spin: u64) {
    while spin > 0 {
        spin -= 1;
        if spin & 0xFF == 0 {
            core::hint::black_box(spin);
        }
        if spin % (1 << 22) == 0 {
            userlib::yield_now();
        }
    }
}

/// execdemo —— execve 端到端验证（第九刀）：证明号位 3 是**真换地址空间**
/// 的 exec，而非旧版"重置帧跳函数指针"的伪 exec。
///
/// 流程：fork 出子进程 → 子进程打印旧映像证据行 → 子调
/// exec("/Applications/Shell", 77)（内核销毁子进程旧地址空间、重新装载
/// Shell ELF、切换 TTBR0、重置 TrapFrame）→ 新映像经 _start 的 exec 自检
/// 协议（x2=77≠0）打印特征 banner 并 exit(77) → 父进程 wait_pid 收集退出码。
///
/// 三行证据链（缺一不可）：
/// 1. "[C] execdemo: OLD image ..." —— 来自旧地址空间（exec 之前的代码）；
/// 2. "[C] exec-image: fresh AS! ..." —— 只能来自新装入的 ELF 映射：
///    这是全新页表 + 全新用户栈上的新实例；其 bootfs 映射地址必然不同于
///    本命令运行前的 bootfs 地址（exec 构建新空间时旧空间尚未销毁，
///    物理页不可能重叠）；
/// 3. "[P] execdemo: collected ... code=77" —— pid 未变而映像已换，
///    且 zombie/waitpid 状态机跨 exec 继续成立。
fn execdemo_command() {
    match userlib::fork() {
        Ok(0) => {
            // —— 子进程：旧映像内的最后遗言，随后彻底换血 ——
            print("[C] execdemo: OLD image alive (pid=");
            match userlib::getpid() {
                Ok(p) => print_u64(p),
                Err(e) => {
                    print("syscall failed (");
                    print_hex(e.code());
                    print(")");
                }
            }
            println("), execing /Applications/Shell");
            // 成功即不返回：控制流已转向新映像入口。Err 分支里旧映像仍在，
            // 报错后带码退出供父收集；若 exec 谎报成功返回（内核 bug），
            // 兜底 exit(70) 防止跌回主循环造成双 shell 抢终端。
            if let Err(e) = exec("/Applications/Shell", 77) {
                print("[C] execdemo: exec failed (");
                print_hex(e.code());
                println(")");
                exit(1);
            }
            exit(70);
        }
        Ok(child_pid) => {
            print("[P] execdemo: forked child ");
            print_u64(child_pid);
            println("");
            match wait_pid(child_pid) {
                Ok((pid, code)) => {
                    print("[P] execdemo: collected pid=");
                    print_u64(pid);
                    print(" code=");
                    print_i32(code);
                    println("");
                    if pid == child_pid && code == 77 {
                        println("[P] execdemo: PASS - address space truly replaced");
                    } else {
                        println("[P] execdemo: FAIL (unexpected pid/code)");
                    }
                }
                Err(e) => {
                    print("[P] execdemo: wait failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        }
        Err(e) => {
            print("[P] execdemo: fork failed (");
            print_hex(e.code());
            println(")");
        }
    }
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

/// fstest —— fsd 块卷文件语义端到端验证（第七刀）。
///
/// 序列：launchd list 预检 fsd/blkdrv 在线 → open("zerofsd.txt",
/// CREATE) → write "ZERO-FSD" → close → reopen(EXISTING) → read 回读
/// 比对 → close。写后必须重开再读：fd 偏移随写推进（POSIX 语义），
/// 顺序读只会得到 EOF。任何一步失败即中止并打印协议错误码。响应
/// 配对依赖单客户端纪律（见 zero_abi::protocol::fs::vtable 冻结注释）；
/// 预检的意义：向无人应答的 FS_REQ 发消息会在阻塞接收上无限等待
/// ——必须先确认服务在线。
fn fstest_command() {
    // ---- 0) 预检：fsd / blkdrv 必须处于 [running] ----
    let mut listing = Message::empty();
    if userlib::ipc_send(LAUNCHD_CMD_REQ, &encode_message(CMD_LIST_SERVICES, &[])).is_err() {
        println("fstest: launchd unreachable");
        return;
    }
    loop {
        match userlib::ipc_receive(LAUNCHD_CMD_RESP, &mut listing) {
            Ok(_) => break,
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => {
                println("fstest: launchd list receive failed");
                return;
            }
        }
    }
    let text = extract_payload_text(&listing.payload);
    if !text.contains("fsd [running") {
        println("fstest: fsd not running (try: launchd spawn fsd)");
        return;
    }
    if !text.contains("blkdrv [running") {
        println("fstest: blkdrv not running (no block backend; try: launchd spawn blkdrv)");
        return;
    }

    const MARK: &[u8; 8] = b"ZERO-FSD";
    const NAME: &[u8] = b"zerofsd.txt";

    // ---- 1) open/create ----
    let mut request = Message::empty();
    request.code = fs_vt::CMD_OPEN;
    request.payload[..NAME.len()].copy_from_slice(NAME);
    request.payload[NAME.len()] = 0; // NUL 收尾
    request.payload[NAME.len() + 1] = fs_vt::OPEN_CREATE; // mode 字节
    print("[1/6] open \"zerofsd.txt\" create: ");
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    if response.code != 0 {
        print_fs_fail("open", response.code);
        return;
    }
    let fd = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    print("fd=");
    print_u64(fd as u64);
    println("");

    // ---- 2) write "ZERO-FSD" ----
    let mut request = Message::empty();
    request.code = fs_vt::CMD_WRITE;
    request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
    request.payload[4..8].copy_from_slice(&(MARK.len() as u32).to_le_bytes());
    request.payload[8..8 + MARK.len()].copy_from_slice(MARK);
    print("[2/6] write \"ZERO-FSD\": ");
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    if response.code != 0 {
        print_fs_fail("write", response.code);
        return;
    }
    let written = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    print("wrote ");
    print_u64(written as u64);
    println(" bytes");

    // ---- 3) close 写句柄（POSIX 语义：写后偏移在文件尾，须重开再读）----
    print("[3/6] close write fd=");
    print_u64(fd as u64);
    print(": ");
    if !send_close(fd) {
        return;
    }

    // ---- 4) 重开（EXISTING，偏移归零；无 mode 字节路径）----
    let mut request = Message::empty();
    request.code = fs_vt::CMD_OPEN;
    request.payload[..NAME.len()].copy_from_slice(NAME);
    request.payload[NAME.len()] = 0; // NUL 收尾，无 mode → EXISTING
    print("[4/6] reopen existing: ");
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    if response.code != 0 {
        print_fs_fail("reopen", response.code);
        return;
    }
    let fd = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    print("fd=");
    print_u64(fd as u64);
    println("");

    // ---- 5) read 回读 + 比对 ----
    let mut request = Message::empty();
    request.code = fs_vt::CMD_READ;
    request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
    request.payload[4..8].copy_from_slice(&(MARK.len() as u32).to_le_bytes());
    print("[5/6] read 8 bytes back: \"");
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    if response.code != 0 {
        print_fs_fail("read", response.code);
        return;
    }
    print_bytes(&response.payload[..MARK.len()]);
    println("\"");
    if &response.payload[..MARK.len()] == MARK {
        println("      compare: MATCH");
    } else {
        println("      compare: MISMATCH (expected ZERO-FSD)");
        // 尽力关掉 fd 后中止。
        send_close(fd);
        println("fstest: FAIL at compare step");
        return;
    }

    // ---- 6) close ----
    print("[6/6] close fd=");
    print_u64(fd as u64);
    print(": ");
    if !send_close(fd) {
        return;
    }

    println("fstest: PASS - fsd block-backed volume verified end-to-end");
}

/// 发送一条 FS 请求并等待 FS_RESP 响应。发送失败（通道满/不可用）
/// 返回 None 并提示。收到错误码由调用方按协议解释。
fn fs_exchange(request: &Message) -> Option<Message> {
    match userlib::ipc_send(FS_REQ, request) {
        Ok(_) => {}
        Err(SysError::ChannelUnavailable) => {
            println("fstest: FS_REQ queue full");
            return None;
        }
        Err(_) => {
            println("fstest: FS_REQ send failed (is fsd online?)");
            return None;
        }
    }
    loop {
        let mut response = Message::empty();
        match userlib::ipc_receive(FS_RESP, &mut response) {
            Ok(_) => return Some(response),
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => {
                println("fstest: FS_RESP receive failed");
                return None;
            }
        }
    }
}

/// CLOSE 一条 fd；失败时打印并返回 false。
fn send_close(fd: u32) -> bool {
    let mut request = Message::empty();
    request.code = fs_vt::CMD_CLOSE;
    request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
    let Some(response) = fs_exchange(&request) else {
        return false;
    };
    if response.code != 0 {
        print_fs_fail("close", response.code);
        return false;
    }
    println("ok");
    true
}

/// 协议错误码 → 可读文本 + 统一失败行。
fn print_fs_fail(step: &str, code: u32) {
    print("FAIL (");
    print(step);
    print(": ");
    let reason = match code {
        fs_proto::ERR_NOT_FOUND => "not found",
        fs_proto::ERR_INVALID => "invalid argument",
        fs_proto::ERR_NO_DESCRIPTOR => "no descriptor / table full",
        fs_proto::ERR_DEVICE => "device error (volume not mounted? blkdrv/disk missing?)",
        _ => "unknown error",
    };
    print(reason);
    println(")");
    println("fstest: FAIL");
}

/// blktest —— raw 块设备读写端到端验证（号位 7/8 内核直通，**绕过 fsd**）。
///
/// 序列：构造 512 字节特征图案 → block_write 写入 → block_read 读回 →
/// 逐字节比对 → 打印 PASS / MISMATCH。每一步失败都友好打印后返回，
/// 绝不 panic（panic_handler 只是最后防线）。
///
/// 选址纪律：默认 LBA 60000。测试盘 32MiB = 65536 扇区，尾段 5500+ 扇区
/// 是天然安全带；而低地址区域住着内核自检(@2048)、userdb(@4096)、fsd
/// 超级块(@8192)与数据区(@16384 起)。`blktest <lba>` 允许指定其他扇区，
/// 但低于 40000 的一律拒绝执行——raw 写入毁掉 fsd 卷可就不好玩了。
fn blktest_command(cmd: &[u8]) {
    const SECTOR: usize = 512;
    /// fsd 卷保留区安全上界（《编译打包命令.txt》LBA 保留地图 + 裕量）。
    const MIN_SAFE_LBA: u64 = 40_000;
    /// 默认扇区：32MiB 测试盘尾段安全带。
    const DEFAULT_LBA: u64 = 60_000;

    // ---- 参数解析：blktest [lba]（十进制）----
    let lba = if cmd == b"blktest" {
        DEFAULT_LBA
    } else {
        match parse_u64(&cmd[8..]) {
            Some(v) if v >= MIN_SAFE_LBA => v,
            Some(_) => {
                println("blktest: refused: LBA < 40000 overlaps the fsd volume region");
                return;
            }
            None => {
                println("usage: blktest [lba]   (decimal; default 60000; must be >= 40000)");
                return;
            }
        }
    };

    print("blktest: raw sector round-trip at LBA=");
    print_u64(lba);
    println(" (direct syscall 7/8, bypasses fsd)");

    // ---- 1) 构造特征图案并写入 ----
    let mut wbuf = [0u8; SECTOR];
    fill_block_pattern(&mut wbuf, lba);
    print("[1/3] write 512-byte signature pattern: ");
    if let Err(e) = userlib::block_write(lba, &wbuf) {
        print_block_fail("write", e);
        return;
    }

    // ---- 2) 读回 ----
    let mut rbuf = [0u8; SECTOR];
    print("[2/3] read back: ");
    if let Err(e) = userlib::block_read(lba, &mut rbuf) {
        print_block_fail("read", e);
        return;
    }

    // ---- 3) 逐字节比对 ----
    print("[3/3] compare: ");
    match (0..SECTOR).find(|&i| rbuf[i] != wbuf[i]) {
        None => {
            println("identical");
            println("blktest: PASS - raw block write/read round-trip verified");
        }
        Some(off) => {
            print("MISMATCH at offset ");
            print_u64(off as u64);
            print(" (expected 0x");
            print_hex(wbuf[off] as u64);
            print(", got 0x");
            print_hex(rbuf[off] as u64);
            println(")");
            println("blktest: FAIL - data did not survive the round trip");
        }
    }
}

/// blktest 单步失败统一打印：错误名 + 编码 + 排查提示，然后返回。
fn print_block_fail(step: &str, e: SysError) {
    print("failed (");
    print(e.as_str());
    print(" code=0x");
    print_hex(e.code());
    println(")");
    if e == SysError::DeviceError {
        println("blktest: hint: is the virtio-blk test disk attached? (./run-qemu.sh mounts target/disk.img)");
    }
    print("blktest: FAIL at ");
    print(step);
    println(" step");
}

/// 生成确定性特征图案：8 字节魔数 "ZEROBLK1" + 小端 LBA +
/// 位置相关伪随机体（比对时以同一函数重算期望值，不依赖读缓冲自身）。
fn fill_block_pattern(buf: &mut [u8], lba: u64) {
    buf[..8].copy_from_slice(b"ZEROBLK1");
    buf[8..16].copy_from_slice(&lba.to_le_bytes());
    let mut acc = (lba as u32) ^ 0xDEAD_BEEF;
    for byte in buf.iter_mut().skip(16) {
        acc = acc.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (acc >> 24) as u8;
    }
}

/// 十进制无符号解析（blktest 参数用；空串/非数字/溢出返回 None）。
fn parse_u64(text: &[u8]) -> Option<u64> {
    if text.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in text {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(value)
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