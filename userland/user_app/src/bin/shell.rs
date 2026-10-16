//! zero-shell —— 交互式用户态控制台（ELF 基址 0x200000，见 link-user.ld）。
//!
//! 全部 syscall 均在已冻结号位内：`ConsoleWrite`(9)、`ConsoleRead`(6)、
//! `Yield`(svc #1 快捷入口)、`Exit`(svc #2 快捷入口)、`SendMessage`(0)、
//! `ReceiveMessage`(1)、`BlockRead`(7)/`BlockWrite`(8，仅 blktest
//! 的 raw 扇区回环验证使用)、`Exec`(3，execdemo 经 fork 子进程使用)、
//! `GetPid`(21)/`GetPpid`(23)、`WaitPid`(22)、`Brk`(24，仅 brktest
//! 的用户堆增长/收缩验证使用)。禁止 MMIO（用户态无 MMIO 权限）。
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
use useralloc::StaticFreeList;
use userlib::{
    cause_segv, console_read, console_write, create_channel, driver_count, driver_info,
    encode_message, exec, exit, extract_payload_text, get_session, net_diag, pci_count, pci_info,
    session_begin, session_list, wait_pid, wait_pid_flags, WAIT_NOHANG,
};
use zero_abi::cap::{CAP_CHANNEL_CREATE, CAP_POWER, CAP_SECURE_IPC, CAP_SESSION};
use zero_abi::channels::{
    FS_REQ, FS_RESP, LAUNCHD_CMD_REQ, LAUNCHD_CMD_RESP, SECURITY_USER_REQ, SECURITY_USER_RESP,
};
use zero_abi::ipc::{ChannelDesc, Message};
use zero_abi::protocol::fs as fs_proto;
use zero_abi::protocol::fs::vtable as fs_vt;
use zero_abi::protocol::launchd::{CMD_LIST_SERVICES, CMD_RESTART_SERVICE, CMD_STATUS};
use zero_abi::protocol::security::{self as sec_proto, parse_token, CapIssueRequest};
use zero_abi::syscall::SysError;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let msg = b"\nshell panic\n";
    let _ = console_write(msg);
    exit(1);
}

// 用户态可回收 free-list 堆：临时 String/Vec 释放后归还，长期 shell
// 不再因历史 bump allocator 只增不减而最终 OOM。
const SHELL_HEAP_SIZE: usize = 64 * 1024;
#[global_allocator]
static SHELL_ALLOC: StaticFreeList<SHELL_HEAP_SIZE> = StaticFreeList::new();

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

/// forktest 的期望父 pid：fork 前由父进程写入自身 getpid() 结果；
/// fork 使子进程继承该静态变量的逻辑值（当前由 COW 页共享后按需断链），
/// 子进程据此断言 getppid() == 父 getpid() 值（号位 23 端到端）。
static mut FORKTEST_PARENT_PID: u64 = 0;

/// 命令历史：内存态最近 8 条（环形）。单核 shell 独占执行，静态可变安全。
const HISTORY_CAP: usize = 8;
static mut HISTORY: [[u8; 128]; HISTORY_CAP] = [[0; 128]; HISTORY_CAP];
static mut HIST_LEN: [usize; 8] = [0; 8];
static mut HIST_HEAD: usize = 0;
static mut HIST_TOTAL: usize = 0;

/// 登录会话状态（第十三刀）：`login`/`su` 成功后记录当前用户名与会话 id。
/// 会话 id 的权威在内核（security 台账），这里只是 whoami 显示用的缓存。
/// 单核 shell 独占执行，静态可变安全；fork 子进程继承副本（POSIX 语义）。
static mut SESSION_USER: [u8; 16] = [0; 16];
static mut SESSION_USER_LEN: usize = 0;
static mut SESSION_ID: u64 = 0;

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
            println("  process: forktest/waittest/nohangtest/orphantest/waitspec/execdemo/segvdemo/pid/ppid");
            println("  sched/sleep: sleepdemo (号位 25 Sleep(ticks))");
            println("  memory:  brktest");
            println("  storage: fstest/fsdemo/blktest");
            println("  threads: threaddemo/mutextest (futex-backed UserMutex)");
            println("  pkg:      pkg ls [dir] / pkg rename <old> <new>");
            println("  fs ops:  ls <dir>/cat <path>/mkdir <path>");
            println("  security: login/su/whoami/sessions/secdemo");
            println(
                "  system: launchd/drivers/pci/netdiag/pid/ppid/shutdown/reboot/clear/history/echo/whoami/help/exit",
            );
        } else if cmd == b"drivers" {
            drivers_command();
        } else if cmd == b"pci" {
            pci_command();
        } else if cmd == b"netdiag" {
            netdiag_command();
        } else if cmd == b"shutdown" {
            power_command(zero_abi::syscall::POWER_OFF);
        } else if cmd == b"reboot" {
            power_command(zero_abi::syscall::POWER_REBOOT);
        } else if cmd.starts_with(b"echo ") {
            println_bytes(&cmd[5..]);
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
        } else if cmd == b"ppid" {
            // 号位 23：显示当前进程的父 pid。shell 由服务注册表 spawn
            // 路径拉起（parent=None），顶层执行按“无父返回 0”约定显示
            // ppid=0；forktest 的子进程内则显示其真实父进程的 pid。
            match userlib::getppid() {
                Ok(p) => {
                    print("ppid=");
                    print_u64(p);
                    println("");
                }
                Err(e) => {
                    print("ppid: syscall failed (");
                    print_hex(e.code());
                    println(")");
                }
            }
        } else if cmd == b"brktest" {
            // 号位 24 端到端：用户堆 sbrk 增长/写入回读/收缩归位。
            brktest_command();
        } else if cmd == b"forktest" {
            // 端到端 fork 验证：svc #0 / x0=2。
            // 返回值区分父子：父=Ok(child_pid)，子=Ok(0)。
            // 子分支打印后立即 exit，绝不回到主循环——否则两个 shell
            // 会并发抢终端（read_line 双消费者）。[P]/[C] 前缀用于在
            // 并发输出交错时辨识来源行（console_write 无进程级串行化）。
            //
            // 号位 23 端到端：fork 前把父进程自身 pid 写入静态变量；
            // COW fork 让子进程继承同一逻辑内存内容，子进程据此断言
            // getppid() == 父 getpid() 值，断言结果经退出码带回父进程。
            match userlib::getpid() {
                Ok(my_pid) => unsafe { FORKTEST_PARENT_PID = my_pid },
                Err(_) => unsafe { FORKTEST_PARENT_PID = 0 },
            }
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
                    // 号位 23 断言：子的 getppid 必须等于父 fork 前记录的
                    // 自身 pid；失败以非零退出码报告，父进程收尸可见。
                    let expected_ppid = unsafe { FORKTEST_PARENT_PID };
                    let mut ppid_ok = expected_ppid != 0;
                    print("[C] child: ppid via getppid=");
                    match userlib::getppid() {
                        Ok(pp) if pp == expected_ppid => print_u64(pp),
                        Ok(pp) => {
                            print_u64(pp);
                            ppid_ok = false;
                        }
                        Err(e) => {
                            print("syscall failed (");
                            print_hex(e.code());
                            print(")");
                            ppid_ok = false;
                        }
                    }
                    println("");
                    if ppid_ok {
                        println("[C] forktest: child ppid assertion PASS");
                        exit(0); // -> ! ：子进程到此终结，永不返回主循环
                    } else {
                        println("[C] forktest: child ppid assertion FAIL");
                        exit(23); // 非零退出码向父进程暴露断言失败
                    }
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
                            // 号位 23 判定：code=0 即子进程 ppid 断言通过。
                            if code == 0 {
                                println("[P] forktest: PASS (child getppid == parent getpid)");
                            } else {
                                println("[P] forktest: FAIL (child ppid assertion rejected)");
                            }
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
        } else if cmd == b"segvdemo" {
            // 信号位图最小版端到端（第九刀）：fork 出的子进程故意解引用
            // 空指针 → EL0 数据 abort → 内核投递默认动作 SIGSEGV（登记
            // pending_signals 位图）并以 code=-11 走既有 zombie→waitpid
            // 状态机；父进程收集后打印死因。子分支经 cause_segv() 永不
            // 返回，绝不回到主循环（同 forktest：防双 shell 抢终端）。
            match userlib::fork() {
                Ok(0) => {
                    println("[C] segvdemo: child alive, dereferencing NULL");
                    cause_segv(); // -> ! ：地址 0 写入 → SIGSEGV 默认动作终止
                }
                Ok(child_pid) => {
                    print("[P] segvdemo: forked child ");
                    print_u64(child_pid);
                    println("");
                    match userlib::wait_pid(child_pid) {
                        Ok((pid, code)) => {
                            print("collected pid=");
                            print_u64(pid);
                            print(" code=");
                            print_i32(code);
                            if code == -11 {
                                println(" (SIGSEGV)");
                            } else {
                                println("");
                            }
                        }
                        Err(e) => {
                            print("[P] segvdemo: wait failed (");
                            print_hex(e.code());
                            println(")");
                        }
                    }
                }
                Err(e) => {
                    print("[P] segvdemo: fork failed (");
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
                            println(
                                "[P] waitspec: PASS (two precise collects, out-of-order exits)",
                            );
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
        } else if cmd == b"sleepdemo" {
            // Sleep(ticks) 实机验证（号位 25，第十一刀）。见 sleepdemo_command。
            sleepdemo_command();
        } else if cmd == b"fstest" {
            // 端到端文件语义验证（第七刀）：经 launchd list 预检 fsd/
            // blkdrv 在线后，向 FS_REQ 发 open/create → write("ZERO-FSD")
            // → read 回读比对 → close 序列，逐步打印结果。
            fstest_command();
        } else if cmd == b"blktest" || cmd.starts_with(b"blktest ") {
            // raw 块设备端到端验证：号位 7/8 内核直通（绕过 fsd 卷语义）。
            blktest_command(cmd);
        } else if cmd == b"ls" || cmd.starts_with(b"ls ") {
            // 目录树列表（第十二刀）：经 fsd LIST 路径版。
            ls_command(cmd);
        } else if cmd == b"cat" || cmd.starts_with(b"cat ") {
            // 文件内容打印（第十二刀）：OPEN EXISTING → 分块 READ → CLOSE。
            cat_command(cmd);
        } else if cmd == b"mkdir" || cmd.starts_with(b"mkdir ") {
            // 建目录（第十二刀 CMD_MKDIR）。
            mkdir_command(cmd);
        } else if cmd == b"fsdemo" {
            // 目录树端到端验证（第十二刀）。见 fsdemo_command。
            fsdemo_command();
        } else if cmd == b"pkg" || cmd.starts_with(b"pkg ") {
            // 包管理命令面（第十八刀 ZeroPkg 设备内 MVP）。见 pkg_command。
            pkg_command(cmd);
        } else if cmd == b"mutextest" {
            // 线程同步原语验证（号位27/28，第十五刀二期）。见 mutextest_command。
            mutextest_command();
        } else if cmd == b"threaddemo" {
            // 线程模型端到端验证（号位 26，第十五刀）。见 threaddemo_command。
            threaddemo_command();
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
        } else if cmd == b"login" || cmd == b"su" {
            // 第十三刀：登录 / 切换会话（命令链末尾追加，最小化并行
            // 冲突面；help 文案同步补一行）。
            let mode = if cmd == b"login" { "login" } else { "su" };
            login_flow(mode);
        } else if cmd == b"whoami" {
            whoami_command();
        } else if cmd == b"sessions" {
            sessions_command();
        } else if cmd == b"secdemo" {
            // 实机验收（第十三刀）：无权 send 被拒 → securityd 签发 cap
            // → 重发成功 → revoke 再拒 → PASS。
            secdemo_command();
        } else if cmd.len() > 0 {
            print_bytes(b"unknown command: ");
            println_bytes(cmd);
        }
    }
    0
}

/// sleepdemo —— Sleep(ticks) 端到端验证（号位 25，第十一刀）。
///
/// 序列：fork 子进程 → 子调 sleep_ticks(12)，内核 tick 引擎真推进后
/// 唤醒并经陷阱帧回写 elapsed（≥12 即「真睡眠」——Blocked 进程不参与
/// 调度，忙等路径不可能凭空拿到 ≥ 请求值的流逝计数）；父先自睡
/// 5 tick（验证睡眠队列多进程互不干扰），随后 wait 收尸断言 exit 77。
/// 全过打印 PASS。对照 waitspec 的 delay_cycles 忙等：本命令期间 CPU
/// 可让给其他进程，串口活性即为调度器未空转的旁证。
fn sleepdemo_command() {
    let my = userlib::getpid().unwrap_or(9999);
    print("[P] sleepdemo(self pid=");
    print_u64(my);
    println("): forking sleeper child (child sleeps 12 ticks)");
    match userlib::fork() {
        Ok(0) => {
            // 第十七刀🥇诊断：getpid 先行——若能成功而后续 println 静默，
            // 则「COW 断链后首个 console_write」为特殊失败点。
            let cpid = userlib::getpid().unwrap_or(8888);
            print("[C] child alive pid=");
            print_u64(cpid);
            println(", sleeping 12 ticks");
            // 子：睡 12 tick → elapsed 回写 ≥ 12 → exit(77)
            match userlib::sleep_ticks(12) {
                Ok(elapsed) => {
                    print("[C] woke up, elapsed ticks=");
                    print_u64(elapsed);
                    if elapsed >= 12 {
                        println(" (>=12 OK)");
                    } else {
                        println(" (<12 FAIL)");
                    }
                }
                Err(e) => {
                    print("[C] sleep_ticks failed: ");
                    print_i32(e as i32);
                    println("");
                }
            }
            userlib::exit(77);
        }
        Ok(child_pid) => {
            // 父：自睡 5 tick（短于子，先醒），随后以 WNOHANG 轮询+让出
            // 等待收尸——保持就绪队列恒有 Running 进程，避开「全员阻塞
            // 后 idle 轮转」的调度器历史雷区（详见 STATUS 第十一刀披露）。
            match userlib::sleep_ticks(5) {
                Ok(elapsed) => {
                    print("[P] parent slept, elapsed ticks=");
                    print_u64(elapsed);
                    println("");
                }
                Err(e) => {
                    print("[P] parent sleep failed: ");
                    print_i32(e as i32);
                    println("");
                }
            }
            // 阻塞收尸（对照 WNOHANG 轮询：轮询版会让 idle 窗口吞掉
            // 定时器流——见 STATUS 第十一刀「已知问题」披露）。
            let mut pass = false;
            match userlib::wait_pid(child_pid) {
                Ok((pid, code)) => {
                    print("[P] collected pid=");
                    print_u64(pid);
                    print(" code=");
                    print_i32(code);
                    println("");
                    pass = pid == child_pid && code == 77;
                }
                Err(e) => {
                    print("[P] wait failed: ");
                    print_i32(e as i32);
                    println("");
                }
            }
            if pass {
                println("[P] sleepdemo: PASS (sleep/wake + frame writeback)");
            } else {
                println("[P] sleepdemo: FAIL");
            }
        }
        Err(e) => {
            print("[P] sleepdemo: fork failed: ");
            print_i32(e as i32);
            println("");
        }
    }
}

/// brktest —— 用户堆端到端验证（号位 24，第十刀）。
///
/// 序列：sbrk(0) 取初始 break → sbrk(8192) 增长两页（返回旧 break，
/// POSIX 语义）→ 在新堆区写入特征图案并回读校验（证明页真实映射、
/// EL0 可写且内容跨页正确）→ sbrk(-8192) 收缩 → 复查 break 归位。
/// 各阶段打印 break 值；全过打印 PASS。任何一步失败即中止并指明阶段
/// 与错误码，绝不 panic（panic_handler 只是最后防线）。
fn brktest_command() {
    const GROW: i64 = 8192; // 两页

    println("brktest: heap grow/shrink round-trip (syscall 24)");
    // ---- 1) 初始 break ----
    let b0 = match userlib::sbrk(0) {
        Ok(v) => v,
        Err(e) => return print_brk_fail("sbrk(0) query", e),
    };
    print("[1/5] sbrk(0): initial break=0x");
    print_hex(b0 as u64);
    println("");

    // ---- 2) 增长两页：必须返回增长前的旧 break ----
    let grown_old = match userlib::sbrk(GROW) {
        Ok(v) => v,
        Err(e) => return print_brk_fail("sbrk(+8192)", e),
    };
    print("[2/5] sbrk(+8192): old break=0x");
    print_hex(grown_old as u64);
    println("");
    if grown_old != b0 {
        println("brktest: FAIL - sbrk did not return pre-grow break");
        return;
    }

    // ---- 3) 新值复查 + 特征图案写入/回读 ----
    let b1 = match userlib::sbrk(0) {
        Ok(v) => v,
        Err(e) => return print_brk_fail("sbrk(0) after grow", e),
    };
    print("[3/5] after grow break=0x");
    print_hex(b1 as u64);
    println("");
    if b1 != b0 + GROW as usize {
        println("brktest: FAIL - break did not advance by 8192");
        return;
    }
    unsafe {
        let words = GROW as usize / 8;
        let base = b0 as *mut u64;
        for i in 0..words {
            core::ptr::write_volatile(base.add(i), heap_pattern(i));
        }
        for i in 0..words {
            let got = core::ptr::read_volatile(base.add(i));
            if got != heap_pattern(i) {
                print("brktest: FAIL - readback mismatch at offset ");
                print_u64((i * 8) as u64);
                println("");
                return;
            }
        }
    }
    println("      pattern write/readback: MATCH");

    // ---- 4) 收缩两页：必须返回收缩前的旧 break ----
    let shrunk_old = match userlib::sbrk(-GROW) {
        Ok(v) => v,
        Err(e) => return print_brk_fail("sbrk(-8192)", e),
    };
    print("[4/5] sbrk(-8192): old break=0x");
    print_hex(shrunk_old as u64);
    println("");
    if shrunk_old != b1 {
        println("brktest: FAIL - shrink did not report pre-shrink break");
        return;
    }

    // ---- 5) 终态归位 ----
    let b2 = match userlib::sbrk(0) {
        Ok(v) => v,
        Err(e) => return print_brk_fail("sbrk(0) final", e),
    };
    print("[5/5] final break=0x");
    print_hex(b2 as u64);
    println("");
    if b2 != b0 {
        println("brktest: FAIL - break did not return to initial value");
        return;
    }
    println("brktest: PASS - user heap grow/shrink verified end-to-end");
}

/// brktest 堆区特征图案：位置相关的确定性 64 位字。写入与校验共用同一
/// 函数重算期望值（不依赖读缓冲自身——与 blktest fill_block_pattern
/// 同一设计纪律），常数取自 "ZEROHEAP" 的 ASCII 编码。
fn heap_pattern(i: usize) -> u64 {
    (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5A45_524F_4845_4150
}

/// brktest 单步失败统一打印：阶段 + 错误名 + 编码，然后返回。
fn print_brk_fail(step: &str, e: SysError) {
    print("brktest: FAIL at ");
    print(step);
    print(" (");
    print(e.as_str());
    print(" code=0x");
    print_hex(e.code());
    println(")");
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
        HIST_HEAD = (head + 1) % HISTORY_CAP;
        HIST_TOTAL = (HIST_TOTAL + 1).min(HISTORY_CAP);
    }
}

fn print_history() {
    unsafe {
        let total = HIST_TOTAL;
        let head = HIST_HEAD;
        let start = (head + HISTORY_CAP - total) % HISTORY_CAP;
        for k in 0..total {
            let idx = (start + k) % HISTORY_CAP;
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
/// 选址纪律（第32刀 ZFS 默认化后更新）：ZFS 使用整块设备，不再存在
/// “卷外尾段”。zfsd 永久保留最后一个 4KiB 逻辑块给 raw diagnostics；
/// 本命令经 BlockCapacity 动态算出该块首 LBA，显式参数也只能落在同一
/// 保留块内。这样 raw 回环测试不可能覆盖 live ZFS metadata/data。
fn blktest_command(cmd: &[u8]) {
    const SECTOR: usize = 512;
    const SECTORS_PER_ZFS_BLOCK: u64 = 4096 / 512;

    // Knife32 made ZFS consume the whole device, so the historical hard-coded
    // LBA 60000 is no longer a safe "outside the fsd volume" location. zfsd
    // now reserves the final 4KiB logical block exclusively for this raw test.
    let capacity = match userlib::block_capacity_sectors() {
        Ok(v) if v >= SECTORS_PER_ZFS_BLOCK * 2 => v,
        _ => {
            println("blktest: cannot determine a usable block-device capacity");
            return;
        }
    };
    let diagnostic_lba = ((capacity / SECTORS_PER_ZFS_BLOCK) - 1) * SECTORS_PER_ZFS_BLOCK;

    // Developer override is constrained to the same reserved 4KiB block. This
    // keeps the diagnostic useful without allowing an interactive shell command
    // to silently corrupt the live ZFS namespace.
    let lba = if cmd == b"blktest" {
        diagnostic_lba
    } else {
        match parse_u64(&cmd[8..]) {
            Some(v) if v >= diagnostic_lba && v < diagnostic_lba + SECTORS_PER_ZFS_BLOCK => v,
            Some(_) => {
                print("blktest: refused: only reserved diagnostic LBA ");
                print_u64(diagnostic_lba);
                print("..");
                print_u64(diagnostic_lba + SECTORS_PER_ZFS_BLOCK - 1);
                println(" is writable");
                return;
            }
            None => {
                println("usage: blktest [lba-within-final-reserved-4KiB-block]");
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

fn read_line_impl(buf: &mut [u8], echo: bool) -> usize {
    let mut i = 0usize;
    while i < buf.len() {
        let mut c: [u8; 1] = [0];
        match console_read(&mut c) {
            Ok(0) => {
                let _ = userlib::sleep_ticks(1);
                continue;
            }
            Err(SysError::WouldBlock) => {
                // ⚠ 必须 continue：yield 会返回到 match 之后的语句，若不加
                // continue 就会贯穿到 ch=c[0]，把缓冲区残留的 0 当成收到的
                // 字节 —— 缓冲区被 NUL 填满、真实命令永远匹配不上。
                // （旧代码靠 yield_now 的错误 -> ! 标注掩盖了这一逻辑。）
                let _ = userlib::sleep_ticks(1);
                continue;
            }
            Err(_) => return i,
            Ok(_) => {}
        }
        let ch = c[0];
        if ch == b'\n' || ch == b'\r' {
            buf[i] = ch;
            i += 1;
            if !echo {
                let _ = console_write(b"\r\n");
            }
            break;
        } else if ch == 0x7f || ch == 0x08 {
            // backspace
            if i > 0 {
                i -= 1;
                if echo {
                    let _ = console_write(b"\x08 \x08");
                }
            }
        } else {
            buf[i] = ch;
            i += 1;
            if echo {
                let _ = console_write(&c);
            }
        }
    }
    i
}

fn read_line(buf: &mut [u8]) -> usize {
    read_line_impl(buf, true)
}

fn read_line_hidden(buf: &mut [u8]) -> usize {
    read_line_impl(buf, false)
}

fn netdiag_command() {
    let info = match net_diag() {
        Ok(v) => v,
        Err(e) => {
            print("netdiag: unavailable 0x");
            print_hex(e.code());
            println("");
            return;
        }
    };
    print("netdiag: v=");
    print_u64(info.transport_version as u64);
    print(" status=0x");
    print_hex(info.device_status as u64);
    print(" rxq=");
    print_u64(info.rx_queue_size as u64);
    print(" rxpfn=0x");
    print_hex(info.rx_queue_pfn as u64);
    print(" txq=");
    print_u64(info.tx_queue_size as u64);
    print(" txpfn=0x");
    print_hex(info.tx_queue_pfn as u64);
    println("");
    print("netdiag: tx_submit=");
    print_u64(info.tx_submits);
    print(" tx_complete=");
    print_u64(info.tx_completions);
    print(" rx_complete=");
    print_u64(info.rx_completions);
    print(" mac=");
    for i in 0..6 {
        if i != 0 {
            print(":");
        }
        print_hex(info.mac[i] as u64);
    }
    println("");
}

fn pci_command() {
    use zero_abi::driver::{PCI_BAR_64, PCI_BAR_IO, PCI_BAR_PREFETCH};
    let count = match pci_count() {
        Ok(v) => v.min(128),
        Err(e) => {
            print("pci: count failed 0x");
            print_hex(e.code());
            println("");
            return;
        }
    };
    print("pci: count=");
    print_u64(count as u64);
    println("");
    for index in 0..count {
        let Ok(info) = pci_info(index as u32) else {
            continue;
        };
        print("  ");
        print_hex(info.segment as u64);
        print(":");
        print_hex(info.bus as u64);
        print(":");
        print_hex(info.device as u64);
        print(".");
        print_hex(info.function as u64);
        print(" pci=");
        print_hex(info.vendor_id as u64);
        print(":");
        print_hex(info.device_id as u64);
        print(" sub=");
        print_hex(info.subsystem_vendor as u64);
        print(":");
        print_hex(info.subsystem_id as u64);
        print(" class=");
        print_hex(info.class as u64);
        print(":");
        print_hex(info.subclass as u64);
        print(":");
        print_hex(info.prog_if as u64);
        print(" rev=");
        print_hex(info.revision as u64);
        print(" caps=0x");
        print_hex(info.capability_bits);
        print(" virtio_cfg=0x");
        print_hex(info.virtio_cfg_types as u64);
        if info.msix_table_size != 0 {
            print(" msix=");
            print_u64(info.msix_table_size as u64);
            print(" table=BAR");
            print_u64(info.msix_table_bar as u64);
            print("+0x");
            print_hex(info.msix_table_offset as u64);
            print(" pba=BAR");
            print_u64(info.msix_pba_bar as u64);
            print("+0x");
            print_hex(info.msix_pba_offset as u64);
        }
        println("");
        for (bar_index, bar) in info.bars.iter().enumerate() {
            if bar.size == 0 {
                continue;
            }
            print("    BAR");
            print_u64(bar_index as u64);
            print(if bar.flags & PCI_BAR_IO != 0 {
                " IO "
            } else {
                " MEM "
            });
            print("base=0x");
            print_hex(bar.address);
            print(" size=0x");
            print_hex(bar.size);
            if bar.flags & PCI_BAR_64 != 0 {
                print(" 64");
            }
            if bar.flags & PCI_BAR_PREFETCH != 0 {
                print(" prefetch");
            }
            println("");
        }
    }
}

fn drivers_command() {
    let count = match driver_count() {
        Ok(v) => v.min(128),
        Err(e) => {
            print("drivers: count failed 0x");
            print_hex(e.code());
            println("");
            return;
        }
    };
    print("drivers: count=");
    print_u64(count);
    println("");
    for index in 0..count {
        let Ok(info) = driver_info(index as u32) else {
            continue;
        };
        print("  drv");
        print_u64(index);
        print(" kind=");
        print_u64(info.kind as u64);
        if info.pci_id != 0 {
            let vendor = info.pci_id & 0xffff;
            let device = info.pci_id >> 16;
            print(" pci=");
            print_hex(vendor as u64);
            print(":");
            print_hex(device as u64);
            let class = info.pci_class & 0xff;
            let subclass = (info.pci_class >> 8) & 0xff;
            let prog_if = (info.pci_class >> 16) & 0xff;
            let revision = info.pci_class >> 24;
            print(" class=");
            print_hex(class as u64);
            print(":");
            print_hex(subclass as u64);
            print(":");
            print_hex(prog_if as u64);
            print(" rev=");
            print_hex(revision as u64);
        }
        print(" mmio=0x");
        print_hex(info.mmio_base);
        print("+0x");
        print_hex(info.mmio_len);
        print(" irq=");
        print_u64(info.irq as u64);
        println("");
    }
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
// ═══════════════ 第十二刀：目录树命令（ls/cat/mkdir/fsdemo）═══════════════

/// 取命令首个空格后的参数（去首尾空格；无参数返回空切片）。
fn cmd_arg(cmd: &[u8]) -> &[u8] {
    let rest = match cmd.iter().position(|&b| b == b' ') {
        Some(pos) => &cmd[pos + 1..],
        None => b"",
    };
    let mut start = 0usize;
    let mut end = rest.len();
    while start < end && (rest[start] == b' ' || rest[start] == b'\t') {
        start += 1;
    }
    while end > start && (rest[end - 1] == b' ' || rest[end - 1] == b'\t') {
        end -= 1;
    }
    &rest[start..end]
}

/// 构造带路径参数的 fsd 请求：[path NUL][extra?]。
fn path_request(code: u32, path: &[u8], extra: Option<u8>) -> Message {
    let mut request = Message::empty();
    request.code = code;
    let mut pos = 0usize;
    if !path.is_empty() {
        let take = path.len().min(request.payload.len() - 2);
        request.payload[..take].copy_from_slice(&path[..take]);
        pos = take;
    }
    request.payload[pos] = 0; // NUL 收尾
    if let Some(byte) = extra {
        request.payload[pos + 1] = byte;
    }
    request
}

/// ls —— 列目录。`ls` 列根，`ls <dir>` 列子目录；子目录条目自带尾 '/'。
fn ls_command(cmd: &[u8]) {
    let arg = cmd_arg(cmd);
    let dir: &[u8] = if arg.starts_with(b"/") {
        &arg[1..]
    } else {
        arg
    };
    // 嵌套路径直接透传 fsd（空段/点段的权威拒绝在服务端）。
    let request = path_request(fs_vt::CMD_LIST, dir, None);
    print("fs> ");
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    match response.code {
        0 => {
            // payload 为 `name\n` 串；逐行打印
            let mut line_start = 0usize;
            for i in 0..response.payload.len() {
                if response.payload[i] == 0 {
                    break;
                }
                if response.payload[i] == b'\n' {
                    println_bytes(&response.payload[line_start..i]);
                    line_start = i + 1;
                }
            }
            if line_start == 0 && response.payload[0] == 0 {
                println("(empty)");
            } else if line_start < response.payload.len() && response.payload[line_start] != 0 {
                println_bytes(&response.payload[line_start..]);
            }
        }
        _ => print_fs_fail("ls", response.code),
    }
}

/// cat —— 打印文件内容到串口。OPEN(EXISTING) → 循环 READ(≤96B) → CLOSE。
fn cat_command(cmd: &[u8]) {
    let raw = cmd_arg(cmd);
    if raw.is_empty() {
        println("usage: cat <path>");
        return;
    }
    let path: &[u8] = if raw.starts_with(b"/") {
        &raw[1..]
    } else {
        raw
    };
    // open existing
    let request = path_request(fs_vt::CMD_OPEN, path, None);
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    if response.code != 0 {
        print_fs_fail("cat open", response.code);
        return;
    }
    let fd = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    // read loop
    loop {
        let mut request = Message::empty();
        request.code = fs_vt::CMD_READ;
        request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
        request.payload[4..8].copy_from_slice(&96u32.to_le_bytes());
        let Some(response) = fs_exchange(&request) else {
            let _ = send_close(fd);
            return;
        };
        if response.code != 0 {
            let _ = console_write(b"\r\n");
            print_fs_fail("cat read", response.code);
            let _ = send_close(fd);
            return;
        }
        let end = response
            .payload
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(response.payload.len());
        if end == 0 {
            break; // EOF（0 字节回包）
        }
        let _ = console_write(&response.payload[..end]);
        if end < 96 {
            break; // 短读即尾
        }
    }
    let _ = console_write(b"\r\n");
    if !send_close(fd) {
        return;
    }
}

/// mkdir —— 创建目录。
fn mkdir_command(cmd: &[u8]) {
    let raw = cmd_arg(cmd);
    if raw.is_empty() {
        println("usage: mkdir <path>");
        return;
    }
    let path: &[u8] = if raw.starts_with(b"/") {
        &raw[1..]
    } else {
        raw
    };
    let request = path_request(fs_vt::CMD_MKDIR, path, None);
    let Some(response) = fs_exchange(&request) else {
        return;
    };
    if response.code == 0 {
        print("mkdir ");
        print_bytes(path);
        println(": ok");
    } else {
        print_fs_fail("mkdir", response.code);
    }
}

/// fsdemo —— 目录树端到端验证（第十二刀）。
///
/// 序列：mkdir /zfdemo → create+write /zfdemo/note.txt("TREE-OK") →
/// 重开回读比对 → ls /zfdemo 断言含 "note.txt" → mkdir 嵌套 /zfdemo/sub
/// → 在其下 create/读回 /zfdemo/sub/b.txt → unlink 两文件 → rmdir 两目录
/// （先空后父）→ 全过 PASS。任何一步失败即 FAIL 并指明阶段。
fn fsdemo_command() {
    const DIR: &[u8] = b"zfdemo";
    const SUB: &[u8] = b"zfdemo/sub";
    const NOTE: &[u8] = b"zfdemo/note.txt";
    const BFILE: &[u8] = b"zfdemo/sub/b.txt";

    // [1] mkdir 根级目录
    let response = match fs_exchange(&path_request(fs_vt::CMD_MKDIR, DIR, None)) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[1/9] mkdir zfdemo", response.code);
        return;
    }
    println("[1/9] mkdir zfdemo: ok");

    // [2] create + write note.txt
    let mut request = path_request(fs_vt::CMD_OPEN, NOTE, Some(fs_vt::OPEN_CREATE));
    request.code = fs_vt::CMD_OPEN;
    let response = match fs_exchange(&request) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[2/9] create note.txt", response.code);
        return;
    }
    let fd = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    let mark = b"TREE-OK";
    let mut request = Message::empty();
    request.code = fs_vt::CMD_WRITE;
    request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
    request.payload[4..8].copy_from_slice(&(mark.len() as u32).to_le_bytes());
    request.payload[8..8 + mark.len()].copy_from_slice(mark);
    let response = match fs_exchange(&request) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[2/9] write note.txt", response.code);
        return;
    }
    if !send_close(fd) {
        return;
    }
    println("[2/9] write zfdemo/note.txt \"TREE-OK\": ok");

    // [3] reopen + read back + 比对
    let response = match fs_exchange(&path_request(fs_vt::CMD_OPEN, NOTE, None)) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[3/9] reopen note.txt", response.code);
        return;
    }
    let fd = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    let mut request = Message::empty();
    request.code = fs_vt::CMD_READ;
    request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
    request.payload[4..8].copy_from_slice(&(mark.len() as u32).to_le_bytes());
    let response = match fs_exchange(&request) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 || &response.payload[..mark.len()] != mark {
        print_fs_fail("[3/9] readback note.txt", response.code);
        return;
    }
    let _ = send_close(fd);
    println("[3/9] readback \"TREE-OK\": MATCH");

    // [4] ls 目录断言含 note.txt
    let response = match fs_exchange(&path_request(fs_vt::CMD_LIST, DIR, None)) {
        Some(r) => r,
        None => return,
    };
    let text_ok = response.code == 0 && response.payload.windows(8).any(|w| w == b"note.txt");
    if !text_ok {
        print_fs_fail("[4/9] ls zfdemo", response.code);
        return;
    }
    println("[4/9] ls zfdemo contains note.txt: ok");

    // [5] mkdir 嵌套 + 子文件写读
    let response = match fs_exchange(&path_request(fs_vt::CMD_MKDIR, SUB, None)) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[5/9] mkdir zfdemo/sub", response.code);
        return;
    }
    let response = match fs_exchange(&path_request(
        fs_vt::CMD_OPEN,
        BFILE,
        Some(fs_vt::OPEN_CREATE),
    )) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[5/9] create sub/b.txt", response.code);
        return;
    }
    let fd = u32::from_le_bytes(response.payload[0..4].try_into().unwrap_or([0; 4]));
    let mut request = Message::empty();
    request.code = fs_vt::CMD_WRITE;
    request.payload[0..4].copy_from_slice(&fd.to_le_bytes());
    request.payload[4..8].copy_from_slice(&2u32.to_le_bytes());
    request.payload[8..10].copy_from_slice(b"BB");
    let response = match fs_exchange(&request) {
        Some(r) => r,
        None => return,
    };
    if response.code != 0 {
        print_fs_fail("[5/9] write sub/b.txt", response.code);
        return;
    }
    let _ = send_close(fd);
    println("[5/9] nested zfdemo/sub/b.txt write: ok");

    // [6] rmdir 非空目录必须被拒（POSIX 语义）
    let response = match fs_exchange(&path_request(fs_vt::CMD_RMDIR, SUB, None)) {
        Some(r) => r,
        None => return,
    };
    if response.code == 0 {
        println("[6/9] rmdir non-empty zfdemo/sub: FAIL (should be denied)");
        return;
    }
    println("[6/9] rmdir non-empty zfdemo/sub: correctly denied");

    // [7] unlink 两文件
    for (path, step) in [
        (NOTE, "[7/9] unlink note.txt"),
        (BFILE, "[7/9] unlink sub/b.txt"),
    ] {
        let response = match fs_exchange(&path_request(fs_vt::CMD_UNLINK, path, None)) {
            Some(r) => r,
            None => return,
        };
        if response.code != 0 {
            print_fs_fail(step, response.code);
            return;
        }
    }
    println("[7/9] unlink note.txt + sub/b.txt: ok");

    // [8] rmdir 空 sub → 成功；再 rmdir zfdemo → 成功
    for (path, step) in [(SUB, "[8/9] rmdir zfdemo/sub"), (DIR, "[8/9] rmdir zfdemo")] {
        let response = match fs_exchange(&path_request(fs_vt::CMD_RMDIR, path, None)) {
            Some(r) => r,
            None => return,
        };
        if response.code != 0 {
            print_fs_fail(step, response.code);
            return;
        }
    }
    println("[8/9] rmdir empty sub then zfdemo: ok");

    // [9] 复查：目录已消失（LIST 应 NOT_FOUND）
    let response = match fs_exchange(&path_request(fs_vt::CMD_LIST, DIR, None)) {
        Some(r) => r,
        None => return,
    };
    if response.code == 0 {
        println("[9/9] post-rmdir ls: FAIL (still exists)");
        return;
    }
    println("[9/9] post-rmdir ls: gone");
    println("fsdemo: PASS (mkdir/list/unlink/rmdir tree semantics)");
}

// ═══════════════════════════════════════════════════════════════════════
// 第十三刀「安全模型成型」：登录会话与 secdemo 实机验收。
// 全部命令追加在命令链末尾（最小化并行刀冲突面）；协议对齐
// zero_abi::protocol::security（0x230/0x231 通道，编解码共用 abi 纯函数）。
// ═══════════════════════════════════════════════════════════════════════

/// 向 securityd 发一条请求并等待响应（单客户端纪律：请求/响应各占
/// 一条通道，同一时刻只允许一个客户端在途——与 fstest 的 fs_exchange
/// 同一约定）。失败返回 None 并打印提示。
fn sec_exchange(code: u32, payload: &[u8]) -> Option<Message> {
    let message = encode_message(code, payload);
    match userlib::ipc_send(SECURITY_USER_REQ, &message) {
        Ok(_) => {}
        Err(SysError::ChannelUnavailable) => {
            println("securityd: request queue full");
            return None;
        }
        Err(_) => {
            println("securityd: send failed (is securityd online?)");
            return None;
        }
    }
    loop {
        let mut response = Message::empty();
        match userlib::ipc_receive(SECURITY_USER_RESP, &mut response) {
            Ok(_) => return Some(response),
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => {
                println("securityd: receive failed");
                return None;
            }
        }
    }
}

/// 读取一行并去掉 CR/LF 尾。
fn trim_line(buf: &mut [u8], n: usize) -> &[u8] {
    let mut end = n;
    while end > 0 && (buf[end - 1] == b'\r' || buf[end - 1] == b'\n') {
        end -= 1;
    }
    &buf[..end]
}

fn read_line_trimmed(buf: &mut [u8]) -> &[u8] {
    let n = read_line(buf);
    trim_line(buf, n)
}

/// 密码输入不回显；仍支持退格并在 Enter 后换行。
fn read_password(buf: &mut [u8]) -> &[u8] {
    let n = read_line_hidden(buf);
    trim_line(buf, n)
}

/// `login` / `su` 共用流程：
///   ① CMD_USER_VERIFY 校验凭据；
///   ② CMD_CAP_ISSUE 申请一枚本进程名下的 CAP_SESSION 登录令牌；
///   ③ 号位 43 SessionBegin 消费令牌建立会话（su 场景旧会话整体注销，
///     绑定旧会话的能力授予一并失效——跨会话重放防线由内核保证）。
/// 默认账户见 rootfs /etc/users：root/zero（admin）、guest/guest（user）。
fn login_flow(mode: &str) {
    print(mode);
    print(" username: ");
    let mut ubuf = [0u8; 64];
    let user = read_line_trimmed(&mut ubuf);
    print("password: ");
    let mut pbuf = [0u8; 64];
    let password = read_password(&mut pbuf);

    // ---- ① 凭据校验 ----
    let mut payload = [0u8; 128];
    if user.len() + password.len() + 3 > payload.len() {
        println("login: credentials too long");
        return;
    }
    payload[..user.len()].copy_from_slice(user);
    payload[user.len() + 1..user.len() + 1 + password.len()].copy_from_slice(password);
    let Some(resp) = sec_exchange(
        sec_proto::CMD_USER_VERIFY,
        &payload[..user.len() + password.len() + 2],
    ) else {
        return;
    };
    if resp.code != 0 {
        println("login: invalid credentials");
        return;
    }

    // ---- ② 申请登录令牌（CAP_SESSION，一次性消费）----
    let Ok(my_pid) = userlib::getpid() else {
        println("login: getpid failed");
        return;
    };
    let req = CapIssueRequest {
        target_pid: my_pid,
        caps: CAP_SESSION,
        ttl: 0, // 不过期：会话生命周期即凭证有效期（su/退出时注销）
    };
    let mut issue_buf = [0u8; 128];
    if !sec_proto::encode_cap_issue(&mut issue_buf, &req) {
        println("login: encode issue failed");
        return;
    }
    let Some(resp) = sec_exchange(sec_proto::CMD_CAP_ISSUE, &issue_buf) else {
        return;
    };
    if resp.code != 0 {
        println("login: cap issuance denied by securityd");
        return;
    }
    let Some(token) = parse_token(&resp.payload) else {
        println("login: malformed token response");
        return;
    };

    // ---- ③ 建立会话 ----
    match session_begin(token) {
        Ok(sid) => {
            unsafe {
                // 容量取常量而非 &STATIC.len()（避免对 mutable static
                // 建共享引用的新版 lint 告警；HISTORY 旧代码保持原样）。
                const SESSION_USER_CAP: usize = 16;
                let n = user.len().min(SESSION_USER_CAP);
                SESSION_USER[..n].copy_from_slice(&user[..n]);
                SESSION_USER_LEN = n;
                SESSION_ID = sid;
            }
            print(mode);
            print(": welcome ");
            print_bytes(user);
            print(" (session id=");
            print_u64(sid);
            println(")");
            if mode == "su" {
                println("su: old session dissolved (its capability grants revoked)");
            }
        }
        Err(e) => {
            print("login: session_begin failed (");
            print_hex(e.code());
            println(")");
        }
    }
}

/// `whoami`：已登录显示用户名，未登录保持历史输出 "console"。
fn whoami_command() {
    unsafe {
        if SESSION_USER_LEN > 0 {
            println_bytes(&SESSION_USER[..SESSION_USER_LEN]);
        } else {
            println("console");
        }
    }
}

/// `sessions`：列出全部存活会话（号位 45 SessionList）。
fn sessions_command() {
    let mut buf = [0u8; 512];
    match session_list(&mut buf) {
        Ok(n) if n > 0 => {
            // 行集逐行打印（内核写入的是 \n 分隔文本）
            let text = extract_payload_text(&buf[..n]);
            print("sessions:\n");
            for line in text.split('\n') {
                if !line.is_empty() {
                    print("  ");
                    println(line);
                }
            }
        }
        Ok(_) => println("sessions: none"),
        Err(e) => {
            print("sessions: syscall failed (");
            print_hex(e.code());
            println(")");
        }
    }
    // 本进程自己的会话视图（号位 44）
    match get_session() {
        Ok(sid) => {
            print("current session id=");
            println_u64(sid);
        }
        Err(_) => {}
    }
}

fn println_u64(v: u64) {
    print_u64(v);
    println("");
}

/// secdemo —— 受保护通道 + 动态 capability 生命周期。
///
/// 新安全模型下 securityd 读取的是**内核盖章的 sender PID**；只有已登录
/// admin 能签普通能力/撤销令牌。演示因此直接在当前 admin shell 上验证：
///   [1] 无权创建受保护通道 → PermissionDenied
///   [2] admin 为自己申请 CAP_CHANNEL_CREATE|CAP_SECURE_IPC
///   [3] 创建受保护通道成功
///   [4] 持动态能力发送成功
///   [5] 撤销令牌后再次发送 → PermissionDenied
fn power_command(action: u32) {
    let Ok(pid) = userlib::getpid() else {
        println("power: getpid failed");
        return;
    };
    let Some(token) = request_cap(pid, CAP_POWER) else {
        println("power: denied (admin login required)");
        return;
    };
    let label = if action == zero_abi::syscall::POWER_REBOOT {
        "reboot"
    } else {
        "shutdown"
    };
    print("power: requesting ");
    println(label);
    if let Err(e) = userlib::power_control(action) {
        let _ = request_revoke(token);
        print("power: firmware transition failed (");
        print_hex(e.code());
        println(")");
    }
}

fn secdemo_command() {
    const CH: u32 = zero_abi::channels::SECDEMO_CH;
    let desc = ChannelDesc {
        id: CH,
        capacity: 4,
        tx_groups: CAP_SECURE_IPC,
        rx_groups: 0,
    };

    print("[1/5] create protected channel WITHOUT cap: ");
    match create_channel(&desc) {
        Err(SysError::PermissionDenied) => println("denied as expected"),
        Err(e) => {
            print("unexpected error (");
            print_hex(e.code());
            println(")");
            println("secdemo: FAIL at step 1");
            return;
        }
        Ok(()) => {
            println("allowed (unexpected!)");
            println("secdemo: FAIL at step 1");
            return;
        }
    }

    let Ok(my_pid) = userlib::getpid() else {
        println("secdemo: getpid failed");
        return;
    };
    let Some(token) = request_cap(my_pid, CAP_CHANNEL_CREATE | CAP_SECURE_IPC) else {
        println("secdemo: FAIL at step 2 (admin issuance denied)");
        return;
    };
    println("[2/5] securityd issued admin-authorized token");

    print("[3/5] create protected channel WITH cap: ");
    match create_channel(&desc) {
        Ok(()) => println("ok"),
        Err(SysError::ChannelUnavailable) => println("already exists (continuing)"),
        Err(e) => {
            print("failed (");
            print_hex(e.code());
            println(")");
            let _ = request_revoke(token);
            println("secdemo: FAIL at step 3");
            return;
        }
    }

    print("[4/5] send WITH dynamic grant: ");
    let m = encode_message(0x2, b"probe-authorized");
    if userlib::ipc_send(CH, &m).is_err() {
        println("failed");
        let _ = request_revoke(token);
        println("secdemo: FAIL at step 4");
        return;
    }
    println("accepted");

    print("[5/5] revoke then send again: ");
    if !request_revoke(token) {
        println("revoke failed");
        println("secdemo: FAIL at step 5");
        return;
    }
    let m2 = encode_message(0x3, b"probe-revoked");
    match userlib::ipc_send(CH, &m2) {
        Err(SysError::PermissionDenied) => {
            println("denied as expected");
            println("[P] secdemo: PASS - RX/TX policy + dynamic capability lifecycle verified");
        }
        _ => {
            println("NOT denied (FAIL)");
            println("secdemo: FAIL at step 5");
        }
    }
}

/// 向 securityd 请求撤销一枚令牌（CMD_CAP_REVOKE；权威在内核台账）。
fn request_revoke(token: u64) -> bool {
    let mut buf = [0u8; 128];
    if !sec_proto::encode_token(&mut buf, token) {
        return false;
    }
    match sec_exchange(sec_proto::CMD_CAP_REVOKE, &buf) {
        Some(resp) => resp.code == 0,
        None => false,
    }
}

/// 向 securityd 申请为目标 pid 签发 `caps`，成功返回令牌编号。
fn request_cap(target_pid: u64, caps: u32) -> Option<u64> {
    let req = CapIssueRequest {
        target_pid,
        caps,
        ttl: 1_000_000, // 逻辑 tick 计的长有效期；演示结束即显式 revoke
    };
    let mut buf = [0u8; 128];
    if !sec_proto::encode_cap_issue(&mut buf, &req) {
        return None;
    }
    let resp = sec_exchange(sec_proto::CMD_CAP_ISSUE, &buf)?;
    if resp.code != 0 {
        return None;
    }
    parse_token(&resp.payload)
}

// ═══════════════ 第十五刀：线程模型（threaddemo）═══════════════

/// 线程与主程序共享的静态缓冲（同地址空间的直接证据）。
/// 访问一律经 addr_of_mut!，规避 static_mut_refs 警告。
static mut THREAD_SHARED: u64 = 0;

/// 共享写入的特征值（来自 create_thread 的 arg 参数）。
const THREAD_MAGIC_ARG: usize = 0xC0DE_CAFE;

/// 线程入口：写共享区 → 打印 → exit(77)。**不得返回**（x30=0，
/// 返回即 SIGSEGV 终结本线程——ABI 约定见 zero-abi 号位 26 文档）。
extern "C" fn threaddemo_thread_entry(arg: usize) -> ! {
    unsafe {
        core::ptr::addr_of_mut!(THREAD_SHARED).write_volatile(arg as u64);
    }
    let tid = userlib::getpid().unwrap_or(0);
    print("[T] thread tid=");
    print_u64(tid);
    print(" arg=0x");
    print_hex(arg as u64);
    println(" (shared space write done)");
    userlib::exit(77);
}

/// threaddemo —— 线程端到端验证（第十五刀）。
///
/// 序列：sbrk 取 64KiB 线程栈 → 清共享标志 → CreateThread(入口/栈顶/
/// tls=0/arg=MAGIC) → 主线程阻塞 wait_pid(tid) join → 断言退出码 77
/// **且共享缓冲已被线程写入 MAGIC**（证明同地址空间零拷贝共享生效，
/// 区别于 fork 的独立副本）。双断言全过打印 PASS。
fn threaddemo_command() {
    println("[P] threaddemo: allocating 64KiB thread stack via brk");
    let old_break = match userlib::sbrk(65536) {
        Ok(v) => v,
        Err(e) => {
            print("[P] sbrk failed: ");
            print_i32(e as i32);
            println("");
            return;
        }
    };
    let stack_top = (old_break + 65536 + 0xfff) & !0xfff; // 页对齐栈顶

    unsafe {
        core::ptr::addr_of_mut!(THREAD_SHARED).write_volatile(0);
    }

    let my = userlib::getpid().unwrap_or(0);
    print("[P] self pid=");
    print_u64(my);
    println(", creating thread");
    let tid = match unsafe {
        userlib::create_thread(
            threaddemo_thread_entry as *const () as usize,
            stack_top,
            0, // tls：本演示不用 TLS
            THREAD_MAGIC_ARG,
        )
    } {
        Ok(t) => t,
        Err(e) => {
            print("[P] create_thread failed: ");
            print_i32(e as i32);
            println("");
            return;
        }
    };
    print("[P] tid=");
    print_u64(tid);
    println("");

    // join：阻塞收尸（tid 是真 pid，WaitPid 语义原样复用）
    let mut pass = false;
    match userlib::wait_pid(tid) {
        Ok((pid, code)) => {
            print("[P] joined tid=");
            print_u64(pid);
            print(" code=");
            print_i32(code);
            println("");
            pass = pid == tid && code == 77;
        }
        Err(e) => {
            print("[P] wait failed: ");
            print_i32(e as i32);
            println("");
        }
    }
    let shared = unsafe { core::ptr::addr_of!(THREAD_SHARED).read_volatile() };
    if shared != THREAD_MAGIC_ARG as u64 {
        print("[P] shared buffer mismatch: 0x");
        print_hex(shared);
        println("");
        pass = false;
    } else {
        println("[P] shared buffer carries thread write: ok");
    }

    if pass {
        println("threaddemo: PASS (CreateThread + shared space + join)");
    } else {
        println("threaddemo: FAIL");
    }
}

// ═══════════════ 第十五刀二期：mutextest ═══════════════════════

/// 共享计数器与门闩（线程组共享地址空间的直接受益者）。
static MUTEX_COUNT: userlib::UserMutex = userlib::UserMutex::new();
static mut MUTEX_COUNTER: u64 = 0;
const MUTEX_ITERS: u64 = 500;

/// 线程入口：持锁自增 N 次。arg 用作线程序号（打印区分）。
extern "C" fn mutextest_entry(seq: usize) -> ! {
    for _ in 0..MUTEX_ITERS {
        MUTEX_COUNT.lock();
        unsafe {
            core::ptr::addr_of_mut!(MUTEX_COUNTER)
                .write_volatile(core::ptr::addr_of!(MUTEX_COUNTER).read_volatile() + 1);
        }
        MUTEX_COUNT.unlock();
    }
    let tid = userlib::getpid().unwrap_or(0);
    print("[T] worker ");
    print_u64(seq as u64);
    print(" tid=");
    print_u64(tid);
    println(" done");
    userlib::exit(0);
}

/// mutextest —— 三线程互斥计数验证（号位 26+27/28 组合拳）。
///
/// 主线程创建 3 个工作线程，各自经 UserMutex（快路径 CAS / 慢路径
/// FutexWait-Wake）对共享计数器自增 500 次；全部 join 后断言总数恰为
/// 1500。任何竞态/丢唤醒都会表现为计数偏差 ⇒ FAIL。
fn mutextest_command() {
    // sbrk 取 3 份线程栈（各 32KiB）
    let old = match userlib::sbrk(3 * 32768) {
        Ok(v) => v,
        Err(e) => {
            print("[P] sbrk failed: ");
            print_i32(e as i32);
            println("");
            return;
        }
    };
    unsafe {
        core::ptr::addr_of_mut!(MUTEX_COUNTER).write_volatile(0);
    }

    let mut tids = [0u64; 3];
    for seq in 0..3usize {
        let stack_top = (old + (seq + 1) * 32768 + 0xfff) & !0xfff;
        match unsafe {
            userlib::create_thread(mutextest_entry as *const () as usize, stack_top, 0, seq)
        } {
            Ok(t) => tids[seq] = t,
            Err(e) => {
                print("[P] create_thread failed: ");
                print_i32(e as i32);
                println("");
                return;
            }
        }
    }
    println("[P] 3 workers created (each +500 through UserMutex)");

    let mut pass = true;
    for seq in 0..3usize {
        match userlib::wait_pid(tids[seq]) {
            Ok((pid, code)) => {
                if pid != tids[seq] || code != 0 {
                    pass = false;
                    print("[P] join mismatch pid=");
                    print_u64(pid);
                    print(" code=");
                    print_i32(code);
                    println("");
                }
            }
            Err(e) => {
                print("[P] join failed: ");
                print_i32(e as i32);
                println("");
                pass = false;
            }
        }
    }
    let total = unsafe { core::ptr::addr_of!(MUTEX_COUNTER).read_volatile() };
    print("[P] counter=");
    print_u64(total);
    println("");
    if pass && total == 3 * MUTEX_ITERS {
        println("mutextest: PASS (futex-backed mutex, exact count)");
    } else {
        println("mutextest: FAIL");
    }
}

// ═══════════════ 第十八刀：ZeroPkg 设备内命令面（MVP）══════════════

/// pkg —— 包管理入口（MVP）。
/// `pkg ls [dir]`   列目录（默认 /Applications，安装目标区）
/// `pkg rename A B` 同卷原子改名（安装事务的提交动作）
/// 完整 install 流（临时名写入→哈希校验→rename 上线）待 WS-B 后续，
/// 本命令面先行打通 fsd 树语义的管理通路。
fn pkg_command(cmd: &[u8]) {
    let arg = cmd_arg(cmd);
    if arg == b"ls" || arg.starts_with(b"ls ") {
        let dir = if arg.len() > 2 {
            &arg[3..]
        } else {
            b"/Applications"
        };
        let dir = if dir.starts_with(b"/") {
            &dir[1..]
        } else {
            dir
        };
        let request = path_request(fs_vt::CMD_LIST, dir, None);
        print("pkg> ");
        let Some(response) = fs_exchange(&request) else {
            return;
        };
        match response.code {
            0 => {
                let mut line_start = 0usize;
                for i in 0..response.payload.len() {
                    if response.payload[i] == 0 {
                        break;
                    }
                    if response.payload[i] == b'\n' {
                        println_bytes(&response.payload[line_start..i]);
                        line_start = i + 1;
                    }
                }
            }
            _ => print_fs_fail("pkg ls", response.code),
        }
    } else if arg.starts_with(b"rename ") {
        // rename <old> <new>
        let rest = &arg[7..];
        let sp = match rest.iter().position(|&b| b == b' ') {
            Some(p) => p,
            None => {
                println("usage: pkg rename <old> <new>");
                return;
            }
        };
        let old = &rest[..sp];
        let mut ns = sp + 1;
        while ns < rest.len() && (rest[ns] == b' ' || rest[ns] == b'\t') {
            ns += 1;
        }
        let new = &rest[ns..];
        if old.is_empty() || new.is_empty() {
            println("usage: pkg rename <old> <new>");
            return;
        }
        fn strip<'a>(p: &[u8], out: &'a mut [u8; 64]) -> &'a [u8] {
            let body = if p.first() == Some(&b'/') { &p[1..] } else { p };
            let take = body.len().min(out.len());
            out[..take].copy_from_slice(&body[..take]);
            &out[..take]
        }
        let mut o_buf = [0u8; 64];
        let mut n_buf = [0u8; 64];
        let o = strip(old, &mut o_buf);
        let n = strip(new, &mut n_buf);
        let mut request = Message::empty();
        request.code = fs_vt::CMD_RENAME;
        let mut pos = 0usize;
        for part in [&o[..], &[0u8][..], &n[..], &[0u8][..]] {
            if pos + part.len() > request.payload.len() {
                println("pkg rename: paths too long");
                return;
            }
            request.payload[pos..pos + part.len()].copy_from_slice(part);
            pos += part.len();
        }
        let Some(response) = fs_exchange(&request) else {
            return;
        };
        match response.code {
            0 => {
                print("pkg rename ");
                print_bytes(&o);
                print(" -> ");
                print_bytes(&n);
                println(": ok");
            }
            _ => print_fs_fail("pkg rename", response.code),
        }
    } else {
        println("usage: pkg ls [dir] | pkg rename <old> <new>");
    }
}
