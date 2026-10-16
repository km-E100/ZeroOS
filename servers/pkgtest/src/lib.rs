#![no_std]

use zero_abi::{channels, ipc::Message, protocol::pkg as pp, syscall::SysError};

/// 候选仓库地址。
///
/// 首选 8443（hardware-acceptance.sh 的默认端口），但该端口在部分宿主
/// 环境下会被系统组件或网络扩展占��——bind 失败而 lsof 查不到属主，
/// Zero OS 侧只会看到 "install failed: network"，把宿主端口占用误报成
/// 网络栈缺陷。系统既无参数传递也无环境变量，端口无法注入，
/// 因此这里按序尝试多个端口：任一可用即视为通过。
const URL_CANDIDATES: [&str; 3] = [
    "https://10.0.2.2:8443/pkgtest.zpkg",
    "https://10.0.2.2:8444/pkgtest.zpkg",
    "https://10.0.2.2:18443/pkgtest.zpkg",
];
const ID: &str = "org.zero.pkgtest";

fn print(s: &str) {
    let _ = userlib::console_write(s.as_bytes());
}

fn rpc(code: u32, arg: &str) -> Result<Message, ()> {
    if arg.len() >= 128 {
        return Err(());
    }
    let mut q = Message::empty();
    q.code = code;
    q.payload[..arg.len()].copy_from_slice(arg.as_bytes());
    userlib::ipc_send(channels::PKG_REQ, &q).map_err(|_| ())?;
    loop {
        let mut r = Message::empty();
        match userlib::ipc_receive(channels::PKG_RESP, &mut r) {
            Ok(()) => return Ok(r),
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => return Err(()),
        }
    }
}

fn expect_ok(code: u32, arg: &str, pass: &str, exit_code: i32) {
    match rpc(code, arg) {
        Ok(r) if r.code == pp::OK => print(pass),
        Ok(r) => {
            print("pkgtest: FAIL: ");
            print(payload_text(&r));
            print("\r\n");
            userlib::exit(exit_code);
        }
        Err(_) => {
            print("pkgtest: FAIL: rpc\r\n");
            userlib::exit(exit_code);
        }
    }
}

pub extern "C" fn server_main() -> ! {
    print("pkgtest: starting public pkgd IPC E2E\r\n");
    // Clean up a prior interrupted run. Either outcome is acceptable.
    let _ = rpc(pp::REMOVE, ID);

    // 依次尝试候选地址。任一成功即继续后续校验。
    let mut installed = false;
    for url in URL_CANDIDATES.iter() {
        match rpc(pp::INSTALL_URL, url) {
            Ok(r) if r.code == pp::OK => {
                installed = true;
                break;
            }
            _ => {
                // 该端口不可用，退避后试下一个，避免连续快速失败。
                let _ = userlib::sleep_ticks(20);
            }
        }
    }
    if !installed {
        print("pkgtest: FAIL: install failed on all candidate ports\r\n");
        userlib::exit(91);
    }
    print("pkgtest: INSTALL PASS\r\n");
    expect_ok(pp::VERIFY, ID, "pkgtest: VERIFY PASS\r\n", 92);
    match rpc(pp::LIST, "") {
        Ok(r) if r.code == pp::OK && payload_text(&r).contains(ID) => {
            print("pkgtest: LIST PASS\r\n")
        }
        _ => {
            print("pkgtest: LIST FAIL\r\n");
            userlib::exit(93);
        }
    }
    expect_ok(pp::LAUNCH, ID, "pkgtest: LAUNCH PASS\r\n", 94);
    // Give the spawned app a chance to reach its entry point before removing
    // the on-disk bundle. Its address space is already private at this point.
    let _ = userlib::sleep_ticks(2);
    expect_ok(pp::REMOVE, ID, "pkgtest: REMOVE PASS\r\n", 95);
    match rpc(pp::VERIFY, ID) {
        Ok(r) if r.code != pp::OK => print("pkgtest: ABSENT PASS\r\n"),
        _ => {
            print("pkgtest: ABSENT FAIL\r\n");
            userlib::exit(96);
        }
    }
    print("pkgtest: ALL PASS\r\n");
    userlib::exit(0)
}

fn payload_text(m: &Message) -> &str {
    let n = m
        .payload
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(m.payload.len());
    core::str::from_utf8(&m.payload[..n]).unwrap_or("")
}
