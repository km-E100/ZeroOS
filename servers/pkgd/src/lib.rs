#![no_std]
use zero_abi::{channels, ipc::Message, protocol::pkg as pp, syscall::SysError};
fn text(p: &[u8]) -> &str {
    let n = p.iter().position(|&b| b == 0).unwrap_or(p.len());
    core::str::from_utf8(&p[..n]).unwrap_or("")
}
fn respond(target: u64, code: u32, msg: &str) {
    let mut r = Message::empty();
    r.code = code;
    let n = msg.len().min(127);
    r.payload[..n].copy_from_slice(&msg.as_bytes()[..n]);
    let _ = userlib::ipc_send_to(channels::PKG_RESP, target, &r);
}
pub extern "C" fn server_main() -> ! {
    let _ = userlib::console_write(b"Zero OS pkgd online\r\n");
    loop {
        let mut q = Message::empty();
        match userlib::ipc_receive_from(channels::PKG_REQ, &mut q) {
            Ok(sender) => handle(sender, &q),
            Err(SysError::WouldBlock) => userlib::yield_now(),
            Err(_) => userlib::yield_now(),
        }
    }
}
fn handle(sender: u64, q: &Message) {
    let arg = text(&q.payload);
    match q.code {
        pp::INSTALL_URL => match libpkg::install_url(arg) {
            Ok(m) => {
                let mut s = heapless_fmt::Buf::<128>::new();
                s.push("installed ");
                s.push(&m.identifier);
                s.push(" ");
                s.push(&m.version);
                respond(sender, pp::OK, s.as_str())
            }
            Err(e) => {
                let mut s = heapless_fmt::Buf::<128>::new();
                s.push("install failed: ");
                s.push(e.as_str());
                respond(sender, pp::ERR, s.as_str())
            }
        },
        pp::REMOVE => match libpkg::remove(arg) {
            Ok(()) => respond(sender, pp::OK, "removed"),
            Err(e) => {
                let mut s = heapless_fmt::Buf::<128>::new();
                s.push("remove failed: ");
                s.push(e.as_str());
                respond(sender, pp::ERR, s.as_str())
            }
        },
        pp::VERIFY => match libpkg::verify(arg) {
            Ok(true) => respond(sender, pp::OK, "verified"),
            Ok(false) => respond(sender, pp::ERR, "hash mismatch"),
            Err(e) => {
                let mut s = heapless_fmt::Buf::<128>::new();
                s.push("verify failed: ");
                s.push(e.as_str());
                respond(sender, pp::ERR, s.as_str())
            }
        },
        pp::LAUNCH => match libpkg::launch(arg) {
            Ok(pid) => {
                let mut s = heapless_fmt::Buf::<128>::new();
                s.push("launched pid=");
                s.push_u64(pid);
                respond(sender, pp::OK, s.as_str())
            }
            Err(_) => respond(sender, pp::ERR, "launch failed"),
        },
        pp::LIST => {
            let mut out = [0u8; 127];
            match libpkg::list(&mut out) {
                Ok(n) => respond(
                    sender,
                    pp::OK,
                    core::str::from_utf8(&out[..n]).unwrap_or(""),
                ),
                Err(_) => respond(sender, pp::ERR, "list failed"),
            }
        }
        _ => respond(sender, pp::ERR, "unknown pkg command"),
    }
}
mod heapless_fmt {
    pub struct Buf<const N: usize> {
        b: [u8; N],
        n: usize,
    }
    impl<const N: usize> Buf<N> {
        pub const fn new() -> Self {
            Self { b: [0; N], n: 0 }
        }
        pub fn push(&mut self, s: &str) {
            let k = (N - self.n).min(s.len());
            self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
            self.n += k
        }
        pub fn push_u64(&mut self, mut v: u64) {
            if v == 0 {
                self.push("0");
                return;
            }
            let mut d = [0u8; 20];
            let mut i = 20;
            while v > 0 {
                i -= 1;
                d[i] = b'0' + (v % 10) as u8;
                v /= 10
            }
            self.push(core::str::from_utf8(&d[i..]).unwrap())
        }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(&self.b[..self.n]).unwrap_or("")
        }
    }
}
