#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
static VALUE: u64 = 0x1122_3344_5566_7788;
#[cfg(target_os = "none")]
struct PtrHolder(*const u64);
#[cfg(target_os = "none")]
unsafe impl Sync for PtrHolder {}
#[cfg(target_os = "none")]
#[used]
static PTR: PtrHolder = PtrHolder(&VALUE as *const u64);
#[cfg(target_os = "none")]
fn hex(mut v: usize, out: &mut [u8; 16]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for i in (0..16).rev() {
        out[i] = H[v & 15];
        v >>= 4
    }
}
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut a = [0u8; 16];
    hex(&VALUE as *const u64 as usize, &mut a);
    let _ = userlib::console_write(b"pietest: addr=0x");
    let _ = userlib::console_write(&a);
    let _ = userlib::console_write(b"\r\n");
    let p = unsafe { core::ptr::read_volatile(&PTR.0) };
    if unsafe { *p } != 0x1122_3344_5566_7788 {
        let _ = userlib::console_write(b"pietest: RELOC FAIL\r\n");
        userlib::exit(88)
    }
    let _ = userlib::console_write(b"pietest: RELOC PASS\r\n");
    userlib::exit(0)
}
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    userlib::exit(89)
}
#[cfg(not(target_os = "none"))]
fn main() {}
