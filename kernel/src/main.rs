#![no_std]
#![no_main]

extern crate zero_microkernel;

use core::arch::global_asm;

global_asm!(include_str!("../../boot/boot.S"));

mod drivers;
mod rootfs;

#[no_mangle]
pub extern "C" fn __zero_kernel_marker__() {}
