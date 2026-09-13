use alloc::{boxed::Box, vec::Vec};
use core::ffi::c_void;
use core::time::Duration;
use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::proto::pi::mp::MpServices;
use uefi::proto::unsafe_protocol;
use uefi::table::Runtime;
use zero_abi::boot::{RootFsEntry, RootFsImage};

/// 内核镜像 `.rodata.boot` 中的内存占位符号名（见 boot/boot.S）。
/// bootloader 在退出 Boot Services 前把真实内存量写回该位置，
/// 使内核拿到的 `BootInfo.memory_bytes` 反映实际硬件配置。
const KERNEL_MEMORY_SYMBOL: &str = "__zero_memory_bytes";

/// ACPI 静态表支持（立项 docs/acpi_static_plan.md · WS-A）：
/// 从 UEFI System Table 的 config 数组抓 ACPI 2.0+ RSDP，补丁进内核
/// 符号 `__zero_rsdp_phys`（0 = 未找到，内核回退硬编码探测路径）。
const KERNEL_RSDP_SYMBOL: &str = "__zero_rsdp_phys";

/// Early platform contract. These slots are patched before ExitBootServices so
/// kernel code can decide whether board-specific MMIO is safe before ACPI/PCI
/// discovery is available. Unknown firmware is deliberately fail-safe.
const KERNEL_PLATFORM_KIND_SYMBOL: &str = "__zero_platform_kind";
const KERNEL_EARLY_UART_BASE_SYMBOL: &str = "__zero_early_uart_base";
const KERNEL_PCI_IO_SEGMENT_SYMBOL: &str = "__zero_pci_io_segment";
const KERNEL_PCI_IO_BUS_BASE_SYMBOL: &str = "__zero_pci_io_bus_base";
const KERNEL_PCI_IO_HOST_BASE_SYMBOL: &str = "__zero_pci_io_host_base";
const KERNEL_PCI_IO_LEN_SYMBOL: &str = "__zero_pci_io_len";
const KERNEL_BOOT_CPU_COUNT_SYMBOL: &str = "__zero_boot_cpu_count";
const KERNEL_BOOT_CPU_MPIDRS_SYMBOL: &str = "__zero_boot_cpu_mpidrs";
const BOOT_CPU_CAPACITY: usize = 4;
const MPIDR_AFFINITY_MASK: u64 = 0x0000_00ff_00ff_ffff;
const PLATFORM_UNKNOWN: u64 = 0;
const PLATFORM_QEMU_VIRT: u64 = 1;
const PLATFORM_PARALLELS_ARM: u64 = 2;
const QEMU_VIRT_PL011_BASE: u64 = 0x0900_0000;

const KERNEL_ROOTFS_IMAGE_SYMBOL: &str = "__zero_rootfs_image";

/// Minimal ABI view of EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL. Only Configuration()
/// and SegmentNumber are used; pointer-sized placeholders preserve the exact
/// UEFI structure layout for the preceding callbacks/access pairs.
#[repr(C)]
#[unsafe_protocol("2f707ebb-4a1a-11d4-9a38-0090273fc14d")]
struct PciRootBridgeIo {
    parent_handle: *mut c_void,
    poll_mem: usize,
    poll_io: usize,
    mem_access: [usize; 2],
    io_access: [usize; 2],
    pci_access: [usize; 2],
    copy_mem: usize,
    map: usize,
    unmap: usize,
    allocate_buffer: usize,
    free_buffer: usize,
    flush: usize,
    get_attributes: usize,
    set_attributes: usize,
    configuration:
        extern "efiapi" fn(this: *mut PciRootBridgeIo, resources: *mut *mut c_void) -> Status,
    segment_number: u32,
}

#[derive(Copy, Clone, Debug)]
struct PciIoWindow {
    segment: u16,
    bus_base: u64,
    host_base: u64,
    len: u64,
}

fn read_unaligned_u16(p: *const u8) -> u16 {
    u16::from_le(unsafe { core::ptr::read_unaligned(p.cast::<u16>()) })
}

fn read_unaligned_u64(p: *const u8) -> u64 {
    u64::from_le(unsafe { core::ptr::read_unaligned(p.cast::<u64>()) })
}

/// Capture the first usable PCI I/O window from UEFI's root-bridge protocol.
/// QWORD descriptors report host AddressRangeMin plus a translation offset that
/// converts host -> PCI bus address; therefore bus_base = host_base + xlate.
fn collect_pci_io_window(st: &SystemTable<Boot>) -> Option<PciIoWindow> {
    const QWORD_ADDRESS_SPACE: u8 = 0x8a;
    const END_TAG: u8 = 0x79;
    const RESOURCE_IO: u8 = 1;
    let bs = st.boot_services();
    let handles = bs.find_handles::<PciRootBridgeIo>().ok()?;
    for handle in handles {
        let Ok(rb) = bs.open_protocol_exclusive::<PciRootBridgeIo>(handle) else {
            continue;
        };
        let mut resources: *mut c_void = core::ptr::null_mut();
        let this = (&*rb) as *const PciRootBridgeIo as *mut PciRootBridgeIo;
        let status = (rb.configuration)(this, &mut resources);
        if status.is_error() || resources.is_null() {
            continue;
        }
        let segment = rb.segment_number as u16;
        let mut p = resources.cast::<u8>();
        for _ in 0..32 {
            let tag = unsafe { p.read() };
            if tag == END_TAG {
                break;
            }
            if tag != QWORD_ADDRESS_SPACE {
                log_warn!(
                    "PCI root bridge seg={} unexpected resource tag=0x{:02x}",
                    segment,
                    tag
                );
                break;
            }
            let body_len = read_unaligned_u16(unsafe { p.add(1) }) as usize;
            let total_len = body_len.checked_add(3)?;
            if body_len < 0x2b {
                break;
            }
            let resource_type = unsafe { p.add(3).read() };
            if resource_type == RESOURCE_IO {
                let host_base = read_unaligned_u64(unsafe { p.add(0x0e) });
                let host_max = read_unaligned_u64(unsafe { p.add(0x16) });
                let xlate = read_unaligned_u64(unsafe { p.add(0x1e) });
                let len = read_unaligned_u64(unsafe { p.add(0x26) });
                if len != 0 {
                    let bus_base = host_base.wrapping_add(xlate);
                    log_info!(
                        "PCI root IO: seg={} host=[0x{:x},0x{:x}] bus_base=0x{:x} xlate=0x{:x} len=0x{:x}",
                        segment,
                        host_base,
                        host_max,
                        bus_base,
                        xlate,
                        len
                    );
                    return Some(PciIoWindow {
                        segment,
                        bus_base,
                        host_base,
                        len,
                    });
                }
            }
            p = unsafe { p.add(total_len) };
        }
    }
    log_info!("PCI root IO: no usable UEFI I/O window");
    None
}

fn patch_kernel_pci_io_window(
    kernel: &crate::kernel_loader::KernelImage,
    window: Option<PciIoWindow>,
) {
    let w = window.unwrap_or(PciIoWindow {
        segment: 0,
        bus_base: 0,
        host_base: 0,
        len: 0,
    });
    let _ = patch_u64_symbol(kernel, KERNEL_PCI_IO_SEGMENT_SYMBOL, w.segment as u64);
    let _ = patch_u64_symbol(kernel, KERNEL_PCI_IO_BUS_BASE_SYMBOL, w.bus_base);
    let _ = patch_u64_symbol(kernel, KERNEL_PCI_IO_HOST_BASE_SYMBOL, w.host_base);
    let _ = patch_u64_symbol(kernel, KERNEL_PCI_IO_LEN_SYMBOL, w.len);
}

fn take_u32(bytes: &[u8], off: &mut usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let v = u32::from_le_bytes(bytes.get(*off..end)?.try_into().ok()?);
    *off = end;
    Some(v)
}

/// Parse xtask's ZEROFSB bundle in place. RootFsEntry path/data pointers point
/// directly into the loader-owned bundle Vec; no second copy of service ELFs is
/// made. The Vec lives across the noreturn kernel jump, and the boot memory-map
/// sink excludes its LoaderData pages from the kernel allocator.
fn build_bootfs_entries(bundle: &[u8]) -> Result<Box<[RootFsEntry]>, Status> {
    if bundle.len() < 12 || &bundle[..8] != b"ZEROFSB\0" {
        return Err(Status::LOAD_ERROR);
    }
    let mut off = 8usize;
    let count = take_u32(bundle, &mut off).ok_or(Status::LOAD_ERROR)? as usize;
    if count == 0 || count > 4096 {
        return Err(Status::LOAD_ERROR);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let path_len = take_u32(bundle, &mut off).ok_or(Status::LOAD_ERROR)? as usize;
        if path_len == 0 || path_len > 4096 {
            return Err(Status::LOAD_ERROR);
        }
        let path_end = off.checked_add(path_len).ok_or(Status::LOAD_ERROR)?;
        let path = bundle.get(off..path_end).ok_or(Status::LOAD_ERROR)?;
        if path.first() != Some(&b'/') || core::str::from_utf8(path).is_err() {
            return Err(Status::LOAD_ERROR);
        }
        off = path_end;
        let data_len = take_u32(bundle, &mut off).ok_or(Status::LOAD_ERROR)? as usize;
        let data_end = off.checked_add(data_len).ok_or(Status::LOAD_ERROR)?;
        let data = bundle.get(off..data_end).ok_or(Status::LOAD_ERROR)?;
        off = data_end;
        entries.push(RootFsEntry {
            path_ptr: path.as_ptr(),
            path_len,
            data_ptr: data.as_ptr(),
            data_len,
        });
    }
    if off != bundle.len() {
        log_warn!("bootfs bundle has {} trailing bytes", bundle.len() - off);
    }
    Ok(entries.into_boxed_slice())
}

fn patch_kernel_rootfs(
    kernel: &crate::kernel_loader::KernelImage,
    bundle: Option<&Vec<u8>>,
) -> Result<(), Status> {
    let Some(addr) = kernel.segments.symbol_address(KERNEL_ROOTFS_IMAGE_SYMBOL) else {
        log_error!("kernel rootfs image symbol missing");
        return Err(Status::LOAD_ERROR);
    };
    let Some(bundle) = bundle else {
        log_error!("bootfs bundle was not loaded");
        return Err(Status::NOT_FOUND);
    };
    let entries = build_bootfs_entries(bundle)?;
    let count = entries.len();
    let ptr = entries.as_ptr();
    // Intentional leak: this is boot handoff memory and the kernel owns the
    // referenced pages for the remainder of the boot. They are excluded by the
    // EFI memory-map snapshot rather than returned to the firmware allocator.
    core::mem::forget(entries);
    unsafe {
        core::ptr::write_volatile(addr as *mut RootFsImage, RootFsImage::new(ptr, count));
    }
    log_info!("bootfs handoff: {} entries @0x{:x}", count, ptr as usize);
    Ok(())
}

use uefi::table::cfg::ACPI2_GUID;

const FB_SYMBOLS: [(&str, usize); 6] = [
    ("__zero_fb_base", 0),
    ("__zero_fb_size", 1),
    ("__zero_fb_width", 2),
    ("__zero_fb_height", 3),
    ("__zero_fb_stride", 4),
    ("__zero_fb_format", 5),
];

#[derive(Copy, Clone, Debug, Default)]
struct FramebufferInfo {
    base: u64,
    size: u64,
    width: u64,
    height: u64,
    stride: u64,
    format: u64,
}

fn capture_framebuffer(st: &SystemTable<Boot>) -> Option<FramebufferInfo> {
    let bs = st.boot_services();
    let handle = bs.get_handle_for_protocol::<GraphicsOutput>().ok()?;
    let mut gop = bs.open_protocol_exclusive::<GraphicsOutput>(handle).ok()?;
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let format = match info.pixel_format() {
        PixelFormat::Rgb => 1,
        PixelFormat::Bgr => 2,
        // Bitmask can be described later with channel masks; BltOnly has no
        // persistent framebuffer pointer. Both deliberately disable handoff.
        PixelFormat::Bitmask | PixelFormat::BltOnly => return None,
    };
    let mut fb = gop.frame_buffer();
    Some(FramebufferInfo {
        base: fb.as_mut_ptr() as usize as u64,
        size: fb.size() as u64,
        width: width as u64,
        height: height as u64,
        stride: info.stride() as u64,
        format,
    })
}

fn patch_kernel_framebuffer(
    kernel: &crate::kernel_loader::KernelImage,
    fb: Option<FramebufferInfo>,
) {
    let fb = fb.unwrap_or_default();
    let values = [fb.base, fb.size, fb.width, fb.height, fb.stride, fb.format];
    for ((symbol, index), value) in FB_SYMBOLS.iter().zip(values) {
        if let Some(addr) = kernel.segments.symbol_address(symbol) {
            unsafe { core::ptr::write_volatile(addr as *mut u64, value) };
        } else {
            log_warn!("kernel framebuffer symbol `{}` missing", symbol);
        }
        let _ = index;
    }
    if fb.base != 0 {
        log_info!(
            "GOP framebuffer: base=0x{:x} size={} {}x{} stride={} format={}",
            fb.base,
            fb.size,
            fb.width,
            fb.height,
            fb.stride,
            fb.format
        );
    } else {
        log_warn!("no directly accessible GOP framebuffer; graphical console disabled");
    }
}

fn find_rsdp_phys(st: &SystemTable<Boot>) -> Option<u64> {
    for entry in st.config_table() {
        if entry.guid == ACPI2_GUID {
            return Some(entry.address as usize as u64);
        }
    }
    None
}

fn patch_kernel_rsdp(kernel: &crate::kernel_loader::KernelImage, rsdp: Option<u64>) {
    let Some(addr) = kernel.segments.symbol_address(KERNEL_RSDP_SYMBOL) else {
        log_warn!(
            "kernel symbol `{}` not found; rsdp stays 0",
            KERNEL_RSDP_SYMBOL
        );
        return;
    };
    let value = rsdp.unwrap_or(0);
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, value);
    }
    if let Some(v) = rsdp {
        log_info!(
            "patched kernel `{}` @0x{:016x} = RSDP 0x{:x}",
            KERNEL_RSDP_SYMBOL,
            addr,
            v
        );
    } else {
        log_warn!(
            "no ACPI RSDP in config table; kernel `{}` = 0",
            KERNEL_RSDP_SYMBOL
        );
    }
}

fn patch_u64_symbol(kernel: &crate::kernel_loader::KernelImage, symbol: &str, value: u64) -> bool {
    let Some(addr) = kernel.segments.symbol_address(symbol) else {
        log_warn!("kernel platform symbol `{}` missing", symbol);
        return false;
    };
    unsafe { core::ptr::write_volatile(addr as *mut u64, value) };
    true
}

fn rsdp_oem_id(st: &SystemTable<Boot>) -> Option<[u8; 6]> {
    let rsdp = find_rsdp_phys(st)? as usize;
    if rsdp == 0 {
        return None;
    }
    let mut out = [0u8; 6];
    unsafe {
        for (i, b) in out.iter_mut().enumerate() {
            *b = core::ptr::read_volatile((rsdp + 9 + i) as *const u8);
        }
    }
    Some(out)
}

fn oem_ascii(id: Option<[u8; 6]>) -> alloc::string::String {
    let Some(id) = id else {
        return alloc::string::String::from("<none>");
    };
    id.iter()
        .map(|b| {
            if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '?'
            }
        })
        .collect()
}

#[inline]
fn acpi_rd8(addr: u64) -> u8 {
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

fn acpi_rd32(addr: u64) -> u32 {
    let mut b = [0u8; 4];
    for (i, v) in b.iter_mut().enumerate() {
        *v = acpi_rd8(addr + i as u64);
    }
    u32::from_le_bytes(b)
}

fn acpi_rd64(addr: u64) -> u64 {
    let mut b = [0u8; 8];
    for (i, v) in b.iter_mut().enumerate() {
        *v = acpi_rd8(addr + i as u64);
    }
    u64::from_le_bytes(b)
}

fn acpi_sig(addr: u64, sig: &[u8; 4]) -> bool {
    (0..4).all(|i| acpi_rd8(addr + i as u64) == sig[i])
}

/// ACPI SPCR early-console discovery. The SPCR structure starts with the common
/// 36-byte SDT header, then interface_type at +36 and a 12-byte GAS at +40.
/// Accept only SystemMemory + ARM PL011 (DBG2 subtype 0x03); other serial kinds
/// need a different register protocol and stay disabled rather than guessed.
fn find_spcr_pl011_base(st: &SystemTable<Boot>) -> Option<u64> {
    const ACPI_DBG2_ARM_PL011: u8 = 0x03;
    const GAS_SYSTEM_MEMORY: u8 = 0;
    let rsdp = find_rsdp_phys(st)?;
    let xsdt = acpi_rd64(rsdp + 24);
    if xsdt == 0 || !acpi_sig(xsdt, b"XSDT") {
        return None;
    }
    let len = acpi_rd32(xsdt + 4) as usize;
    if len < 36 || len > 1024 * 1024 || (len - 36) % 8 != 0 {
        return None;
    }
    for i in 0..((len - 36) / 8) {
        let table = acpi_rd64(xsdt + 36 + (i * 8) as u64);
        if table == 0 || !acpi_sig(table, b"SPCR") {
            continue;
        }
        let table_len = acpi_rd32(table + 4) as usize;
        if table_len < 52 {
            return None;
        }
        let interface = acpi_rd8(table + 36);
        let space_id = acpi_rd8(table + 40);
        let base = acpi_rd64(table + 44);
        log_info!(
            "SPCR: interface=0x{:02x} space={} base=0x{:x}",
            interface,
            space_id,
            base
        );
        return (interface == ACPI_DBG2_ARM_PL011 && space_id == GAS_SYSTEM_MEMORY && base != 0)
            .then_some(base);
    }
    log_info!("SPCR: absent");
    None
}

#[inline]
fn local_mpidr_affinity() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let mpidr: u64;
        unsafe {
            core::arch::asm!("mrs {0}, mpidr_el1", out(reg) mpidr, options(nomem, nostack, preserves_flags))
        };
        mpidr & MPIDR_AFFINITY_MASK
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

extern "efiapi" fn capture_ap_mpidr(arg: *mut c_void) {
    if arg.is_null() {
        return;
    }
    let affinity = local_mpidr_affinity();
    unsafe { core::ptr::write_volatile(arg.cast::<u64>(), affinity) };
}

/// Snapshot the architectural CPU affinities while UEFI still owns the APs.
/// `ProcessorId` from EFI_MP_SERVICES_PROTOCOL is deliberately *not* assumed to
/// be MPIDR: PI only promises a hardware-unique ID. Instead, StartupThisAP runs a
/// tiny synchronous callback on each enabled/healthy AP and reads MPIDR_EL1 there.
fn collect_uefi_mpidrs(st: &SystemTable<Boot>) -> Vec<u64> {
    let bs = st.boot_services();
    let Ok(handle) = bs.get_handle_for_protocol::<MpServices>() else {
        log_info!("MP Services: protocol absent");
        return Vec::new();
    };
    let Ok(mp) = bs.open_protocol_exclusive::<MpServices>(handle) else {
        log_warn!("MP Services: protocol open failed");
        return Vec::new();
    };
    let Ok(count) = mp.get_number_of_processors() else {
        log_warn!("MP Services: processor count failed");
        return Vec::new();
    };
    let bsp_number = mp.who_am_i().ok();
    log_info!(
        "MP Services: total={} enabled={} bsp={:?}",
        count.total,
        count.enabled,
        bsp_number
    );

    let mut out = Vec::with_capacity(count.total.min(BOOT_CPU_CAPACITY));
    // Always seed the BSP from the architectural register itself; this also
    // keeps topology useful on firmware that exposes MP Services but refuses AP callbacks.
    out.push(local_mpidr_affinity());

    for number in 0..count.total {
        if out.len() >= BOOT_CPU_CAPACITY {
            break;
        }
        let Ok(info) = mp.get_processor_info(number) else {
            continue;
        };
        if info.is_bsp() || bsp_number == Some(number) {
            continue;
        }
        if !info.is_enabled() || !info.is_healthy() {
            log_info!(
                "MP Services: cpu{} skipped enabled={} healthy={}",
                number,
                info.is_enabled(),
                info.is_healthy()
            );
            continue;
        }
        let mut affinity = u64::MAX;
        let arg = (&mut affinity as *mut u64).cast::<c_void>();
        match mp.startup_this_ap(
            number,
            capture_ap_mpidr,
            arg,
            Some(Duration::from_millis(100)),
        ) {
            Ok(()) if affinity != u64::MAX => {
                affinity &= MPIDR_AFFINITY_MASK;
                if !out.contains(&affinity) {
                    log_info!(
                        "MP Services: cpu{} processor_id=0x{:x} mpidr=0x{:x}",
                        number,
                        info.processor_id,
                        affinity
                    );
                    out.push(affinity);
                }
            }
            Ok(()) => {
                log_warn!("MP Services: cpu{} callback returned no MPIDR", number);
            }
            Err(e) => {
                log_warn!(
                    "MP Services: cpu{} callback failed: {:?}",
                    number,
                    e.status()
                );
            }
        }
    }
    out
}

fn patch_kernel_cpu_topology(kernel: &crate::kernel_loader::KernelImage, mpidrs: &[u64]) {
    let count = mpidrs.len().min(BOOT_CPU_CAPACITY);
    let _ = patch_u64_symbol(kernel, KERNEL_BOOT_CPU_COUNT_SYMBOL, count as u64);
    let Some(base) = kernel
        .segments
        .symbol_address(KERNEL_BOOT_CPU_MPIDRS_SYMBOL)
    else {
        log_warn!(
            "kernel CPU topology symbol `{}` missing",
            KERNEL_BOOT_CPU_MPIDRS_SYMBOL
        );
        return;
    };
    unsafe {
        for i in 0..BOOT_CPU_CAPACITY {
            let value = mpidrs.get(i).copied().unwrap_or(0);
            core::ptr::write_volatile((base as *mut u64).add(i), value);
        }
    }
    if count != 0 {
        log_info!(
            "CPU topology handoff: count={} mpidrs={:?}",
            count,
            &mpidrs[..count]
        );
    }
}

/// Classify only platforms for which Zero OS has an explicit early-MMIO
/// contract. QEMU's ArmVirt ACPI tables use RSDP OEM ID `BOCHS `; combine that
/// positive board fingerprint with EDK II before enabling QEMU-only MMIO.
/// Any unknown firmware remains fail-safe with early UART disabled.
fn patch_kernel_platform(st: &SystemTable<Boot>, kernel: &crate::kernel_loader::KernelImage) {
    let vendor = alloc::string::String::from(st.firmware_vendor());
    let oem = rsdp_oem_id(st);
    let oem_text = oem_ascii(oem);
    log_info!(
        "platform probe: vendor=\"{}\" rsdp_oem=\"{}\"",
        vendor,
        oem_text
    );

    let qemu_virt = vendor == "EDK II" && oem == Some(*b"BOCHS ");
    let spcr_uart = find_spcr_pl011_base(st);
    let (kind, fallback_uart, name) = if qemu_virt {
        (PLATFORM_QEMU_VIRT, QEMU_VIRT_PL011_BASE, "qemu-virt")
    } else if oem == Some(*b"PRLS  ") {
        (PLATFORM_PARALLELS_ARM, 0, "parallels-arm")
    } else {
        (PLATFORM_UNKNOWN, 0, "unknown-safe")
    };
    let uart_base = spcr_uart.unwrap_or(fallback_uart);

    let k = patch_u64_symbol(kernel, KERNEL_PLATFORM_KIND_SYMBOL, kind);
    let u = patch_u64_symbol(kernel, KERNEL_EARLY_UART_BASE_SYMBOL, uart_base);
    if k || u {
        log_info!(
            "platform handoff: vendor=\"{}\" kind={} ({}) early_uart=0x{:x}",
            vendor,
            kind,
            name,
            uart_base
        );
    }
}

/// 内核引导上下文：UEFI bootloader 与内核之间的协议载体。
///
/// 当前内核入口 (boot.S `_start`) 固定读取静态 `boot_info_struct`，
/// 因此这里除了保存计算结果外，还会在 prepare() 阶段把 `memory_bytes`
/// 直接补丁进已加载的内核镜像（通过 ELF 符号定位）。
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct KernelBootContext {
    /// 协商出的可用物理内存字节数（0 = 未知，内核回退 512 MiB）。
    pub memory_bytes: u64,
    /// EFI CONVENTIONAL 区间总量（仅用于诊断日志）。
    pub total_usable_bytes: u64,
    /// EFI CONVENTIONAL 最大连续块字节数（仅用于诊断日志）。
    pub max_contiguous_bytes: u64,
}

impl KernelBootContext {
    pub fn prepare(
        st: &mut SystemTable<Boot>,
        kernel: &crate::kernel_loader::KernelImage,
        rootfs: Option<&Vec<u8>>,
        _config: &crate::boot_config::BootConfig,
    ) -> Result<Self, Status> {
        let (total, max_block) = collect_usable_memory(st)?;

        // 保守策略：取「CONVENTIONAL 区间的最大连续块」而非总量。
        // 理由：内核位图分配器（microkernel/src/mm/phys.rs）假定物理内存从
        // RAM_BASE 连续延伸 memory_bytes 字节；若传总量而 EFI 在中间留下
        // MMIO/保留空洞，分配器可能把空洞当成 RAM 分配出去。
        // QEMU virt 下 0x4000_0000 开始的整块 RAM 就是最大连续块，二者等价。
        let memory_bytes = if max_block.bytes > 0 {
            max_block.bytes
        } else {
            total
        };

        log_info!(
            "EFI usable memory: total={} bytes, max_contiguous={} bytes @0x{:016x}",
            total,
            max_block.bytes,
            max_block.start
        );
        log_info!(
            "kernel memory_bytes = {} bytes ({} MiB)",
            memory_bytes,
            memory_bytes / (1024 * 1024)
        );

        patch_kernel_memory(kernel, memory_bytes);
        patch_kernel_rootfs(kernel, rootfs)?;

        // ACPI（WS-A）：ExitBootServices 前 RSDP 仍由固件持有/有效。
        patch_kernel_rsdp(kernel, find_rsdp_phys(st));

        // Snapshot CPU topology while UEFI MP Services can still run AP callbacks.
        // Runtime ACPI remains primary; this handoff is the architectural fallback
        // for firmware whose post-EBS MADT view does not enumerate all processors.
        let boot_mpidrs = collect_uefi_mpidrs(st);
        patch_kernel_cpu_topology(kernel, &boot_mpidrs);

        // Root bridge I/O translation is a Boot Services protocol and must be
        // captured before ExitBootServices. It enables legacy PCI I/O BARs on ARM64.
        patch_kernel_pci_io_window(kernel, collect_pci_io_window(st));

        // Early board contract: protect the kernel from touching QEMU-virt MMIO
        // on unrelated ARM64 firmware before ACPI/PCI discovery can take over.
        patch_kernel_platform(st, kernel);

        // Display Foundation：GOP mode/framebuffer 仅在 Boot Services 存活时
        // 可通过 protocol 查询，故在退出前捕获并补丁进内核只读槽位。
        let framebuffer = capture_framebuffer(st);
        patch_kernel_framebuffer(kernel, framebuffer);

        // 精细内存图：把合并后的 CONVENTIONAL 区间表灌入内核汇槽，
        // 物理分配器据此登记空洞（失败仅告警，内核回退总量路径）。
        fill_memory_map_sink(kernel, st);

        log_info!("boot context prepared");
        Ok(Self {
            memory_bytes,
            total_usable_bytes: total,
            max_contiguous_bytes: max_block.bytes,
        })
    }

    pub fn exit_boot_services(&self, st: SystemTable<Boot>) -> SystemTable<Runtime> {
        let (runtime, memory_map) = st.exit_boot_services();
        log_info!(
            "exited boot services with {} entries",
            memory_map.entries().len()
        );
        runtime
    }
}

#[derive(Default, Copy, Clone)]
struct UsableBlock {
    start: u64,
    bytes: u64,
}

/// 遍历 EFI memory map，统计 CONVENTIONAL 可用内存：
/// 返回 (总量, 最大连续块)。相邻且地址连续的 CONVENTIONAL 描述符合并为一个块。
fn collect_usable_memory(st: &mut SystemTable<Boot>) -> Result<(u64, UsableBlock), Status> {
    // memory_map() 需要调用方提供缓冲；内核加载已完成，堆仍可用，64 KiB 足够容纳
    // 数百个 EFI 描述符（每个 48 字节）。
    let mut buffer = alloc::vec![0u8; 64 * 1024];
    let map = st
        .boot_services()
        .memory_map(&mut buffer)
        .map_err(|e| e.status())?;
    let mut total = 0u64;
    let mut best = UsableBlock::default();
    let mut run = UsableBlock::default(); // 当前合并中的连续块
    let mut in_run = false;

    for desc in map.entries() {
        if desc.ty != uefi::table::boot::MemoryType::CONVENTIONAL {
            in_run = false;
            continue;
        }
        let bytes = desc.page_count * 4096;
        total += bytes;

        let contiguous = in_run
            && desc.phys_start <= run.start + run.bytes
            && desc.phys_start + bytes >= run.start + run.bytes;
        if contiguous {
            let end = desc.phys_start + bytes;
            run.bytes = end.saturating_sub(run.start);
        } else {
            run = UsableBlock {
                start: desc.phys_start,
                bytes,
            };
            in_run = true;
        }
        if run.bytes > best.bytes {
            best = run;
        }
    }
    Ok((total, best))
}

/// 内核侧 `__zero_memory_map` 汇槽协议常量（与 mm/phys.rs 镜像一致）。
mod memory_map_sink {
    pub const MAGIC: u64 = 0x5A4D_454D_3130_3131;
    pub const HEADER: usize = 0x10;
    pub const ENTRY: usize = 16;
    pub const CAPACITY: usize = 4096;
}

/// 把合并后的 CONVENTIONAL 区间表写入内核 `__zero_memory_map` 汇槽。
/// 超容截断保低址段；magic 最后落笔；任何异常仅告警——内核侧会
/// 因 magic 不符回退总量路径。
fn fill_memory_map_sink(kernel: &crate::kernel_loader::KernelImage, st: &mut SystemTable<Boot>) {
    let Some(sink_va) = kernel.segments.symbol_address("__zero_memory_map") else {
        log_warn!("memory map sink `__zero_memory_map` absent; kernel uses total fallback");
        return;
    };
    if !kernel.segments.contains_addr(sink_va) {
        log_warn!("memory map sink outside loaded segments; skipped");
        return;
    }

    // 收集并合并 CONVENTIONAL 区间（升序）。
    let mut buffer = alloc::vec![0u8; 64 * 1024];
    let map = match st.boot_services().memory_map(&mut buffer) {
        Ok(m) => m,
        Err(e) => {
            log_warn!("memory map unavailable: {:?}", e.status());
            return;
        }
    };
    let mut regions: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    for desc in map.entries() {
        if desc.ty != uefi::table::boot::MemoryType::CONVENTIONAL {
            continue;
        }
        let start = desc.phys_start;
        let end = desc.phys_start.saturating_add(desc.page_count * 4096);
        if let Some(last) = regions.last_mut() {
            let last_end = last.0.saturating_add(last.1);
            if start <= last_end {
                last.1 = end.saturating_sub(last.0);
                continue;
            }
        }
        regions.push((start, end - start));
    }

    let max_entries =
        (memory_map_sink::CAPACITY - memory_map_sink::HEADER) / memory_map_sink::ENTRY;
    if regions.len() > max_entries {
        regions.truncate(max_entries);
    }

    let sink = sink_va as *mut u8;
    unsafe {
        let mut off = memory_map_sink::HEADER;
        for &(base, len) in &regions {
            core::ptr::copy_nonoverlapping(base.to_le_bytes().as_ptr(), sink.add(off), 8);
            core::ptr::copy_nonoverlapping(len.to_le_bytes().as_ptr(), sink.add(off + 8), 8);
            off += memory_map_sink::ENTRY;
        }
        // count 先于 magic 落笔，magic 是有效性最终承诺。
        core::ptr::copy_nonoverlapping(
            (regions.len() as u64).to_le_bytes().as_ptr(),
            sink.add(0x08),
            8,
        );
        core::ptr::copy_nonoverlapping(memory_map_sink::MAGIC.to_le_bytes().as_ptr(), sink, 8);
    }
    log_info!(
        "memory map sink filled @0x{sink_va:016x}: {} regions",
        regions.len()
    );
}

/// 写回内核镜像 `.rodata.boot` 的 `__zero_memory_bytes` 占位符。
/// 内核按 p_vaddr 恒等映射加载，符号 VA 即可直接作为物理地址写入。
fn patch_kernel_memory(kernel: &crate::kernel_loader::KernelImage, memory_bytes: u64) {
    let Some(addr) = kernel.segments.symbol_address(KERNEL_MEMORY_SYMBOL) else {
        log_warn!(
            "kernel symbol `{}` not found; memory_bytes stays 0 (kernel falls back to 512 MiB)",
            KERNEL_MEMORY_SYMBOL
        );
        return;
    };
    unsafe {
        core::ptr::write_volatile(addr as *mut u64, memory_bytes);
    }
    log_info!(
        "patched kernel `{}` @0x{:016x} = {}",
        KERNEL_MEMORY_SYMBOL,
        addr,
        memory_bytes
    );
}
