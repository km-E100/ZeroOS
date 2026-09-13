//! VirtIO GPU display + VirGL 3D backend (device id 16).
//!
//! Knife 22 keeps the 2D scanout path. Knife 34 negotiates VIRTIO_GPU_F_VIRGL,
//! enumerates capsets, and exposes a capability-gated userspace 3D path. The
//! command stream is intentionally opaque to the kernel (VirGL/Gallium protocol),
//! while context/resource/DMA lifetime stays kernel-owned.

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use alloc::vec::Vec;
use core::mem::size_of;
use core::ptr;
use spin::Mutex;
use zero_abi::driver::DriverDescriptor;

use super::{
    configure_queue, negotiate_features_low, probe_device, set_driver_ok, VirtQueue, VirtqDesc,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use crate::{info, warn};

const DEVICE_ID_GPU: u32 = 16;
const QUEUE_SIZE: usize = 8;

// VirtIO GPU feature bits (low feature word).
const F_VIRGL: u32 = 1 << 0;
const F_CONTEXT_INIT: u32 = 1 << 4;
const WANTED_FEATURES: u32 = F_VIRGL | F_CONTEXT_INIT;
const CFG_NUM_CAPSETS: usize = 0x10c;

// 2D commands.
const CTRL_GET_DISPLAY_INFO: u32 = 0x0100;
const CTRL_RESOURCE_CREATE_2D: u32 = 0x0101;
const CTRL_RESOURCE_UNREF: u32 = 0x0102;
const CTRL_SET_SCANOUT: u32 = 0x0103;
const CTRL_RESOURCE_FLUSH: u32 = 0x0104;
const CTRL_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CTRL_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CTRL_RESOURCE_DETACH_BACKING: u32 = 0x0107;
const CTRL_GET_CAPSET_INFO: u32 = 0x0108;
const CTRL_GET_CAPSET: u32 = 0x0109;

// 3D commands.
const CTRL_CTX_CREATE: u32 = 0x0200;
const CTRL_CTX_DESTROY: u32 = 0x0201;
const CTRL_CTX_ATTACH_RESOURCE: u32 = 0x0202;
const CTRL_CTX_DETACH_RESOURCE: u32 = 0x0203;
const CTRL_RESOURCE_CREATE_3D: u32 = 0x0204;
const CTRL_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
const CTRL_SUBMIT_3D: u32 = 0x0207;

const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_OK_CAPSET_INFO: u32 = 0x1102;
const RESP_OK_CAPSET: u32 = 0x1103;
const FLAG_FENCE: u32 = 1;

const FORMAT_B8G8R8X8_UNORM: u32 = 2;
const RESOURCE_ID_2D: u32 = 1;
const RESOURCE_3D_FIRST: u32 = 0x100;
const MAX_3D_STREAM: usize = 1024 * 1024;
const MAX_3D_BACKING: usize = 64 * 1024 * 1024;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct CtrlHeader {
    kind: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    padding: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
struct Rect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct DisplayOne {
    rect: Rect,
    enabled: u32,
    flags: u32,
}
#[repr(C)]
#[derive(Default)]
struct DisplayInfo {
    hdr: CtrlHeader,
    pmodes: [DisplayOne; 16],
}
#[repr(C)]
struct Create2d {
    hdr: CtrlHeader,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
struct MemEntry {
    addr: u64,
    length: u32,
    padding: u32,
}
#[repr(C)]
struct AttachOne {
    hdr: CtrlHeader,
    resource_id: u32,
    nr_entries: u32,
    entry: MemEntry,
}
#[repr(C)]
struct SetScanout {
    hdr: CtrlHeader,
    rect: Rect,
    scanout_id: u32,
    resource_id: u32,
}
#[repr(C)]
struct Transfer2d {
    hdr: CtrlHeader,
    rect: Rect,
    offset: u64,
    resource_id: u32,
    padding: u32,
}
#[repr(C)]
struct Flush {
    hdr: CtrlHeader,
    rect: Rect,
    resource_id: u32,
    padding: u32,
}
#[repr(C)]
struct GetCapsetInfo {
    hdr: CtrlHeader,
    capset_index: u32,
    padding: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct RespCapsetInfo {
    hdr: CtrlHeader,
    capset_id: u32,
    capset_max_version: u32,
    capset_max_size: u32,
    padding: u32,
}
#[repr(C)]
struct GetCapset {
    hdr: CtrlHeader,
    capset_id: u32,
    capset_version: u32,
}
#[repr(C)]
struct CtxCreate {
    hdr: CtrlHeader,
    nlen: u32,
    context_init: u32,
    debug_name: [u8; 64],
}
#[repr(C)]
struct CtxResource {
    hdr: CtrlHeader,
    resource_id: u32,
    padding: u32,
}
#[repr(C)]
struct Create3d {
    hdr: CtrlHeader,
    resource_id: u32,
    target: u32,
    format: u32,
    bind: u32,
    width: u32,
    height: u32,
    depth: u32,
    array_size: u32,
    last_level: u32,
    nr_samples: u32,
    flags: u32,
    padding: u32,
}
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Box3d {
    x: u32,
    y: u32,
    z: u32,
    w: u32,
    h: u32,
    d: u32,
}
#[repr(C)]
struct Transfer3d {
    hdr: CtrlHeader,
    box3d: Box3d,
    offset: u64,
    resource_id: u32,
    level: u32,
    stride: u32,
    layer_stride: u32,
}
#[repr(C)]
struct Submit3d {
    hdr: CtrlHeader,
    size: u32,
    padding: u32,
}
#[repr(C)]
struct Unref {
    hdr: CtrlHeader,
    resource_id: u32,
    padding: u32,
}

#[derive(Copy, Clone, Debug)]
struct Capset {
    id: u32,
    max_version: u32,
    max_size: u32,
}
#[derive(Copy, Clone, Debug)]
struct Resource3d {
    id: u32,
    desc: zero_abi::gpu::Gpu3dResourceDesc,
    backing: usize,
    backing_len: usize,
    attached_ctx: u32,
}

struct GpuState {
    base: usize,
    queue: VirtQueue<QUEUE_SIZE>,
    backing: usize,
    bytes: usize,
    width: usize,
    height: usize,
    features: u32,
    capsets: Vec<Capset>,
    contexts: Vec<u32>,
    resources: Vec<Resource3d>,
    next_context: u32,
    next_resource: u32,
    next_fence: u64,
}
unsafe impl Send for GpuState {}
static GPU: Mutex<Option<GpuState>> = Mutex::new(None);

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Gpu3dError {
    Unsupported,
    Invalid,
    NotFound,
    Device,
    NoMemory,
}

fn hdr(kind: u32) -> CtrlHeader {
    CtrlHeader {
        kind,
        ..CtrlHeader::default()
    }
}
fn fenced_hdr(g: &mut GpuState, kind: u32, ctx_id: u32) -> CtrlHeader {
    let fence = g.next_fence;
    g.next_fence = g.next_fence.wrapping_add(1).max(1);
    CtrlHeader {
        kind,
        flags: FLAG_FENCE,
        fence_id: fence,
        ctx_id,
        padding: 0,
    }
}

pub fn init(desc: &DriverDescriptor) {
    let base = desc.mmio_base as usize;
    let features = unsafe {
        if super::mmio_read32(base, 0x008) == 0 {
            return;
        }
        if !probe_device(base, DEVICE_ID_GPU, "virtio-gpu") {
            return;
        }
        let Some(f) = negotiate_features_low(base, WANTED_FEATURES) else {
            return;
        };
        f
    };
    let Some(mut queue) = (unsafe { configure_queue::<QUEUE_SIZE>(base, 0) }) else {
        warn!("virtio-gpu: control queue unavailable");
        return;
    };
    crate::drivers::register_irq_handler(desc.irq, irq_handler);
    unsafe { set_driver_ok(base) };

    let capsets = if features & F_VIRGL != 0 {
        enumerate_capsets(base, &mut queue)
    } else {
        Vec::new()
    };

    let display = match transact::<CtrlHeader, DisplayInfo>(&mut queue, &hdr(CTRL_GET_DISPLAY_INFO))
    {
        Some(r) if r.hdr.kind == RESP_OK_DISPLAY_INFO => r,
        Some(r) => {
            warn!(
                "virtio-gpu: GET_DISPLAY_INFO response kind={:#x}",
                r.hdr.kind
            );
            return;
        }
        None => {
            warn!("virtio-gpu: GET_DISPLAY_INFO timeout");
            return;
        }
    };
    let Some(mode) = display
        .pmodes
        .iter()
        .find(|m| m.enabled != 0 && m.rect.width > 0 && m.rect.height > 0)
        .copied()
    else {
        warn!("virtio-gpu: no enabled scanout");
        return;
    };
    let width = mode.rect.width as usize;
    let height = mode.rect.height as usize;
    let Some(bytes) = width.checked_mul(height).and_then(|n| n.checked_mul(4)) else {
        return;
    };
    let Ok(layout) = Layout::from_size_align(bytes, 4096) else {
        return;
    };
    let backing = unsafe { alloc_zeroed(layout) };
    if backing.is_null() {
        warn!("virtio-gpu: backing OOM");
        return;
    }
    let rect = Rect {
        x: 0,
        y: 0,
        width: width as u32,
        height: height as u32,
    };
    let create = Create2d {
        hdr: hdr(CTRL_RESOURCE_CREATE_2D),
        resource_id: RESOURCE_ID_2D,
        format: FORMAT_B8G8R8X8_UNORM,
        width: width as u32,
        height: height as u32,
    };
    if !ok_nodata(&mut queue, &create) {
        warn!("virtio-gpu: CREATE_2D failed");
        return;
    }
    let attach = AttachOne {
        hdr: hdr(CTRL_RESOURCE_ATTACH_BACKING),
        resource_id: RESOURCE_ID_2D,
        nr_entries: 1,
        entry: MemEntry {
            addr: backing as u64,
            length: bytes as u32,
            padding: 0,
        },
    };
    if !ok_nodata(&mut queue, &attach) {
        warn!("virtio-gpu: ATTACH_BACKING failed");
        return;
    }
    let scan = SetScanout {
        hdr: hdr(CTRL_SET_SCANOUT),
        rect,
        scanout_id: 0,
        resource_id: RESOURCE_ID_2D,
    };
    if !ok_nodata(&mut queue, &scan) {
        warn!("virtio-gpu: SET_SCANOUT failed");
        return;
    }

    *GPU.lock() = Some(GpuState {
        base,
        queue,
        backing: backing as usize,
        bytes,
        width,
        height,
        features,
        capsets,
        contexts: Vec::new(),
        resources: Vec::new(),
        next_context: 1,
        next_resource: RESOURCE_3D_FIRST,
        next_fence: 1,
    });
    crate::display::install_virtio_gpu_framebuffer(backing as usize, bytes, width, height, width);
    flush_all();
    // Never log while holding GPU: the graphical logger flushes through this
    // very driver, so GPU-lock -> logger -> flush_all -> GPU-lock deadlocks.
    let capsets_snapshot = {
        GPU.lock()
            .as_ref()
            .map(|g| g.capsets.clone())
            .unwrap_or_default()
    };
    info!(
        "driver: virtio-gpu 2D scanout {}x{} online (base={:#x})",
        width, height, base
    );
    if features & F_VIRGL != 0 {
        info!(
            "driver: virtio-gpu VirGL 3D feature online capsets={}",
            capsets_snapshot.len()
        );
        for c in &capsets_snapshot {
            info!(
                "virtio-gpu: capset id={} max_version={} max_size={}",
                c.id, c.max_version, c.max_size
            );
        }
    } else {
        info!("driver: virtio-gpu host backend is 2D-only (VIRGL feature absent)");
    }
}

fn enumerate_capsets(base: usize, queue: &mut VirtQueue<QUEUE_SIZE>) -> Vec<Capset> {
    let count = unsafe { super::mmio_read32(base, CFG_NUM_CAPSETS) }.min(64);
    let mut out = Vec::new();
    for i in 0..count {
        let req = GetCapsetInfo {
            hdr: hdr(CTRL_GET_CAPSET_INFO),
            capset_index: i,
            padding: 0,
        };
        match transact::<GetCapsetInfo, RespCapsetInfo>(queue, &req) {
            Some(r)
                if r.hdr.kind == RESP_OK_CAPSET_INFO
                    && r.capset_id != 0
                    && r.capset_max_size != 0 =>
            {
                out.push(Capset {
                    id: r.capset_id,
                    max_version: r.capset_max_version,
                    max_size: r.capset_max_size,
                })
            }
            _ => break,
        }
    }
    out
}

fn ok_nodata<T>(q: &mut VirtQueue<QUEUE_SIZE>, req: &T) -> bool {
    transact::<T, CtrlHeader>(q, req)
        .map(|r| r.kind == RESP_OK_NODATA)
        .unwrap_or(false)
}
fn transact<Req, Resp: Default>(q: &mut VirtQueue<QUEUE_SIZE>, req: &Req) -> Option<Resp> {
    let mut resp = Resp::default();
    unsafe {
        let d = q.desc;
        *d.add(0) = VirtqDesc {
            addr: req as *const Req as u64,
            len: size_of::<Req>() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        *d.add(1) = VirtqDesc {
            addr: &mut resp as *mut Resp as u64,
            len: size_of::<Resp>() as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
    }
    q.push(0);
    wait_used(q).map(|_| resp)
}
fn transact_payload<Req, Resp: Default>(
    q: &mut VirtQueue<QUEUE_SIZE>,
    req: &Req,
    payload: &[u8],
) -> Option<Resp> {
    if payload.is_empty() {
        return transact(q, req);
    }
    let mut resp = Resp::default();
    unsafe {
        let d = q.desc;
        *d.add(0) = VirtqDesc {
            addr: req as *const Req as u64,
            len: size_of::<Req>() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        *d.add(1) = VirtqDesc {
            addr: payload.as_ptr() as u64,
            len: payload.len() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 2,
        };
        *d.add(2) = VirtqDesc {
            addr: &mut resp as *mut Resp as u64,
            len: size_of::<Resp>() as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
    }
    q.push(0);
    wait_used(q).map(|_| resp)
}
fn transact_into<Req>(q: &mut VirtQueue<QUEUE_SIZE>, req: &Req, out: &mut [u8]) -> Option<usize> {
    if out.len() > u32::MAX as usize {
        return None;
    }
    unsafe {
        let d = q.desc;
        *d.add(0) = VirtqDesc {
            addr: req as *const Req as u64,
            len: size_of::<Req>() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };
        *d.add(1) = VirtqDesc {
            addr: out.as_mut_ptr() as u64,
            len: out.len() as u32,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
    }
    q.push(0);
    wait_used(q).map(|e| e.len as usize)
}
fn wait_used(q: &mut VirtQueue<QUEUE_SIZE>) -> Option<super::VirtqUsedElem> {
    for _ in 0..5_000_000usize {
        if let Some(e) = q.pop_used() {
            return Some(e);
        }
        core::hint::spin_loop();
    }
    None
}
fn header_from_bytes(bytes: &[u8]) -> Option<CtrlHeader> {
    if bytes.len() < size_of::<CtrlHeader>() {
        return None;
    }
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr() as *const CtrlHeader) })
}

pub fn active() -> bool {
    GPU.lock().is_some()
}
pub fn dimensions() -> Option<(usize, usize)> {
    GPU.lock().as_ref().map(|g| (g.width, g.height))
}
pub fn framebuffer() -> Option<(usize, usize)> {
    GPU.lock().as_ref().map(|g| (g.backing, g.bytes))
}

pub fn three_d_info() -> Result<zero_abi::gpu::Gpu3dInfo, Gpu3dError> {
    let guard = GPU.lock();
    let g = guard.as_ref().ok_or(Gpu3dError::Unsupported)?;
    if g.features & F_VIRGL == 0 {
        return Err(Gpu3dError::Unsupported);
    }
    let cap = g
        .capsets
        .iter()
        .find(|c| c.id == 2)
        .or_else(|| g.capsets.iter().find(|c| c.id == 1))
        .ok_or(Gpu3dError::Unsupported)?;
    let mut flags = zero_abi::gpu::GPU3D_FLAG_VIRGL;
    if g.features & F_CONTEXT_INIT != 0 {
        flags |= zero_abi::gpu::GPU3D_FLAG_CONTEXT_INIT;
    }
    Ok(zero_abi::gpu::Gpu3dInfo {
        flags,
        capset_id: cap.id,
        capset_version: cap.max_version,
        capset_size: cap.max_size,
    })
}

pub fn get_capset(capset_id: u32, version: u32, out: &mut [u8]) -> Result<usize, Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    if g.features & F_VIRGL == 0 {
        return Err(Gpu3dError::Unsupported);
    }
    let cap = g
        .capsets
        .iter()
        .find(|c| c.id == capset_id)
        .copied()
        .ok_or(Gpu3dError::NotFound)?;
    if version > cap.max_version || out.len() < cap.max_size as usize {
        return Err(Gpu3dError::Invalid);
    }
    let mut wire = Vec::new();
    wire.try_reserve_exact(size_of::<CtrlHeader>() + cap.max_size as usize)
        .map_err(|_| Gpu3dError::NoMemory)?;
    wire.resize(size_of::<CtrlHeader>() + cap.max_size as usize, 0);
    let req = GetCapset {
        hdr: hdr(CTRL_GET_CAPSET),
        capset_id,
        capset_version: version,
    };
    let used = transact_into(&mut g.queue, &req, &mut wire).ok_or(Gpu3dError::Device)?;
    let rh = header_from_bytes(&wire[..used.min(wire.len())]).ok_or(Gpu3dError::Device)?;
    if rh.kind != RESP_OK_CAPSET {
        return Err(Gpu3dError::Device);
    }
    let payload = used
        .saturating_sub(size_of::<CtrlHeader>())
        .min(cap.max_size as usize);
    if payload > out.len() {
        return Err(Gpu3dError::Invalid);
    }
    out[..payload]
        .copy_from_slice(&wire[size_of::<CtrlHeader>()..size_of::<CtrlHeader>() + payload]);
    Ok(payload)
}

pub fn create_context(capset_id: u32) -> Result<u32, Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    if g.features & F_VIRGL == 0 || !g.capsets.iter().any(|c| c.id == capset_id) {
        return Err(Gpu3dError::Unsupported);
    }
    let id = g.next_context;
    g.next_context = g.next_context.wrapping_add(1).max(1);
    let mut name = [0u8; 64];
    let tag = b"ZeroOS-VirGL";
    name[..tag.len()].copy_from_slice(tag);
    let req = CtxCreate {
        hdr: fenced_hdr(g, CTRL_CTX_CREATE, id),
        nlen: tag.len() as u32,
        context_init: if g.features & F_CONTEXT_INIT != 0 {
            capset_id & 0xff
        } else {
            0
        },
        debug_name: name,
    };
    if !ok_nodata(&mut g.queue, &req) {
        return Err(Gpu3dError::Device);
    }
    g.contexts.push(id);
    Ok(id)
}

pub fn destroy_context(ctx: u32) -> Result<(), Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    let pos = g
        .contexts
        .iter()
        .position(|&v| v == ctx)
        .ok_or(Gpu3dError::NotFound)?;
    if g.resources.iter().any(|r| r.attached_ctx == ctx) {
        return Err(Gpu3dError::Invalid);
    }
    let req = CtrlHeader {
        kind: CTRL_CTX_DESTROY,
        ..fenced_hdr(g, CTRL_CTX_DESTROY, ctx)
    };
    if !ok_nodata(&mut g.queue, &req) {
        return Err(Gpu3dError::Device);
    }
    g.contexts.swap_remove(pos);
    Ok(())
}

pub fn create_resource(desc: zero_abi::gpu::Gpu3dResourceDesc) -> Result<u32, Gpu3dError> {
    if desc.width == 0
        || desc.height == 0
        || desc.depth == 0
        || desc.array_size == 0
        || desc.width > 8192
        || desc.height > 8192
        || desc.backing_bytes as usize > MAX_3D_BACKING
    {
        return Err(Gpu3dError::Invalid);
    }
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    if g.features & F_VIRGL == 0 {
        return Err(Gpu3dError::Unsupported);
    }
    let id = g.next_resource;
    g.next_resource = g.next_resource.wrapping_add(1).max(RESOURCE_3D_FIRST);
    let req = Create3d {
        hdr: fenced_hdr(g, CTRL_RESOURCE_CREATE_3D, 0),
        resource_id: id,
        target: desc.target,
        format: desc.format,
        bind: desc.bind,
        width: desc.width,
        height: desc.height,
        depth: desc.depth,
        array_size: desc.array_size,
        last_level: desc.last_level,
        nr_samples: desc.nr_samples,
        flags: desc.flags,
        padding: 0,
    };
    if !ok_nodata(&mut g.queue, &req) {
        return Err(Gpu3dError::Device);
    }

    let mut backing = 0usize;
    let mut backing_len = 0usize;
    if desc.backing_bytes != 0 {
        backing_len = desc.backing_bytes as usize;
        let layout = Layout::from_size_align(backing_len, 4096).map_err(|_| Gpu3dError::Invalid)?;
        let p = unsafe { alloc_zeroed(layout) };
        if p.is_null() {
            let _ = unref_resource_wire(g, id);
            return Err(Gpu3dError::NoMemory);
        }
        backing = p as usize;
        let attach = AttachOne {
            hdr: fenced_hdr(g, CTRL_RESOURCE_ATTACH_BACKING, 0),
            resource_id: id,
            nr_entries: 1,
            entry: MemEntry {
                addr: backing as u64,
                length: backing_len as u32,
                padding: 0,
            },
        };
        if !ok_nodata(&mut g.queue, &attach) {
            unsafe {
                dealloc(p, layout);
            }
            let _ = unref_resource_wire(g, id);
            return Err(Gpu3dError::Device);
        }
    }
    g.resources.push(Resource3d {
        id,
        desc,
        backing,
        backing_len,
        attached_ctx: 0,
    });
    Ok(id)
}

fn unref_resource_wire(g: &mut GpuState, id: u32) -> bool {
    let req = Unref {
        hdr: fenced_hdr(g, CTRL_RESOURCE_UNREF, 0),
        resource_id: id,
        padding: 0,
    };
    ok_nodata(&mut g.queue, &req)
}

pub fn destroy_resource(id: u32) -> Result<(), Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    let pos = g
        .resources
        .iter()
        .position(|r| r.id == id)
        .ok_or(Gpu3dError::NotFound)?;
    let r = g.resources[pos];
    if r.attached_ctx != 0 {
        let req = CtxResource {
            hdr: fenced_hdr(g, CTRL_CTX_DETACH_RESOURCE, r.attached_ctx),
            resource_id: id,
            padding: 0,
        };
        if !ok_nodata(&mut g.queue, &req) {
            return Err(Gpu3dError::Device);
        }
    }
    // Device must drop DMA references before guest backing is freed.
    if r.backing != 0 {
        let req = Unref {
            hdr: fenced_hdr(g, CTRL_RESOURCE_DETACH_BACKING, 0),
            resource_id: id,
            padding: 0,
        };
        if !ok_nodata(&mut g.queue, &req) {
            return Err(Gpu3dError::Device);
        }
    }
    if !unref_resource_wire(g, id) {
        return Err(Gpu3dError::Device);
    }
    let r = g.resources.swap_remove(pos);
    if r.backing != 0 {
        if let Ok(layout) = Layout::from_size_align(r.backing_len, 4096) {
            unsafe {
                dealloc(r.backing as *mut u8, layout);
            }
        }
    }
    Ok(())
}

pub fn attach_resource(ctx: u32, id: u32) -> Result<(), Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    if !g.contexts.contains(&ctx) {
        return Err(Gpu3dError::NotFound);
    }
    let pos = g
        .resources
        .iter()
        .position(|r| r.id == id)
        .ok_or(Gpu3dError::NotFound)?;
    if g.resources[pos].attached_ctx != 0 {
        return Err(Gpu3dError::Invalid);
    }
    let req = CtxResource {
        hdr: fenced_hdr(g, CTRL_CTX_ATTACH_RESOURCE, ctx),
        resource_id: id,
        padding: 0,
    };
    if !ok_nodata(&mut g.queue, &req) {
        return Err(Gpu3dError::Device);
    }
    g.resources[pos].attached_ctx = ctx;
    Ok(())
}

pub fn submit_3d(ctx: u32, stream: &[u8]) -> Result<(), Gpu3dError> {
    if stream.is_empty() || stream.len() > MAX_3D_STREAM || stream.len() & 3 != 0 {
        return Err(Gpu3dError::Invalid);
    }
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    if !g.contexts.contains(&ctx) {
        return Err(Gpu3dError::NotFound);
    }
    let req = Submit3d {
        hdr: fenced_hdr(g, CTRL_SUBMIT_3D, ctx),
        size: stream.len() as u32,
        padding: 0,
    };
    let Some(resp) = transact_payload::<Submit3d, CtrlHeader>(&mut g.queue, &req, stream) else {
        return Err(Gpu3dError::Device);
    };
    if resp.kind != RESP_OK_NODATA {
        return Err(Gpu3dError::Device);
    }
    Ok(())
}

pub fn readback_3d(id: u32, out: &mut [u8]) -> Result<usize, Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    let pos = g
        .resources
        .iter()
        .position(|r| r.id == id)
        .ok_or(Gpu3dError::NotFound)?;
    let r = g.resources[pos];
    if r.backing == 0
        || r.backing_len == 0
        || r.desc.target != 2
        || r.desc.format != FORMAT_B8G8R8X8_UNORM
    {
        return Err(Gpu3dError::Unsupported);
    }
    let stride = r.desc.width.checked_mul(4).ok_or(Gpu3dError::Invalid)?;
    let layer_stride = stride
        .checked_mul(r.desc.height)
        .ok_or(Gpu3dError::Invalid)?;
    let req = Transfer3d {
        hdr: fenced_hdr(g, CTRL_TRANSFER_FROM_HOST_3D, r.attached_ctx),
        box3d: Box3d {
            x: 0,
            y: 0,
            z: 0,
            w: r.desc.width,
            h: r.desc.height,
            d: 1,
        },
        offset: 0,
        resource_id: id,
        level: 0,
        stride,
        layer_stride,
    };
    if !ok_nodata(&mut g.queue, &req) {
        return Err(Gpu3dError::Device);
    }
    let n = out.len().min(r.backing_len);
    unsafe {
        ptr::copy_nonoverlapping(r.backing as *const u8, out.as_mut_ptr(), n);
    }
    Ok(n)
}

pub fn scanout_3d(id: u32) -> Result<(), Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    let r = g
        .resources
        .iter()
        .find(|r| r.id == id)
        .copied()
        .ok_or(Gpu3dError::NotFound)?;
    let rect = Rect {
        x: 0,
        y: 0,
        width: r.desc.width,
        height: r.desc.height,
    };
    let scan = SetScanout {
        hdr: fenced_hdr(g, CTRL_SET_SCANOUT, 0),
        rect,
        scanout_id: 0,
        resource_id: id,
    };
    if !ok_nodata(&mut g.queue, &scan) {
        return Err(Gpu3dError::Device);
    }
    let flush = Flush {
        hdr: fenced_hdr(g, CTRL_RESOURCE_FLUSH, 0),
        rect,
        resource_id: id,
        padding: 0,
    };
    if !ok_nodata(&mut g.queue, &flush) {
        return Err(Gpu3dError::Device);
    }
    Ok(())
}

pub fn restore_2d_scanout() -> Result<(), Gpu3dError> {
    let mut guard = GPU.lock();
    let g = guard.as_mut().ok_or(Gpu3dError::Unsupported)?;
    let rect = Rect {
        x: 0,
        y: 0,
        width: g.width as u32,
        height: g.height as u32,
    };
    let scan = SetScanout {
        hdr: hdr(CTRL_SET_SCANOUT),
        rect,
        scanout_id: 0,
        resource_id: RESOURCE_ID_2D,
    };
    if !ok_nodata(&mut g.queue, &scan) {
        return Err(Gpu3dError::Device);
    }
    Ok(())
}

pub fn flush_all() {
    let mut guard = GPU.lock();
    let Some(g) = guard.as_mut() else { return };
    let rect = Rect {
        x: 0,
        y: 0,
        width: g.width as u32,
        height: g.height as u32,
    };
    let transfer = Transfer2d {
        hdr: hdr(CTRL_TRANSFER_TO_HOST_2D),
        rect,
        offset: 0,
        resource_id: RESOURCE_ID_2D,
        padding: 0,
    };
    if !ok_nodata(&mut g.queue, &transfer) {
        return;
    }
    let flush = Flush {
        hdr: hdr(CTRL_RESOURCE_FLUSH),
        rect,
        resource_id: RESOURCE_ID_2D,
        padding: 0,
    };
    let _ = ok_nodata(&mut g.queue, &flush);
}

pub fn irq_handler(_irq: u32) {
    let guard = GPU.lock();
    let Some(g) = guard.as_ref() else { return };
    unsafe {
        let s = super::mmio_read32(g.base, super::REG_INTERRUPT_STATUS);
        if s != 0 {
            super::mmio_write32(g.base, super::REG_INTERRUPT_ACK, s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_layouts_are_stable() {
        assert_eq!(size_of::<CtrlHeader>(), 24);
        assert_eq!(size_of::<Rect>(), 16);
        assert_eq!(size_of::<MemEntry>(), 16);
        assert_eq!(size_of::<DisplayOne>(), 24);
        assert_eq!(size_of::<Create3d>(), 72);
        assert_eq!(size_of::<Transfer3d>(), 72);
        assert_eq!(size_of::<Submit3d>(), 32);
    }
    #[test]
    fn command_ids_match_virtio_gpu_spec() {
        assert_eq!(CTRL_GET_DISPLAY_INFO, 0x100);
        assert_eq!(CTRL_GET_CAPSET_INFO, 0x108);
        assert_eq!(CTRL_CTX_CREATE, 0x200);
        assert_eq!(CTRL_RESOURCE_CREATE_3D, 0x204);
        assert_eq!(CTRL_SUBMIT_3D, 0x207);
        assert_eq!(RESP_OK_NODATA, 0x1100);
    }
    #[test]
    fn feature_bits_are_low_word() {
        assert_eq!(F_VIRGL, 1);
        assert_eq!(F_CONTEXT_INIT, 16);
    }
}
