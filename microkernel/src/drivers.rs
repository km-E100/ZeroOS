use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use spin::Mutex;
use zero_abi::driver::{DriverDescriptor, DriverKind, DriverTable};

const MAX_IRQ: usize = 256;

type IrqHandler = fn(u32);

static DRIVER_TABLE_PTR: AtomicPtr<DriverTable> = AtomicPtr::new(ptr::null_mut());
static IRQ_HANDLERS: Mutex<[Option<IrqHandler>; MAX_IRQ]> = Mutex::new([None; MAX_IRQ]);

#[derive(Debug)]
pub enum BlockError {
    NotReady,
    Busy,
    DeviceError,
    InvalidArgument,
}

#[derive(Debug)]
pub enum NetError {
    NotReady,
    Busy,
    BufferTooSmall,
    DeviceError,
}

pub fn init(table_ptr: *const DriverTable) {
    crate::info!(
        "drivers::init: begin table_ptr=0x{:016x}",
        table_ptr as usize
    );
    DRIVER_TABLE_PTR.store(table_ptr as *mut DriverTable, Ordering::SeqCst);

    let Some(descriptors) = descriptors() else {
        crate::info!("driver: no descriptors provided by bootloader");
        crate::info!("drivers::init: complete (no descriptors)");
        return;
    };

    crate::info!(
        "drivers::init: {} descriptor(s) provided",
        descriptors.len()
    );

    for descriptor in descriptors {
        let name = unsafe { descriptor.name() };
        crate::info!(
            "driver: probing {} (kind={} mmio=0x{:016x} irq={})",
            name,
            descriptor.kind as u32,
            descriptor.mmio_base,
            descriptor.irq
        );

        match descriptor.kind {
            DriverKind::Pl011 => pl011::init(descriptor),
            DriverKind::VirtIOBlk => virtio::blk::init(descriptor),
            DriverKind::VirtIONet => virtio::net::init(descriptor),
            DriverKind::VirtIOConsole | DriverKind::VirtIORng => {
                crate::info!("driver: unsupported virtio kind {}", descriptor.kind as u32)
            }
            DriverKind::Nvme => {
                crate::info!("driver: NVMe device '{}' delegated to user-space", name)
            }
        }
    }

    crate::info!("drivers::init: complete");
}

pub fn descriptors() -> Option<&'static [DriverDescriptor]> {
    let ptr = DRIVER_TABLE_PTR.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { (*ptr).as_slice() })
    }
}

pub fn handle_irq(irq: u32) -> bool {
    crate::info!("drivers::handle_irq: irq={}", irq);
    let handler = {
        let table = IRQ_HANDLERS.lock();
        table.get(irq as usize).and_then(|entry| *entry)
    };

    if let Some(handler) = handler {
        crate::info!("drivers::handle_irq: dispatching to handler");
        handler(irq);
        true
    } else {
        crate::info!("drivers::handle_irq: no handler installed");
        false
    }
}

pub fn register_irq_handler(irq: u32, handler: IrqHandler) {
    let index = irq as usize;
    if index >= MAX_IRQ {
        crate::info!("driver: irq {} out of range", irq);
        return;
    }
    {
        let mut table = IRQ_HANDLERS.lock();
        table[index] = Some(handler);
    }
    unsafe {
        crate::arch::enable_irq(irq);
    }
}

pub fn unregister_irq_handler(irq: u32) {
    let index = irq as usize;
    if index >= MAX_IRQ {
        return;
    }
    {
        let mut table = IRQ_HANDLERS.lock();
        table[index] = None;
    }
    unsafe {
        crate::arch::disable_irq(irq);
    }
}

pub mod pl011 {
    use super::register_irq_handler;
    use core::ptr::{read_volatile, write_volatile};
    use spin::Mutex;
    use zero_abi::driver::DriverDescriptor;

    const DR: usize = 0x00;
    const FR: usize = 0x18;
    const IBRD: usize = 0x24;
    const FBRD: usize = 0x28;
    const LCRH: usize = 0x2c;
    const CR: usize = 0x30;
    const IMSC: usize = 0x38;
    const MIS: usize = 0x40;
    const ICR: usize = 0x44;

    const RXIM: u32 = 1 << 4;
    const RTIM: u32 = 1 << 6;

    struct State {
        base: usize,
        ready: bool,
        rx_buf: [u8; 256],
        head: usize,
        tail: usize,
    }

    impl State {
        const fn new() -> Self {
            Self {
                base: 0,
                ready: false,
                rx_buf: [0; 256],
                head: 0,
                tail: 0,
            }
        }
    }

    static STATE: Mutex<State> = Mutex::new(State::new());

    pub fn init(descriptor: &DriverDescriptor) {
        let base = descriptor.mmio_base as usize;
        unsafe {
            crate::info!("pl011::init: base=0x{:016x}", base);
            write32(base, CR, 0);
            write32(base, IMSC, 0);
            write32(base, ICR, 0x7ff);
            write32(base, IBRD, 13);
            write32(base, FBRD, 2);
            write32(base, LCRH, 3 << 5);
            write32(base, CR, (1 << 0) | (1 << 8) | (1 << 9));
            write32(base, IMSC, RXIM | RTIM);
        }

        {
            let mut state = STATE.lock();
            state.base = base;
            state.ready = true;
            state.head = 0;
            state.tail = 0;
        }

        register_irq_handler(descriptor.irq, irq_handler);
        crate::info!("driver: pl011 initialised (irq={})", descriptor.irq);
    }

    pub fn read_byte() -> Option<u8> {
        let mut state = STATE.lock();
        if !state.ready || state.head == state.tail {
            return None;
        }
        let byte = state.rx_buf[state.tail % state.rx_buf.len()];
        state.tail = (state.tail + 1) % state.rx_buf.len();
        Some(byte)
    }

    pub fn read_into(buffer: &mut [u8]) -> usize {
        let mut count = 0;
        for slot in buffer.iter_mut() {
            match read_byte() {
                Some(byte) => {
                    *slot = byte;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    pub fn poll_console<F: FnMut(u8)>(mut sink: F) {
        while let Some(byte) = read_byte() {
            sink(byte);
        }
    }

    fn irq_handler(_irq: u32) {
        crate::info!("pl011::irq_handler: irq={}", _irq);
        let mut state = STATE.lock();
        if !state.ready {
            crate::info!("pl011::irq_handler: state not ready");
            return;
        }

        unsafe {
            let pending = read32(state.base, MIS);
            crate::info!("pl011::irq_handler: MIS=0x{:08x}", pending);
            if pending & (RXIM | RTIM) != 0 {
                while read32(state.base, FR) & (1 << 4) == 0 {
                    let byte = read32(state.base, DR) as u8;
                    let len = state.rx_buf.len();
                    let idx = state.head % len;
                    state.rx_buf[idx] = byte;
                    state.head = (state.head + 1) % len;
                    if state.head == state.tail {
                        state.tail = (state.tail + 1) % len;
                    }
                }
            }
            write32(state.base, ICR, pending);
        }
    }

    unsafe fn read32(base: usize, offset: usize) -> u32 {
        read_volatile((base + offset) as *const u32)
    }

    unsafe fn write32(base: usize, offset: usize, value: u32) {
        write_volatile((base + offset) as *mut u32, value);
    }
}

pub mod virtio {
    use super::{register_irq_handler, BlockError, NetError};
    use alloc::alloc::{alloc_zeroed, Layout};
    use core::cmp::min;
    use core::ptr::{self, read_volatile, write_volatile};
    use core::sync::atomic::{fence, Ordering};
    use spin::Mutex;
    use zero_abi::driver::DriverDescriptor;

    const STATUS_ACKNOWLEDGE: u32 = 1;
    const STATUS_DRIVER: u32 = 2;
    const STATUS_DRIVER_OK: u32 = 4;
    const STATUS_FEATURES_OK: u32 = 8;

    const REG_MAGIC: usize = 0x000;
    const REG_VERSION: usize = 0x004;
    const REG_DEVICE_ID: usize = 0x008;
    const REG_VENDOR_ID: usize = 0x00c;
    const REG_STATUS: usize = 0x070;
    const REG_DRIVER_FEATURES: usize = 0x020;
    const REG_DRIVER_FEATURES_SEL: usize = 0x024;
    const REG_QUEUE_NUM_MAX: usize = 0x034;
    const REG_QUEUE_NUM: usize = 0x038;
    const REG_QUEUE_ALIGN: usize = 0x03c;
    const REG_QUEUE_PFN: usize = 0x040;
    const REG_QUEUE_NOTIFY: usize = 0x050;
    const REG_INTERRUPT_STATUS: usize = 0x060;
    const REG_INTERRUPT_ACK: usize = 0x064;

    const VIRTQ_DESC_F_NEXT: u16 = 1;
    const VIRTQ_DESC_F_WRITE: u16 = 2;

    #[repr(C)]
    struct VirtqDesc {
        addr: u64,
        len: u32,
        flags: u16,
        next: u16,
    }

    #[repr(C)]
    struct VirtqAvail<const N: usize> {
        flags: u16,
        idx: u16,
        ring: [u16; N],
        event: u16,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct VirtqUsedElem {
        id: u32,
        len: u32,
    }

    #[repr(C)]
    struct VirtqUsed<const N: usize> {
        flags: u16,
        idx: u16,
        ring: [VirtqUsedElem; N],
        event: u16,
    }

    fn align_up(value: usize, align: usize) -> usize {
        let mask = align - 1;
        (value + mask) & !mask
    }

    unsafe fn mmio_read32(base: usize, offset: usize) -> u32 {
        read_volatile((base + offset) as *const u32)
    }

    unsafe fn mmio_write32(base: usize, offset: usize, value: u32) {
        write_volatile((base + offset) as *mut u32, value);
    }

    struct VirtQueue<const N: usize> {
        base: usize,
        queue_index: u32,
        desc: *mut VirtqDesc,
        avail: *mut VirtqAvail<N>,
        used: *mut VirtqUsed<N>,
        queue_size: u16,
        avail_idx: u16,
        last_used_idx: u16,
    }

    impl<const N: usize> VirtQueue<N> {
        fn push(&mut self, head: u16) {
            unsafe {
                let avail = &mut *self.avail;
                avail.ring[(self.avail_idx % self.queue_size) as usize] = head;
                fence(Ordering::Release);
                self.avail_idx = self.avail_idx.wrapping_add(1);
                avail.idx = self.avail_idx;
                fence(Ordering::SeqCst);
                mmio_write32(self.base, REG_QUEUE_NOTIFY, self.queue_index);
            }
        }

        fn pop_used(&mut self) -> Option<VirtqUsedElem> {
            unsafe {
                let used = &*self.used;
                if self.last_used_idx == used.idx {
                    None
                } else {
                    let elem = used.ring[(self.last_used_idx % self.queue_size) as usize];
                    self.last_used_idx = self.last_used_idx.wrapping_add(1);
                    Some(elem)
                }
            }
        }
    }

    pub mod blk {
        use super::*;

        const SECTOR_SIZE: usize = 512;
        const MAX_TRANSFER: usize = SECTOR_SIZE * 8;
        const QUEUE_SIZE: usize = 16;

        #[repr(C)]
        struct VirtioBlkReq {
            req_type: u32,
            reserved: u32,
            sector: u64,
        }

        struct VirtioBlkState {
            base: usize,
            ready: bool,
            queue: Option<VirtQueue<QUEUE_SIZE>>,
            header: *mut VirtioBlkReq,
            status_ptr: *mut u8,
            bounce: *mut u8,
            bounce_len: usize,
            inflight: bool,
            last_status: u8,
            last_len: usize,
        }

        impl VirtioBlkState {
            const fn new() -> Self {
                Self {
                    base: 0,
                    ready: false,
                    queue: None,
                    header: ptr::null_mut(),
                    status_ptr: ptr::null_mut(),
                    bounce: ptr::null_mut(),
                    bounce_len: 0,
                    inflight: false,
                    last_status: 0xff,
                    last_len: 0,
                }
            }
        }

        unsafe impl Send for VirtioBlkState {}

        static STATE: Mutex<VirtioBlkState> = Mutex::new(VirtioBlkState::new());

        pub fn init(descriptor: &DriverDescriptor) {
            let base = descriptor.mmio_base as usize;
            unsafe {
                crate::info!(
                    "virtio::blk::init: base=0x{:016x} irq={}",
                    base,
                    descriptor.irq
                );
                let magic = mmio_read32(base, super::REG_MAGIC);
                let version = mmio_read32(base, super::REG_VERSION);
                let device_id = mmio_read32(base, super::REG_DEVICE_ID);
                let vendor_id = mmio_read32(base, super::REG_VENDOR_ID);
                crate::info!(
                    "driver: virtio-blk mmio @ {:#x}: magic={:#x} version={} device_id={:#x} vendor={:#x}",
                    base,
                    magic,
                    version,
                    device_id,
                    vendor_id
                );
                if magic != 0x7472_6976 {
                    crate::info!("driver: virtio-blk bad magic");
                    return;
                }
                if device_id != 2 {
                    crate::info!(
                        "driver: virtio-blk unexpected device id (got {:#x})",
                        device_id
                    );
                    return;
                }
                mmio_write32(base, super::REG_STATUS, 0);
                mmio_write32(base, super::REG_STATUS, super::STATUS_ACKNOWLEDGE);
                let mut status = super::STATUS_ACKNOWLEDGE | super::STATUS_DRIVER;
                mmio_write32(base, super::REG_STATUS, status);
                mmio_write32(base, super::REG_DRIVER_FEATURES_SEL, 0);
                mmio_write32(base, super::REG_DRIVER_FEATURES, 0);
                status |= super::STATUS_FEATURES_OK;
                mmio_write32(base, super::REG_STATUS, status);
                if mmio_read32(base, super::REG_STATUS) & super::STATUS_FEATURES_OK == 0 {
                    crate::info!("driver: virtio-blk feature negotiation failed");
                    return;
                }
            }

            {
                let mut state = STATE.lock();
                state.base = base;
                if let Err(err) = configure_queue(&mut state) {
                    crate::info!("driver: virtio-blk queue setup failed: {:?}", err);
                    return;
                }
                state.ready = true;
            }

            register_irq_handler(descriptor.irq, irq_handler);
            unsafe {
                let mut status = mmio_read32(base, super::REG_STATUS);
                status |= super::STATUS_DRIVER_OK;
                mmio_write32(base, super::REG_STATUS, status);
            }
            crate::info!("driver: virtio-blk initialised (irq={})", descriptor.irq);
        }

        pub fn is_ready() -> bool {
            STATE.lock().ready
        }

        pub fn read_blocks(lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            if buffer.is_empty() {
                return Ok(());
            }
            if buffer.len() % SECTOR_SIZE != 0 {
                return Err(BlockError::InvalidArgument);
            }

            let mut processed = 0;
            let mut current_lba = lba;
            while processed < buffer.len() {
                let chunk = min(buffer.len() - processed, MAX_TRANSFER);
                {
                    #[allow(unused_mut)]
                    let mut state = STATE.lock();
                    if !state.ready {
                        return Err(BlockError::NotReady);
                    }
                    while state.inflight {
                        drop(state);
                        core::hint::spin_loop();
                        state = STATE.lock();
                    }
                    prepare_request(&mut state, current_lba, chunk, None, true)?;
                }
                let len = wait_for_completion()?;
                let copy_len = len.min(chunk);
                let state = STATE.lock();
                if state.bounce.is_null() {
                    return Err(BlockError::DeviceError);
                }
                unsafe {
                    ptr::copy_nonoverlapping(
                        state.bounce,
                        buffer[processed..processed + copy_len].as_mut_ptr(),
                        copy_len,
                    );
                }
                processed += chunk;
                current_lba += (chunk / SECTOR_SIZE) as u64;
            }

            Ok(())
        }

        pub fn write_blocks(lba: u64, buffer: &[u8]) -> Result<(), BlockError> {
            if buffer.is_empty() {
                return Ok(());
            }
            if buffer.len() % SECTOR_SIZE != 0 {
                return Err(BlockError::InvalidArgument);
            }

            let mut processed = 0;
            let mut current_lba = lba;
            while processed < buffer.len() {
                let chunk = min(buffer.len() - processed, MAX_TRANSFER);
                {
                    #[allow(unused_mut)]
                    let mut state = STATE.lock();
                    if !state.ready {
                        return Err(BlockError::NotReady);
                    }
                    while state.inflight {
                        drop(state);
                        core::hint::spin_loop();
                        state = STATE.lock();
                    }
                    prepare_request(
                        &mut state,
                        current_lba,
                        chunk,
                        Some(&buffer[processed..processed + chunk]),
                        false,
                    )?;
                }
                wait_for_completion()?;
                processed += chunk;
                current_lba += (chunk / SECTOR_SIZE) as u64;
            }

            Ok(())
        }

        fn prepare_request(
            state: &mut VirtioBlkState,
            lba: u64,
            data_len: usize,
            payload: Option<&[u8]>,
            is_read: bool,
        ) -> Result<(), BlockError> {
            let Some(queue) = state.queue.as_mut() else {
                return Err(BlockError::DeviceError);
            };
            if state.bounce_len < data_len {
                return Err(BlockError::InvalidArgument);
            }
            if state.header.is_null() || state.status_ptr.is_null() || state.bounce.is_null() {
                return Err(BlockError::DeviceError);
            }

            unsafe {
                if let Some(bytes) = payload {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), state.bounce, data_len);
                }
                (*state.header).req_type = if is_read { 0 } else { 1 };
                (*state.header).reserved = 0;
                (*state.header).sector = lba;
                ptr::write_volatile(state.status_ptr, 0xff);

                let desc = queue.desc;
                (*desc.add(0)).addr = state.header as u64;
                (*desc.add(0)).len = size_of::<VirtioBlkReq>() as u32;
                (*desc.add(0)).flags = VIRTQ_DESC_F_NEXT;
                (*desc.add(0)).next = 1;

                (*desc.add(1)).addr = state.bounce as u64;
                (*desc.add(1)).len = data_len as u32;
                (*desc.add(1)).flags =
                    if is_read { VIRTQ_DESC_F_WRITE } else { 0 } | VIRTQ_DESC_F_NEXT;
                (*desc.add(1)).next = 2;

                (*desc.add(2)).addr = state.status_ptr as u64;
                (*desc.add(2)).len = 1;
                (*desc.add(2)).flags = VIRTQ_DESC_F_WRITE;
                (*desc.add(2)).next = 0;

                queue.push(0);
            }

            state.last_status = 0xff;
            state.last_len = 0;
            state.inflight = true;
            Ok(())
        }

        fn wait_for_completion() -> Result<usize, BlockError> {
            loop {
                let (ready, status, len) = {
                    let state = STATE.lock();
                    if state.inflight {
                        (false, 0xff, 0)
                    } else {
                        (true, state.last_status, state.last_len)
                    }
                };
                if ready {
                    return if status == 0 {
                        Ok(len)
                    } else {
                        Err(BlockError::DeviceError)
                    };
                }
                core::hint::spin_loop();
            }
        }

        fn configure_queue(state: &mut VirtioBlkState) -> Result<(), BlockError> {
            unsafe {
                mmio_write32(state.base, super::REG_QUEUE_NUM, 0);
                let max_size = mmio_read32(state.base, super::REG_QUEUE_NUM_MAX) as u16;
                crate::info!(
                    "virtio-blk queue sel=0 max_size={} (requested={})",
                    max_size,
                    QUEUE_SIZE
                );
                if max_size == 0 {
                    return Err(BlockError::DeviceError);
                }
                let queue_size = (QUEUE_SIZE as u16).min(max_size);
                crate::info!("virtio-blk queue size={}", queue_size);
                mmio_write32(state.base, super::REG_QUEUE_ALIGN, 4096);

                let desc_bytes = size_of::<VirtqDesc>() * QUEUE_SIZE;
                let avail_offset = align_up(desc_bytes, 16);
                let used_offset =
                    align_up(avail_offset + size_of::<VirtqAvail<QUEUE_SIZE>>(), 4096);
                let total_size = used_offset + size_of::<VirtqUsed<QUEUE_SIZE>>();
                let layout = Layout::from_size_align(total_size, 4096).map_err(|_| {
                    crate::info!("virtio-blk queue layout error (size={})", total_size);
                    BlockError::DeviceError
                })?;
                let mem = alloc_zeroed(layout);
                if mem.is_null() {
                    crate::info!("virtio-blk queue alloc failed (bytes={})", total_size);
                    return Err(BlockError::DeviceError);
                }
                let desc = mem as *mut VirtqDesc;
                let avail = mem.add(avail_offset) as *mut VirtqAvail<QUEUE_SIZE>;
                let used = mem.add(used_offset) as *mut VirtqUsed<QUEUE_SIZE>;

                crate::info!(
                    "virtio-blk desc={:#x} avail={:#x} used={:#x}",
                    desc as usize,
                    avail as usize,
                    used as usize
                );
                mmio_write32(state.base, super::REG_QUEUE_NUM, queue_size as u32);
                mmio_write32(
                    state.base,
                    super::REG_QUEUE_PFN,
                    (mem as usize >> 12) as u32,
                );
                crate::info!("virtio-blk queue_pfn={:#x}", (mem as usize >> 12) as u32);

                state.queue = Some(VirtQueue {
                    base: state.base,
                    queue_index: 0,
                    desc,
                    avail,
                    used,
                    queue_size,
                    avail_idx: 0,
                    last_used_idx: 0,
                });

                let header_layout = Layout::from_size_align(size_of::<VirtioBlkReq>(), 16).unwrap();
                let header_ptr = alloc_zeroed(header_layout);
                if header_ptr.is_null() {
                    crate::info!("virtio-blk header alloc failed");
                    return Err(BlockError::DeviceError);
                }
                state.header = header_ptr as *mut VirtioBlkReq;

                let status_ptr = alloc_zeroed(Layout::from_size_align(1, 1).unwrap());
                if status_ptr.is_null() {
                    crate::info!("virtio-blk status alloc failed");
                    return Err(BlockError::DeviceError);
                }
                state.status_ptr = status_ptr;

                let bounce_ptr = alloc_zeroed(Layout::from_size_align(MAX_TRANSFER, 16).unwrap());
                if bounce_ptr.is_null() {
                    crate::info!("virtio-blk bounce alloc failed");
                    return Err(BlockError::DeviceError);
                }
                state.bounce = bounce_ptr;
                state.bounce_len = MAX_TRANSFER;
            }

            Ok(())
        }

        fn irq_handler(_irq: u32) {
            crate::info!("virtio::blk::irq_handler: irq={}", _irq);
            let mut state = STATE.lock();
            if !state.ready {
                crate::info!("virtio::blk::irq_handler: state not ready");
                return;
            }
            unsafe {
                let status = mmio_read32(state.base, super::REG_INTERRUPT_STATUS);
                crate::info!(
                    "virtio::blk::irq_handler: INTERRUPT_STATUS=0x{:08x}",
                    status
                );
                if status != 0 {
                    mmio_write32(state.base, super::REG_INTERRUPT_ACK, status);
                }
            }
            let mut completed = false;
            let mut length = 0usize;
            if let Some(queue) = state.queue.as_mut() {
                while let Some(elem) = queue.pop_used() {
                    completed = true;
                    length = elem.len as usize;
                }
            }
            if completed {
                state.last_status = if state.status_ptr.is_null() {
                    0xff
                } else {
                    unsafe { ptr::read_volatile(state.status_ptr) }
                };
                state.last_len = length;
                state.inflight = false;
            }
        }
    }

    pub mod net {
        use super::*;

        const RX_QUEUE_SIZE: usize = 8;
        const TX_QUEUE_SIZE: usize = 8;
        const MAX_FRAME: usize = 1536;

        struct VirtioNetState {
            base: usize,
            ready: bool,
            rx_queue: Option<VirtQueue<RX_QUEUE_SIZE>>,
            tx_queue: Option<VirtQueue<TX_QUEUE_SIZE>>,
            rx_buffers: *mut u8,
            rx_lengths: [u16; RX_QUEUE_SIZE],
            tx_buffer: *mut u8,
            tx_inflight: bool,
        }

        impl VirtioNetState {
            const fn new() -> Self {
                Self {
                    base: 0,
                    ready: false,
                    rx_queue: None,
                    tx_queue: None,
                    rx_buffers: ptr::null_mut(),
                    rx_lengths: [u16::MAX; RX_QUEUE_SIZE],
                    tx_buffer: ptr::null_mut(),
                    tx_inflight: false,
                }
            }
        }

        unsafe impl Send for VirtioNetState {}

        static STATE: Mutex<VirtioNetState> = Mutex::new(VirtioNetState::new());

        pub fn init(descriptor: &DriverDescriptor) {
            let base = descriptor.mmio_base as usize;
            unsafe {
                let magic = mmio_read32(base, super::REG_MAGIC);
                let version = mmio_read32(base, super::REG_VERSION);
                let device_id = mmio_read32(base, super::REG_DEVICE_ID);
                let vendor_id = mmio_read32(base, super::REG_VENDOR_ID);
                crate::info!(
                    "driver: virtio-net mmio @ {:#x}: magic={:#x} version={} device_id={:#x} vendor={:#x}",
                    base,
                    magic,
                    version,
                    device_id,
                    vendor_id
                );
                if magic != 0x7472_6976 {
                    crate::info!("driver: virtio-net bad magic");
                    return;
                }
                if device_id != 1 {
                    crate::info!("driver: virtio-net unexpected device id");
                    return;
                }
                mmio_write32(base, super::REG_STATUS, 0);
                mmio_write32(base, super::REG_STATUS, super::STATUS_ACKNOWLEDGE);
                let mut status = super::STATUS_ACKNOWLEDGE | super::STATUS_DRIVER;
                mmio_write32(base, super::REG_STATUS, status);
                mmio_write32(base, super::REG_DRIVER_FEATURES_SEL, 0);
                mmio_write32(base, super::REG_DRIVER_FEATURES, 0);
                status |= super::STATUS_FEATURES_OK;
                mmio_write32(base, super::REG_STATUS, status);
                if mmio_read32(base, super::REG_STATUS) & super::STATUS_FEATURES_OK == 0 {
                    crate::info!("driver: virtio-net feature negotiation failed");
                    return;
                }
            }

            {
                let mut state = STATE.lock();
                state.base = base;
                if let Err(err) = configure_rx(&mut state) {
                    crate::info!("virtio-net: RX setup failed: {:?}", err);
                    return;
                }
                if let Err(err) = configure_tx(&mut state) {
                    crate::info!("virtio-net: TX setup failed: {:?}", err);
                    return;
                }
                state.ready = true;
            }

            register_irq_handler(descriptor.irq, irq_handler);
            unsafe {
                let mut status = mmio_read32(base, super::REG_STATUS);
                status |= super::STATUS_DRIVER_OK;
                mmio_write32(base, super::REG_STATUS, status);
            }
            crate::info!("driver: virtio-net initialised (irq={})", descriptor.irq);
        }

        pub fn is_ready() -> bool {
            STATE.lock().ready
        }

        pub fn transmit(frame: &[u8]) -> Result<(), NetError> {
            if frame.is_empty() {
                return Ok(());
            }
            if frame.len() > MAX_FRAME {
                return Err(NetError::BufferTooSmall);
            }

            let mut state = STATE.lock();
            if !state.ready {
                return Err(NetError::NotReady);
            }
            if state.tx_inflight {
                return Err(NetError::Busy);
            }
            let tx_buffer = state.tx_buffer;
            if tx_buffer.is_null() {
                return Err(NetError::DeviceError);
            }
            unsafe {
                ptr::copy_nonoverlapping(frame.as_ptr(), tx_buffer, frame.len());
            }
            {
                let queue = state.tx_queue.as_mut().ok_or(NetError::DeviceError)?;
                unsafe {
                    let desc = queue.desc;
                    (*desc).addr = tx_buffer as u64;
                    (*desc).len = frame.len() as u32;
                    (*desc).flags = 0;
                    (*desc).next = 0;
                    queue.push(0);
                }
            }
            state.tx_inflight = true;
            Ok(())
        }

        pub fn poll_receive(buffer: &mut [u8]) -> Result<Option<usize>, NetError> {
            let mut state = STATE.lock();
            if !state.ready {
                return Err(NetError::NotReady);
            }
            if state.rx_buffers.is_null() {
                return Err(NetError::DeviceError);
            }
            if state.rx_queue.is_none() {
                return Err(NetError::DeviceError);
            }

            for idx in 0..RX_QUEUE_SIZE {
                let len = state.rx_lengths[idx];
                if len != u16::MAX {
                    let len_usize = len as usize;
                    if buffer.len() < len_usize {
                        return Err(NetError::BufferTooSmall);
                    }
                    unsafe {
                        let src = state.rx_buffers.add(idx * MAX_FRAME);
                        ptr::copy_nonoverlapping(src, buffer.as_mut_ptr(), len_usize);
                    }
                    state.rx_lengths[idx] = u16::MAX;
                    if let Some(queue) = state.rx_queue.as_mut() {
                        queue.push(idx as u16);
                    }
                    return Ok(Some(len_usize));
                }
            }

            Ok(None)
        }

        fn configure_rx(state: &mut VirtioNetState) -> Result<(), NetError> {
            unsafe {
                mmio_write32(state.base, super::REG_QUEUE_PFN, 0);
                mmio_write32(state.base, super::REG_QUEUE_NUM, 0);
                let max_size = mmio_read32(state.base, super::REG_QUEUE_NUM_MAX) as u16;
                if max_size == 0 {
                    return Err(NetError::DeviceError);
                }
                let queue_size = (RX_QUEUE_SIZE as u16).min(max_size);
                mmio_write32(state.base, super::REG_QUEUE_ALIGN, 4096);

                let desc_bytes = size_of::<VirtqDesc>() * RX_QUEUE_SIZE;
                let avail_offset = align_up(desc_bytes, 16);
                let used_offset =
                    align_up(avail_offset + size_of::<VirtqAvail<RX_QUEUE_SIZE>>(), 4096);
                let total_size = used_offset + size_of::<VirtqUsed<RX_QUEUE_SIZE>>();
                let layout =
                    Layout::from_size_align(total_size, 4096).map_err(|_| NetError::DeviceError)?;
                let mem = alloc_zeroed(layout);
                if mem.is_null() {
                    return Err(NetError::DeviceError);
                }
                let desc = mem as *mut VirtqDesc;
                let avail = mem.add(avail_offset) as *mut VirtqAvail<RX_QUEUE_SIZE>;
                let used = mem.add(used_offset) as *mut VirtqUsed<RX_QUEUE_SIZE>;

                mmio_write32(state.base, super::REG_QUEUE_NUM, queue_size as u32);
                mmio_write32(
                    state.base,
                    super::REG_QUEUE_PFN,
                    (mem as usize >> 12) as u32,
                );

                state.rx_queue = Some(VirtQueue {
                    base: state.base,
                    queue_index: 0,
                    desc,
                    avail,
                    used,
                    queue_size,
                    avail_idx: 0,
                    last_used_idx: 0,
                });

                let buffer_layout = Layout::from_size_align(RX_QUEUE_SIZE * MAX_FRAME, 64)
                    .map_err(|_| NetError::DeviceError)?;
                let buffers = alloc_zeroed(buffer_layout);
                if buffers.is_null() {
                    return Err(NetError::DeviceError);
                }
                state.rx_buffers = buffers;
                state.rx_lengths = [u16::MAX; RX_QUEUE_SIZE];

                if let Some(queue) = state.rx_queue.as_mut() {
                    for idx in 0..queue.queue_size as usize {
                        let buffer = buffers.add(idx * MAX_FRAME);
                        (*queue.desc.add(idx)).addr = buffer as u64;
                        (*queue.desc.add(idx)).len = MAX_FRAME as u32;
                        (*queue.desc.add(idx)).flags = VIRTQ_DESC_F_WRITE;
                        (*queue.desc.add(idx)).next = 0;
                        queue.push(idx as u16);
                    }
                }
            }

            Ok(())
        }

        fn configure_tx(state: &mut VirtioNetState) -> Result<(), NetError> {
            unsafe {
                mmio_write32(state.base, super::REG_QUEUE_NUM, 0);
                mmio_write32(state.base, super::REG_QUEUE_ALIGN, 4096);
                let max_size = mmio_read32(state.base, super::REG_QUEUE_NUM_MAX) as u16;
                if max_size == 0 {
                    return Err(NetError::DeviceError);
                }
                let queue_size = (TX_QUEUE_SIZE as u16).min(max_size);

                let desc_bytes = size_of::<VirtqDesc>() * TX_QUEUE_SIZE;
                let avail_offset = align_up(desc_bytes, 16);
                let used_offset =
                    align_up(avail_offset + size_of::<VirtqAvail<TX_QUEUE_SIZE>>(), 4096);
                let total_size = used_offset + size_of::<VirtqUsed<TX_QUEUE_SIZE>>();
                let layout =
                    Layout::from_size_align(total_size, 4096).map_err(|_| NetError::DeviceError)?;
                let mem = alloc_zeroed(layout);
                if mem.is_null() {
                    return Err(NetError::DeviceError);
                }
                let desc = mem as *mut VirtqDesc;
                let avail = mem.add(avail_offset) as *mut VirtqAvail<TX_QUEUE_SIZE>;
                let used = mem.add(used_offset) as *mut VirtqUsed<TX_QUEUE_SIZE>;

                mmio_write32(state.base, super::REG_QUEUE_NUM, queue_size as u32);
                mmio_write32(
                    state.base,
                    super::REG_QUEUE_PFN,
                    (mem as usize >> 12) as u32,
                );

                state.tx_queue = Some(VirtQueue {
                    base: state.base,
                    queue_index: 1,
                    desc,
                    avail,
                    used,
                    queue_size,
                    avail_idx: 0,
                    last_used_idx: 0,
                });

                let buffer_layout =
                    Layout::from_size_align(MAX_FRAME, 64).map_err(|_| NetError::DeviceError)?;
                let buffer = alloc_zeroed(buffer_layout);
                if buffer.is_null() {
                    return Err(NetError::DeviceError);
                }
                state.tx_buffer = buffer;
                state.tx_inflight = false;
            }

            Ok(())
        }

        fn irq_handler(_irq: u32) {
            let mut state = STATE.lock();
            if !state.ready {
                return;
            }
            unsafe {
                let status = mmio_read32(state.base, super::REG_INTERRUPT_STATUS);
                if status != 0 {
                    mmio_write32(state.base, super::REG_INTERRUPT_ACK, status);
                }
            }

            if let Some(rx_queue) = state.rx_queue.as_mut() {
                let mut idxs = [0u16; RX_QUEUE_SIZE];
                let mut lens = [0u16; RX_QUEUE_SIZE];
                let mut count = 0usize;
                while let Some(elem) = rx_queue.pop_used() {
                    if count < RX_QUEUE_SIZE {
                        idxs[count] = elem.id as u16;
                        lens[count] = elem.len as u16;
                        count += 1;
                    }
                }
                for i in 0..count {
                    let slot = (idxs[i] as usize) % RX_QUEUE_SIZE;
                    state.rx_lengths[slot] = lens[i];
                }
            }

            if let Some(tx_queue) = state.tx_queue.as_mut() {
                let mut completed = false;
                while let Some(_) = tx_queue.pop_used() {
                    completed = true;
                }
                if completed {
                    state.tx_inflight = false;
                }
            }
        }
    }
}
