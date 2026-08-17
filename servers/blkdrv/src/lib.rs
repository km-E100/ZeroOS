#![no_std]

use core::cmp::min;
use core::mem::{size_of, MaybeUninit};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use heapless::Vec;
use log::{info, warn};
use spin::Mutex;
use userlib::{
    driver_count, driver_info, mmio_map, mmio_unmap, shm_len, shm_phys, shm_release, shm_retain,
    yield_now,
};
use zero_abi::channels;
use zero_abi::driver::DriverKind;
use zero_abi::ipc::Message;
use zero_abi::protocol::blk as blk_proto;
use zero_abi::syscall::SysError;

const MAX_DEVICES: usize = 4;
const SECTOR_SIZE: usize = 512;
const MAX_TRANSFER: usize = SECTOR_SIZE * 32;
const QUEUE_SIZE: usize = 16;

const NVME_PAGE_SIZE: usize = 4096;
const NVME_ADMIN_QUEUE_ENTRIES: usize = 8;
const NVME_IO_QUEUE_ENTRIES: usize = 64;
const NVME_MAX_IO_PAGES: usize = 32;
const NVME_MAX_TRANSFER: usize = NVME_PAGE_SIZE * NVME_MAX_IO_PAGES;
const NVME_PRP_LIST_BYTES: usize = NVME_PAGE_SIZE;
const NVME_READY_TIMEOUT: usize = 1_000_000;

const NVME_REG_CAP: usize = 0x000;
const NVME_REG_CC: usize = 0x014;
const NVME_REG_CSTS: usize = 0x01c;
const NVME_REG_AQA: usize = 0x024;
const NVME_REG_ASQ: usize = 0x028;
const NVME_REG_ACQ: usize = 0x030;

const NVME_CC_ENABLE: u32 = 1 << 0;
const NVME_CC_MPS_SHIFT: u32 = 7;
const NVME_CC_IOSQES_SHIFT: u32 = 16;
const NVME_CC_IOCQES_SHIFT: u32 = 20;
const NVME_CC_IOSQES_VALUE: u32 = 6;
const NVME_CC_IOCQES_VALUE: u32 = 4;

const NVME_CMD_WRITE: u8 = 0x01;
const NVME_CMD_READ: u8 = 0x02;
const NVME_ADMIN_CREATE_SQ: u8 = 0x01;
const NVME_ADMIN_CREATE_CQ: u8 = 0x05;
const NVME_ADMIN_IDENTIFY: u8 = 0x06;

static DEVICE_TABLE: Mutex<Vec<BlockDevice, MAX_DEVICES>> = Mutex::new(Vec::new());

pub extern "C" fn server_main() -> ! {
    init_devices();
    info!("blkdrv: virtio backend ready");
    loop {
        let mut message = Message::empty();
        match userlib::ipc_receive(channels::BLKDRV_REQ, &mut message) {
            Ok(_) => dispatch(&message),
            Err(SysError::WouldBlock) => yield_now(),
            Err(err) => {
                warn!("blkdrv: receive error {:?}", err);
                yield_now();
            }
        }
    }
}

fn init_devices() {
    let mut table = DEVICE_TABLE.lock();
    table.clear();
    let count = driver_count().unwrap_or(0);
    for idx in 0..count {
        let Ok(info) = driver_info(idx as u32) else {
            continue;
        };
        if info.kind == DriverKind::VirtIOBlk as u32 {
            match VirtioBlkDevice::new(idx as u8, info) {
                Ok(device) => {
                    let _ = table.push(BlockDevice::Virtio(device));
                }
                Err(err) => warn!("blkdrv: virtio probe failed @{}: {:?}", idx, err),
            }
        } else if info.kind == DriverKind::Nvme as u32 {
            match NvmeDevice::new(idx as u8, info) {
                Ok(device) => {
                    let _ = table.push(BlockDevice::Nvme(device));
                }
                Err(err) => warn!("blkdrv: nvme probe failed @{}: {:?}", idx, err),
            }
        }
    }
}

fn dispatch(request: &Message) {
    match request.code {
        blk_proto::CMD_LIST => cmd_list(),
        blk_proto::CMD_INFO => cmd_info(request),
        blk_proto::CMD_READ => cmd_rw(request, false),
        blk_proto::CMD_WRITE => cmd_rw(request, true),
        blk_proto::CMD_FLUSH => respond_status(blk_proto::STATUS_UNSUPPORTED, &[]),
        blk_proto::CMD_PARTITION_INFO | blk_proto::CMD_IDENTIFY => {
            respond_status(blk_proto::STATUS_UNSUPPORTED, &[])
        }
        _ => respond_status(blk_proto::STATUS_INVALID, &[]),
    }
}

fn cmd_list() {
    let table = DEVICE_TABLE.lock();
    let mut response = Message::empty();
    response.code = blk_proto::STATUS_OK;
    response.payload[0] = table.len() as u8;
    for (slot, device) in table.iter().enumerate() {
        if slot + 1 >= response.payload.len() {
            break;
        }
        response.payload[slot + 1] = device.index();
    }
    let _ = userlib::ipc_send(channels::BLKDRV_RESP, &response);
}

fn cmd_info(request: &Message) {
    if request.payload.is_empty() {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    }
    let index = request.payload[0];
    let mut table = DEVICE_TABLE.lock();
    if let Some(device) = table.iter_mut().find(|dev| dev.index() == index) {
        let mut payload = [0u8; 20];
        payload[0] = device.index();
        payload[1] = match device {
            BlockDevice::Virtio(_) => blk_proto::DEVICE_TYPE_VIRTIO,
            BlockDevice::Nvme(_) => blk_proto::DEVICE_TYPE_NVME,
        };
        payload[2] = 0;
        payload[3] = 0;
        payload[4..12].copy_from_slice(&device.block_size().to_le_bytes());
        payload[12..20].copy_from_slice(&device.capacity_blocks().to_le_bytes());
        respond_status(blk_proto::STATUS_OK, &payload);
    } else {
        respond_status(blk_proto::STATUS_INVALID, &[]);
    }
}

fn cmd_rw(request: &Message, is_write: bool) {
    let Some(io) = IoRequest::parse(&request.payload) else {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    };
    let mut table = DEVICE_TABLE.lock();
    let Some(device) = table.iter_mut().find(|dev| dev.index() == io.device) else {
        respond_status(blk_proto::STATUS_INVALID, &[]);
        return;
    };
    match SharedSlice::acquire(io.shm_handle, io.shm_offset as usize, io.length as usize) {
        Ok(slice) => {
            let result = if is_write {
                device.write_blocks(io.lba, io.length as usize, slice.phys)
            } else {
                device.read_blocks(io.lba, io.length as usize, slice.phys)
            };
            drop(slice);
            match result {
                Ok(processed) => {
                    let mut payload = [0u8; 4];
                    payload.copy_from_slice(&(processed as u32).to_le_bytes());
                    respond_status(blk_proto::STATUS_OK, &payload);
                }
                Err(err) => respond_status(err.status_code(), &[]),
            }
        }
        Err(err) => respond_status(err.status_code(), &[]),
    }
}

fn respond_status(code: u32, payload: &[u8]) {
    let mut response = Message::empty();
    response.code = code;
    let len = payload.len().min(response.payload.len());
    response.payload[..len].copy_from_slice(&payload[..len]);
    let _ = userlib::ipc_send(channels::BLKDRV_RESP, &response);
}

struct IoRequest {
    device: u8,
    lba: u64,
    length: u32,
    shm_handle: u32,
    shm_offset: u32,
}

impl IoRequest {
    fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < 24 {
            return None;
        }
        let device = payload[0];
        let mut lba_bytes = [0u8; 8];
        lba_bytes.copy_from_slice(&payload[4..12]);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&payload[12..16]);
        let mut handle_bytes = [0u8; 4];
        handle_bytes.copy_from_slice(&payload[16..20]);
        let mut offset_bytes = [0u8; 4];
        offset_bytes.copy_from_slice(&payload[20..24]);
        Some(Self {
            device,
            lba: u64::from_le_bytes(lba_bytes),
            length: u32::from_le_bytes(len_bytes),
            shm_handle: u32::from_le_bytes(handle_bytes),
            shm_offset: u32::from_le_bytes(offset_bytes),
        })
    }
}

enum BlockDevice {
    Virtio(VirtioBlkDevice),
    Nvme(NvmeDevice),
}

unsafe impl Send for BlockDevice {}

impl BlockDevice {
    fn index(&self) -> u8 {
        match self {
            BlockDevice::Virtio(dev) => dev.descriptor_index,
            BlockDevice::Nvme(dev) => dev.descriptor_index,
        }
    }

    fn block_size(&self) -> u64 {
        match self {
            BlockDevice::Virtio(dev) => dev.block_size as u64,
            BlockDevice::Nvme(dev) => dev.block_size as u64,
        }
    }

    fn capacity_blocks(&self) -> u64 {
        match self {
            BlockDevice::Virtio(dev) => dev.capacity_blocks,
            BlockDevice::Nvme(dev) => dev.capacity_blocks,
        }
    }

    fn read_blocks(&mut self, lba: u64, len: usize, phys: usize) -> Result<usize, DriverError> {
        match self {
            BlockDevice::Virtio(dev) => dev.transfer(lba, len, phys, true),
            BlockDevice::Nvme(dev) => dev.transfer(lba, len, phys, true),
        }
    }

    fn write_blocks(&mut self, lba: u64, len: usize, phys: usize) -> Result<usize, DriverError> {
        match self {
            BlockDevice::Virtio(dev) => dev.transfer(lba, len, phys, false),
            BlockDevice::Nvme(dev) => dev.transfer(lba, len, phys, false),
        }
    }
}

struct VirtioBlkDevice {
    descriptor_index: u8,
    mmio_base: usize,
    queue: VirtQueue<QUEUE_SIZE>,
    queue_mem: ShmRegion,
    header: ShmRegion,
    status: ShmRegion,
    block_size: u32,
    capacity_blocks: u64,
    inflight: bool,
}

unsafe impl Send for VirtioBlkDevice {}

impl VirtioBlkDevice {
    fn new(index: u8, _info: userlib::DriverInfo) -> Result<Self, DriverError> {
        let mmio = mmio_map(index as u32).map_err(DriverError::from)?;
        let mmio_base = mmio.base as usize;
        unsafe {
            if read32(mmio_base, REG_MAGIC) != 0x7472_6976 {
                return Err(DriverError::Unsupported);
            }
            if read32(mmio_base, REG_DEVICE_ID) != 2 {
                return Err(DriverError::Unsupported);
            }
            write32(mmio_base, REG_STATUS, 0);
            write32(mmio_base, REG_STATUS, STATUS_ACKNOWLEDGE);
            let mut status = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
            write32(mmio_base, REG_STATUS, status);
            write32(mmio_base, REG_DRIVER_FEATURES_SEL, 0);
            write32(mmio_base, REG_DRIVER_FEATURES, 0);
            status |= STATUS_FEATURES_OK;
            write32(mmio_base, REG_STATUS, status);
            if read32(mmio_base, REG_STATUS) & STATUS_FEATURES_OK == 0 {
                return Err(DriverError::Unsupported);
            }
        }

        let mut device = VirtioBlkDevice {
            descriptor_index: index,
            mmio_base,
            queue: VirtQueue::empty(),
            queue_mem: ShmRegion::empty(),
            header: ShmRegion::empty(),
            status: ShmRegion::empty(),
            block_size: SECTOR_SIZE as u32,
            capacity_blocks: 0,
            inflight: false,
        };

        device.configure_queue()?;
        device.read_geometry();
        Ok(device)
    }

    fn configure_queue(&mut self) -> Result<(), DriverError> {
        unsafe {
            write32(self.mmio_base, REG_QUEUE_NUM, 0);
            let max_size = read32(self.mmio_base, REG_QUEUE_NUM_MAX) as u16;
            if max_size == 0 {
                return Err(DriverError::DeviceError);
            }
            let queue_size = min(max_size as usize, QUEUE_SIZE) as u16;
            write32(self.mmio_base, REG_QUEUE_ALIGN, 4096);

            let desc_bytes = size_of::<VirtqDesc>() * QUEUE_SIZE;
            let avail_offset = align_up(desc_bytes, 16);
            let used_offset = align_up(avail_offset + size_of::<VirtqAvail<QUEUE_SIZE>>(), 4096);
            let total_size = used_offset + size_of::<VirtqUsed<QUEUE_SIZE>>();

            let queue_mem = ShmRegion::new(total_size)?;
            let base_ptr = queue_mem.ptr();
            let desc_ptr = base_ptr as *mut VirtqDesc;
            let avail_ptr = base_ptr.add(avail_offset) as *mut VirtqAvail<QUEUE_SIZE>;
            let used_ptr = base_ptr.add(used_offset) as *mut VirtqUsed<QUEUE_SIZE>;

            write32(self.mmio_base, REG_QUEUE_NUM, queue_size as u32);
            write32(
                self.mmio_base,
                REG_QUEUE_PFN,
                (queue_mem.phys() >> 12) as u32,
            );

            self.queue_mem = queue_mem;
            self.queue =
                VirtQueue::new(self.mmio_base, 0, desc_ptr, avail_ptr, used_ptr, queue_size);

            self.header = ShmRegion::new(size_of::<VirtioBlkReq>())?;
            self.status = ShmRegion::new(1)?;
        }
        unsafe {
            write32(
                self.mmio_base,
                REG_STATUS,
                read32(self.mmio_base, REG_STATUS) | STATUS_DRIVER_OK,
            );
        }
        Ok(())
    }

    fn read_geometry(&mut self) {
        unsafe {
            let capacity_lo = read32(self.mmio_base, REG_CONFIG + 0) as u64;
            let capacity_hi = read32(self.mmio_base, REG_CONFIG + 4) as u64;
            let blk_size = read32(self.mmio_base, REG_CONFIG + 0x18);
            self.capacity_blocks = (capacity_hi << 32) | capacity_lo;
            if blk_size != 0 {
                self.block_size = blk_size;
            }
        }
    }

    fn transfer(
        &mut self,
        lba: u64,
        len: usize,
        phys_addr: usize,
        is_read: bool,
    ) -> Result<usize, DriverError> {
        if len == 0 {
            return Ok(0);
        }
        if len % SECTOR_SIZE != 0 || len > MAX_TRANSFER {
            return Err(DriverError::InvalidArgument);
        }
        if self.inflight {
            self.poll_completion()?;
        }
        unsafe {
            let header_ptr = self.header.ptr() as *mut VirtioBlkReq;
            (*header_ptr).req_type = if is_read { 0 } else { 1 };
            (*header_ptr).reserved = 0;
            (*header_ptr).sector = lba;
            core::ptr::write_volatile(self.status.ptr(), 0xff);

            (*self.queue.desc.add(0)).addr = self.header.phys() as u64;
            (*self.queue.desc.add(0)).len = size_of::<VirtioBlkReq>() as u32;
            (*self.queue.desc.add(0)).flags = VIRTQ_DESC_F_NEXT;
            (*self.queue.desc.add(0)).next = 1;

            (*self.queue.desc.add(1)).addr = phys_addr as u64;
            (*self.queue.desc.add(1)).len = len as u32;
            (*self.queue.desc.add(1)).flags =
                (if is_read { VIRTQ_DESC_F_WRITE } else { 0 }) | VIRTQ_DESC_F_NEXT;
            (*self.queue.desc.add(1)).next = 2;

            (*self.queue.desc.add(2)).addr = self.status.phys() as u64;
            (*self.queue.desc.add(2)).len = 1;
            (*self.queue.desc.add(2)).flags = VIRTQ_DESC_F_WRITE;
            (*self.queue.desc.add(2)).next = 0;
        }

        self.queue.push(0);
        self.inflight = true;
        self.poll_completion()?;
        Ok(len)
    }

    fn poll_completion(&mut self) -> Result<(), DriverError> {
        loop {
            if let Some(_elem) = self.queue.pop_used() {
                let status = unsafe { core::ptr::read_volatile(self.status.ptr()) };
                self.inflight = false;
                return if status == 0 {
                    Ok(())
                } else {
                    Err(DriverError::DeviceError)
                };
            }
            yield_now();
        }
    }
}

impl Drop for VirtioBlkDevice {
    fn drop(&mut self) {
        let _ = mmio_unmap(self.descriptor_index as u32);
    }
}

impl Drop for NvmeDevice {
    fn drop(&mut self) {
        let _ = mmio_unmap(self.descriptor_index as u32);
    }
}

struct NvmeDevice {
    descriptor_index: u8,
    mmio_base: usize,
    doorbell_stride: usize,
    admin: NvmeQueue,
    io: NvmeQueue,
    prp_list: ShmRegion,
    next_cid: u16,
    namespace_id: u32,
    block_size: u32,
    capacity_blocks: u64,
    max_queue_entries: u16,
}

unsafe impl Send for NvmeDevice {}

impl NvmeDevice {
    fn new(index: u8, _info: userlib::DriverInfo) -> Result<Self, DriverError> {
        let mmio = mmio_map(index as u32).map_err(DriverError::from)?;
        let mmio_base = mmio.base as usize;
        let cap = unsafe { read64(mmio_base, NVME_REG_CAP) };
        let mqes = (cap & 0xffff) as u16;
        let dstrd = ((cap >> 32) & 0xf) as u8;
        let doorbell_stride = 1usize << (dstrd as usize + 2);

        let max_entries = mqes.saturating_add(1);
        let admin_entries = NVME_ADMIN_QUEUE_ENTRIES.min(max_entries as usize) as u16;
        let admin_sq = ShmRegion::new_aligned(
            admin_entries as usize * core::mem::size_of::<NvmeCommand>(),
            NVME_PAGE_SIZE,
        )?;
        let admin_cq = ShmRegion::new_aligned(
            admin_entries as usize * core::mem::size_of::<NvmeCompletion>(),
            NVME_PAGE_SIZE,
        )?;

        unsafe {
            Self::disable_controller(mmio_base)?;
            write32(
                mmio_base,
                NVME_REG_AQA,
                ((admin_entries - 1) as u32) << 16 | ((admin_entries - 1) as u32),
            );
            write64(mmio_base, NVME_REG_ASQ, admin_sq.phys() as u64);
            write64(mmio_base, NVME_REG_ACQ, admin_cq.phys() as u64);
            Self::enable_controller(mmio_base)?;
        }
        Self::wait_ready(mmio_base, true)?;

        let admin = NvmeQueue::new(
            0,
            admin_entries,
            admin_sq,
            admin_cq,
            mmio_base,
            doorbell_stride,
        );

        let mut device = NvmeDevice {
            descriptor_index: index,
            mmio_base,
            doorbell_stride,
            admin,
            io: NvmeQueue::placeholder(),
            prp_list: ShmRegion::empty(),
            next_cid: 1,
            namespace_id: 1,
            block_size: SECTOR_SIZE as u32,
            capacity_blocks: 0,
            max_queue_entries: max_entries,
        };

        device.identify_namespace()?;
        device.create_io_queues()?;
        device.prp_list = ShmRegion::new_aligned(NVME_PRP_LIST_BYTES, NVME_PAGE_SIZE)?;
        Ok(device)
    }

    fn transfer(
        &mut self,
        lba: u64,
        len: usize,
        phys_addr: usize,
        is_read: bool,
    ) -> Result<usize, DriverError> {
        if len == 0 {
            return Ok(0);
        }
        if len % self.block_size as usize != 0 {
            return Err(DriverError::InvalidArgument);
        }
        if len > NVME_MAX_TRANSFER {
            return Err(DriverError::InvalidArgument);
        }

        if phys_addr % NVME_PAGE_SIZE != 0 {
            return Err(DriverError::InvalidArgument);
        }
        let blocks = len / self.block_size as usize;
        if blocks == 0 || blocks > 0x10000 {
            return Err(DriverError::InvalidArgument);
        }

        let opcode = if is_read {
            NVME_CMD_READ
        } else {
            NVME_CMD_WRITE
        };
        let mut cmd = self.new_command(opcode);
        cmd.nsid = self.namespace_id;
        let prp2 = self.prepare_prps(phys_addr, len)?;
        cmd.prp1 = phys_addr as u64;
        cmd.prp2 = prp2;
        cmd.cdw10 = (lba & 0xffff_ffff) as u32;
        cmd.cdw11 = (lba >> 32) as u32;
        cmd.cdw12 = (blocks as u32 - 1) & 0xffff;

        self.io.submit(&cmd)?;
        let completion = self.io.wait_for_completion()?;
        Self::check_completion(&completion)?;
        if completion.command_id != cmd.command_id() {
            return Err(DriverError::DeviceError);
        }
        Ok(len)
    }

    fn new_command(&mut self, opcode: u8) -> NvmeCommand {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        NvmeCommand::new(opcode, cid)
    }

    fn prepare_prps(&mut self, phys_addr: usize, len: usize) -> Result<u64, DriverError> {
        let pages = (len + NVME_PAGE_SIZE - 1) / NVME_PAGE_SIZE;
        if pages <= 1 {
            return Ok(0);
        }
        if pages == 2 {
            return Ok((phys_addr + NVME_PAGE_SIZE) as u64);
        }
        let entries = pages - 1;
        let capacity = self.prp_list.len() / core::mem::size_of::<u64>();
        if entries > capacity {
            return Err(DriverError::InvalidArgument);
        }
        let list =
            unsafe { core::slice::from_raw_parts_mut(self.prp_list.ptr() as *mut u64, capacity) };
        for idx in 0..entries {
            list[idx] = (phys_addr + NVME_PAGE_SIZE * (idx + 1)) as u64;
        }
        Ok(self.prp_list.phys() as u64)
    }

    fn identify_namespace(&mut self) -> Result<(), DriverError> {
        let buffer = ShmRegion::new_aligned(NVME_PAGE_SIZE, NVME_PAGE_SIZE)?;
        self.select_namespace_id(&buffer)?;
        self.populate_namespace_details(&buffer)?;
        Ok(())
    }

    fn select_namespace_id(&mut self, buffer: &ShmRegion) -> Result<(), DriverError> {
        let mut cmd = self.new_command(NVME_ADMIN_IDENTIFY);
        cmd.nsid = 0;
        cmd.cdw10 = 2; // namespace list
        cmd.prp1 = buffer.phys() as u64;
        self.admin.submit(&cmd)?;
        let completion = self.admin.wait_for_completion()?;
        Self::check_completion(&completion)?;
        let entries =
            unsafe { core::slice::from_raw_parts(buffer.ptr() as *const u32, NVME_PAGE_SIZE / 4) };
        if let Some(&nsid) = entries.iter().find(|&&val| val != 0) {
            self.namespace_id = u32::from_le(nsid);
        }
        if self.namespace_id == 0 {
            self.namespace_id = 1;
        }
        Ok(())
    }

    fn populate_namespace_details(&mut self, buffer: &ShmRegion) -> Result<(), DriverError> {
        let mut cmd = self.new_command(NVME_ADMIN_IDENTIFY);
        cmd.nsid = self.namespace_id;
        cmd.cdw10 = 0;
        cmd.prp1 = buffer.phys() as u64;
        self.admin.submit(&cmd)?;
        let completion = self.admin.wait_for_completion()?;
        Self::check_completion(&completion)?;

        let data_ptr = buffer.ptr() as *const u8;
        unsafe {
            let nsze = u64::from_le(core::ptr::read_unaligned(data_ptr.cast::<u64>()));
            let flbas = core::ptr::read_unaligned(data_ptr.add(26));
            let active = (flbas & 0x0f) as usize;
            let lbaf_offset = 128 + active * 4 + 2;
            let lbaf_ds = core::ptr::read_unaligned(data_ptr.add(lbaf_offset));
            let block_size = 1u32 << (lbaf_ds & 0x1f);
            if block_size != 0 {
                self.block_size = block_size;
            }
            self.capacity_blocks = nsze;
        }
        Ok(())
    }

    fn create_io_queues(&mut self) -> Result<(), DriverError> {
        let entries = NVME_IO_QUEUE_ENTRIES.min(self.max_queue_entries as usize) as u16;
        let cq_region = ShmRegion::new_aligned(
            entries as usize * core::mem::size_of::<NvmeCompletion>(),
            NVME_PAGE_SIZE,
        )?;
        let sq_region = ShmRegion::new_aligned(
            entries as usize * core::mem::size_of::<NvmeCommand>(),
            NVME_PAGE_SIZE,
        )?;

        // Create Completion Queue (QID=1)
        let mut create_cq = self.new_command(NVME_ADMIN_CREATE_CQ);
        create_cq.prp1 = cq_region.phys() as u64;
        create_cq.cdw10 = ((entries - 1) as u32) << 16 | 1;
        create_cq.cdw11 = 1 << 16; // physically contiguous
        self.admin.submit(&create_cq)?;
        let completion = self.admin.wait_for_completion()?;
        Self::check_completion(&completion)?;

        // Create Submission Queue (QID=1 mapped to CQ=1)
        let mut create_sq = self.new_command(NVME_ADMIN_CREATE_SQ);
        create_sq.prp1 = sq_region.phys() as u64;
        create_sq.cdw10 = ((entries - 1) as u32) << 16 | 1;
        create_sq.cdw11 = (1 << 16) | 1; // PC + CQID
        self.admin.submit(&create_sq)?;
        let completion = self.admin.wait_for_completion()?;
        Self::check_completion(&completion)?;

        self.io = NvmeQueue::new(
            1,
            entries,
            sq_region,
            cq_region,
            self.mmio_base,
            self.doorbell_stride,
        );
        Ok(())
    }

    fn check_completion(entry: &NvmeCompletion) -> Result<(), DriverError> {
        if (entry.status >> 1) != 0 {
            Err(DriverError::NvmeStatus(entry.status))
        } else {
            Ok(())
        }
    }

    unsafe fn disable_controller(mmio_base: usize) -> Result<(), DriverError> {
        let cc = read32(mmio_base, NVME_REG_CC);
        if cc & 1 != 0 {
            write32(mmio_base, NVME_REG_CC, cc & !1);
            Self::wait_ready(mmio_base, false)?;
        }
        Ok(())
    }

    unsafe fn enable_controller(mmio_base: usize) -> Result<(), DriverError> {
        let mut cc = 0u32;
        cc |= NVME_CC_ENABLE;
        cc |= 0 << NVME_CC_MPS_SHIFT;
        cc |= NVME_CC_IOSQES_VALUE << NVME_CC_IOSQES_SHIFT;
        cc |= NVME_CC_IOCQES_VALUE << NVME_CC_IOCQES_SHIFT;
        write32(mmio_base, NVME_REG_CC, cc);
        Ok(())
    }

    fn wait_ready(mmio_base: usize, expected: bool) -> Result<(), DriverError> {
        for _ in 0..NVME_READY_TIMEOUT {
            let csts = unsafe { read32(mmio_base, NVME_REG_CSTS) };
            let ready = (csts & 1) != 0;
            if ready == expected {
                return Ok(());
            }
            yield_now();
        }
        Err(DriverError::DeviceError)
    }
}

struct NvmeQueue {
    _qid: u16,
    entries: u16,
    sq: ShmRegion,
    cq: ShmRegion,
    sq_tail: u16,
    cq_head: u16,
    phase: u8,
    sq_doorbell: usize,
    cq_doorbell: usize,
}

unsafe impl Send for NvmeQueue {}

impl NvmeQueue {
    fn placeholder() -> Self {
        Self {
            _qid: 0,
            entries: 1,
            sq: ShmRegion::empty(),
            cq: ShmRegion::empty(),
            sq_tail: 0,
            cq_head: 0,
            phase: 1,
            sq_doorbell: 0,
            cq_doorbell: 0,
        }
    }

    fn new(
        qid: u16,
        entries: u16,
        sq: ShmRegion,
        cq: ShmRegion,
        base: usize,
        stride: usize,
    ) -> Self {
        let sq_offset = base + 0x1000 + (2 * qid as usize) * stride;
        let cq_offset = base + 0x1000 + (2 * qid as usize + 1) * stride;
        Self {
            _qid: qid,
            entries,
            sq,
            cq,
            sq_tail: 0,
            cq_head: 0,
            phase: 1,
            sq_doorbell: sq_offset,
            cq_doorbell: cq_offset,
        }
    }

    fn submit(&mut self, cmd: &NvmeCommand) -> Result<(), DriverError> {
        unsafe {
            let slot = self
                .sq
                .ptr()
                .cast::<NvmeCommand>()
                .add(self.sq_tail as usize);
            slot.write(*cmd);
        }
        self.sq_tail = (self.sq_tail + 1) % self.entries;
        unsafe {
            write32_addr(self.sq_doorbell, self.sq_tail as u32);
        }
        Ok(())
    }

    fn wait_for_completion(&mut self) -> Result<NvmeCompletion, DriverError> {
        loop {
            let entry = unsafe {
                self.cq
                    .ptr()
                    .cast::<NvmeCompletion>()
                    .add(self.cq_head as usize)
                    .read()
            };
            let phase = (entry.status & 1) as u8;
            if phase != self.phase {
                yield_now();
            }
            self.cq_head = (self.cq_head + 1) % self.entries;
            if self.cq_head == 0 {
                self.phase ^= 1;
            }
            unsafe {
                write32_addr(self.cq_doorbell, self.cq_head as u32);
            }
            return Ok(entry);
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct NvmeCommand {
    cdw0: u32,
    nsid: u32,
    rsvd2: u64,
    mptr: u64,
    prp1: u64,
    prp2: u64,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

impl NvmeCommand {
    fn new(opcode: u8, cid: u16) -> Self {
        Self {
            cdw0: (opcode as u32) | ((cid as u32) << 16),
            nsid: 0,
            rsvd2: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    fn command_id(&self) -> u16 {
        (self.cdw0 >> 16) as u16
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct NvmeCompletion {
    cdw0: u32,
    rsvd: u32,
    sq_head: u16,
    sq_id: u16,
    command_id: u16,
    status: u16,
}

#[derive(Debug)]
enum DriverError {
    InvalidArgument,
    DeviceError,
    Unsupported,
    Sys(SysError),
    NvmeStatus(u16),
}

impl DriverError {
    fn status_code(self) -> u32 {
        match self {
            DriverError::InvalidArgument => blk_proto::STATUS_INVALID,
            DriverError::DeviceError => blk_proto::STATUS_IOERR,
            DriverError::Unsupported => blk_proto::STATUS_UNSUPPORTED,
            DriverError::Sys(err) => {
                let _ = err;
                blk_proto::STATUS_IOERR
            }
            DriverError::NvmeStatus(code) => {
                let _ = code;
                blk_proto::STATUS_IOERR
            }
        }
    }
}

impl From<SysError> for DriverError {
    fn from(value: SysError) -> Self {
        DriverError::Sys(value)
    }
}

struct SharedSlice {
    handle: u32,
    phys: usize,
}

impl SharedSlice {
    fn acquire(handle: u32, offset: usize, len: usize) -> Result<Self, DriverError> {
        if len == 0 {
            return Err(DriverError::InvalidArgument);
        }
        shm_retain(handle).map_err(DriverError::from)?;
        let total_len = match shm_len(handle) {
            Ok(len) => len,
            Err(err) => {
                let _ = shm_release(handle);
                return Err(DriverError::from(err));
            }
        };
        if offset + len > total_len {
            let _ = shm_release(handle);
            return Err(DriverError::InvalidArgument);
        }
        let phys = match shm_phys(handle) {
            Ok(addr) => addr,
            Err(err) => {
                let _ = shm_release(handle);
                return Err(DriverError::from(err));
            }
        };
        Ok(Self {
            handle,
            phys: phys + offset,
        })
    }
}

impl Drop for SharedSlice {
    fn drop(&mut self) {
        let _ = shm_release(self.handle);
    }
}

struct ShmRegion {
    mem: MaybeUninit<userlib::SharedMemory>,
    phys: usize,
    len: usize,
}

unsafe impl Send for ShmRegion {}

impl ShmRegion {
    const fn empty() -> Self {
        Self {
            mem: MaybeUninit::uninit(),
            phys: 0,
            len: 0,
        }
    }

    fn new(size: usize) -> Result<Self, DriverError> {
        let mem = userlib::shm_create(size).map_err(DriverError::from)?;
        let phys = userlib::shm_phys(mem.handle).map_err(DriverError::from)?;
        Ok(Self {
            phys,
            len: mem.len,
            mem: MaybeUninit::new(mem),
        })
    }

    fn new_aligned(size: usize, align: usize) -> Result<Self, DriverError> {
        let aligned = if size % align == 0 {
            size
        } else {
            align_up(size, align)
        };
        let region = Self::new(aligned)?;
        if (region.ptr() as usize & (align - 1)) != 0 || (region.phys() & (align - 1)) != 0 {
            return Err(DriverError::DeviceError);
        }
        Ok(region)
    }

    fn ptr(&self) -> *mut u8 {
        unsafe { self.mem.assume_init_ref().ptr }
    }

    fn phys(&self) -> usize {
        self.phys
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl Drop for ShmRegion {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        unsafe {
            let handle = self.mem.assume_init_ref().handle;
            let _ = shm_release(handle);
        }
        self.len = 0;
    }
}

#[repr(C)]
struct VirtioBlkReq {
    req_type: u32,
    reserved: u32,
    sector: u64,
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
    const fn empty() -> Self {
        Self {
            base: 0,
            queue_index: 0,
            desc: core::ptr::null_mut(),
            avail: core::ptr::null_mut(),
            used: core::ptr::null_mut(),
            queue_size: 0,
            avail_idx: 0,
            last_used_idx: 0,
        }
    }

    fn new(
        base: usize,
        queue_index: u32,
        desc: *mut VirtqDesc,
        avail: *mut VirtqAvail<N>,
        used: *mut VirtqUsed<N>,
        queue_size: u16,
    ) -> Self {
        Self {
            base,
            queue_index,
            desc,
            avail,
            used,
            queue_size,
            avail_idx: 0,
            last_used_idx: 0,
        }
    }

    fn push(&mut self, head: u16) {
        unsafe {
            let avail = &mut *self.avail;
            avail.ring[(self.avail_idx % self.queue_size) as usize] = head;
            fence(Ordering::Release);
            self.avail_idx = self.avail_idx.wrapping_add(1);
            avail.idx = self.avail_idx;
            fence(Ordering::SeqCst);
            write32(self.base, REG_QUEUE_NOTIFY, self.queue_index);
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

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;

const REG_MAGIC: usize = 0x000;
const REG_DEVICE_ID: usize = 0x008;
const REG_STATUS: usize = 0x070;
const REG_DRIVER_FEATURES: usize = 0x020;
const REG_DRIVER_FEATURES_SEL: usize = 0x024;
const REG_QUEUE_NUM_MAX: usize = 0x034;
const REG_QUEUE_NUM: usize = 0x038;
const REG_QUEUE_ALIGN: usize = 0x03c;
const REG_QUEUE_PFN: usize = 0x040;
const REG_QUEUE_NOTIFY: usize = 0x050;
const REG_CONFIG: usize = 0x100;

fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}

unsafe fn read32(base: usize, offset: usize) -> u32 {
    read_volatile((base + offset) as *const u32)
}

unsafe fn write32(base: usize, offset: usize, value: u32) {
    write_volatile((base + offset) as *mut u32, value);
}

unsafe fn read64(base: usize, offset: usize) -> u64 {
    read_volatile((base + offset) as *const u64)
}

unsafe fn write64(base: usize, offset: usize, value: u64) {
    write_volatile((base + offset) as *mut u64, value);
}

unsafe fn write32_addr(addr: usize, value: u32) {
    write_volatile(addr as *mut u32, value);
}
