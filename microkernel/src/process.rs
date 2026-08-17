use crate::elf::{PF_W, PF_X};
use crate::mm::address_space::{self, AddressSpace, MapError, USER_STACK_LEN, USER_STACK_TOP};
use crate::mm::paging::{map_temp_page, unmap_temp_page, PAGE_SIZE};
use crate::mm::phys;
use crate::rootfs;
use crate::user_elf;
use core::cell::UnsafeCell;
use core::cmp;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use zero_abi::{ProcessId, ThreadEntry};

const MAX_PROCESSES: usize = 64;
const USER_STACK_SIZE: usize = 0x4000;
const KERNEL_STACK_SIZE: usize = 0x4000;
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct TrapFrame {
    pub regs: [u64; 31], // x0 - x30
    pub sp_el0: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub sp_el1: u64,
}

impl TrapFrame {
    pub const fn new() -> Self {
        Self {
            regs: [0; 31],
            sp_el0: 0,
            elr_el1: 0,
            spsr_el1: 0,
            sp_el1: 0,
        }
    }

    pub fn init_user(
        &mut self,
        entry: ThreadEntry,
        user_stack_top: usize,
        kernel_stack_top: usize,
    ) {
        self.regs = [0; 31];
        self.regs[30] = thread_exit as usize as u64;
        self.sp_el0 = user_stack_top as u64;
        self.elr_el1 = entry as usize as u64;
        self.spsr_el1 = 0; // EL0t, interrupts enabled
        self.sp_el1 = kernel_stack_top as u64;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Running,
    Blocked,
    Dying,
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
struct ProcessRecord {
    pid: ProcessId,
    name: &'static str,
    entry: ThreadEntry,
    state: ProcessState,
    slot: usize,
    addr_space: Option<AddressSpace>,
    privileged: bool,
    entry_point: Option<usize>,
    user_stack_top: Option<usize>,
    started: bool,
}

static NEXT_PID: AtomicU64 = AtomicU64::new(2);
static PROCESS_TABLE: Mutex<[Option<ProcessRecord>; MAX_PROCESSES]> =
    Mutex::new([const { None }; MAX_PROCESSES]);
struct TrapFrameCell(UnsafeCell<TrapFrame>);
impl TrapFrameCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(TrapFrame::new()))
    }

    fn get(&self) -> *mut TrapFrame {
        self.0.get()
    }
}
unsafe impl Sync for TrapFrameCell {}

struct StackCell<const N: usize>(UnsafeCell<[u8; N]>);
impl<const N: usize> StackCell<N> {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; N]))
    }

    fn as_ptr(&self) -> *mut u8 {
        self.0.get().cast::<u8>()
    }
}
unsafe impl<const N: usize> Sync for StackCell<N> {}

static TRAP_FRAMES: [TrapFrameCell; MAX_PROCESSES] =
    [const { TrapFrameCell::new() }; MAX_PROCESSES];
static KERNEL_STACKS: [StackCell<KERNEL_STACK_SIZE>; MAX_PROCESSES] =
    [const { StackCell::new() }; MAX_PROCESSES];

#[derive(Debug)]
pub enum ProcessError {
    NoSuchProcess,
    TableFull,
    NoMemory,
    InvalidArgument,
    PermissionDenied,
    ElfError(crate::elf::ElfError),
    MapError(address_space::MapError),
}

pub fn init() {
    let mut table = PROCESS_TABLE.lock();
    for slot in table.iter_mut() {
        *slot = None;
    }
    NEXT_PID.store(2, Ordering::SeqCst);
}

pub fn spawn(entry: ThreadEntry, name: &'static str) -> ProcessId {
    crate::info!("process::spawn called for name={}", name);
    let pid = ProcessId::new(NEXT_PID.fetch_add(1, Ordering::SeqCst));

    let mut table = PROCESS_TABLE.lock();
    let (slot_index, slot) = table
        .iter_mut()
        .enumerate()
        .find(|(_, slot)| slot.is_none())
        .expect("process table full");

    let user_sp = user_stack_top_raw(slot_index);
    let kernel_sp = kernel_stack_top_raw(slot_index);
    unsafe {
        let tf = TRAP_FRAMES[slot_index].get();
        (*tf).init_user(entry, user_sp, kernel_sp);
    }

    crate::info!(
        "process::spawn: pid={} slot={} name={}",
        pid.raw(),
        slot_index,
        name
    );

    *slot = Some(ProcessRecord {
        pid,
        name,
        entry,
        state: ProcessState::Runnable,
        slot: slot_index,
        addr_space: None,
        privileged: false,
        entry_point: None,
        user_stack_top: None,
        started: true,
    });

    pid
}

pub fn spawn_user(_entry: ThreadEntry, _name: &'static str) -> ProcessId {
    panic!("spawn_user() is deprecated. Use spawn_user_from_bootfs() instead.");
}

pub fn spawn_user_from_bootfs(
    path: &str,
    name: &'static str,
    privileged: bool,
) -> Result<ProcessId, ProcessError> {
    crate::info!("spawn_user_from_bootfs: path={}", path);
    let elf = user_elf::build_user_elf(path).map_err(ProcessError::ElfError)?;
    let pid = spawn(thread_exit, name);
    let Some(slot) = slot_for_pid(pid) else {
        return Err(ProcessError::NoSuchProcess);
    };

    let result = unsafe {
        let mut space = AddressSpace::new();
        map_user_elf_segments(&mut space, &elf, path).map_err(ProcessError::MapError)?;
        space
            .map_stack(USER_STACK_TOP, USER_STACK_LEN)
            .map_err(ProcessError::MapError)?;
        let bootfs_info =
            rootfs::build_user_bootfs_for_process(&mut space, rootfs::USER_BOOTFS_BASE)
                .map_err(ProcessError::MapError)?;
        configure_user_process(slot, space, elf.entry as usize, USER_STACK_TOP);
        set_initial_user_args(
            slot,
            [bootfs_info.entries_ptr, bootfs_info.entries_len, 0, 0],
        );
        let tf = TRAP_FRAMES[slot].get();
        (*tf).elr_el1 = elf.entry;
        (*tf).sp_el0 = USER_STACK_TOP as u64;
        Ok(())
    };

    if let Err(err) = result {
        remove_slot(slot);
        return Err(err);
    }

    if privileged {
        set_privileged(pid, true);
    }
    Ok(pid)
}

pub fn set_privileged(pid: ProcessId, privileged: bool) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = table
        .iter_mut()
        .filter_map(|slot| slot.as_mut())
        .find(|record| record.pid == pid)
    {
        record.privileged = privileged;
    }
}

pub fn is_slot_privileged(slot: usize) -> bool {
    let table = PROCESS_TABLE.lock();
    table
        .get(slot)
        .and_then(|entry| entry.as_ref())
        .map(|record| record.privileged)
        .unwrap_or(false)
}

pub fn slot_for_pid(pid: ProcessId) -> Option<usize> {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter_map(|slot| slot.as_ref())
        .find(|record| record.pid == pid)
        .map(|record| record.slot)
}

pub fn set_state(pid: ProcessId, state: ProcessState) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = table
        .iter_mut()
        .filter_map(|slot| slot.as_mut())
        .find(|record| record.pid == pid)
    {
        record.state = state;
    }
}

pub fn set_state_slot(slot: usize, state: ProcessState) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.state = state;
    }
}

pub fn state(pid: ProcessId) -> Option<ProcessState> {
    let table = PROCESS_TABLE.lock();
    table
        .iter()
        .filter_map(|slot| slot.as_ref())
        .find(|record| record.pid == pid)
        .map(|record| record.state)
}

pub unsafe fn trap_frame(slot: usize) -> *mut TrapFrame {
    TRAP_FRAMES[slot].get()
}

pub type Context = TrapFrame;

pub unsafe fn context_ptr(slot: usize) -> *mut Context {
    trap_frame(slot)
}

pub unsafe fn kernel_stack_top(slot: usize) -> usize {
    kernel_stack_top_raw(slot)
}

pub unsafe fn user_stack_top(slot: usize) -> usize {
    user_stack_top_raw(slot)
}

fn user_stack_top_raw(slot: usize) -> usize {
    let _ = slot;
    USER_STACK_TOP
}

fn kernel_stack_top_raw(slot: usize) -> usize {
    unsafe { KERNEL_STACKS[slot].as_ptr().add(KERNEL_STACK_SIZE) as usize }
}

pub fn pid_at_slot(slot: usize) -> Option<ProcessId> {
    let table = PROCESS_TABLE.lock();
    table[slot].map(|record| record.pid)
}

pub fn remove_slot(slot: usize) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = table[slot] {
        if let Some(space) = record.addr_space {
            unsafe {
                space.destroy();
            }
        }
    }
    table[slot] = None;
}

pub fn address_space(slot: usize) -> Option<AddressSpace> {
    let table = PROCESS_TABLE.lock();
    table[slot].and_then(|record| record.addr_space)
}

#[allow(dead_code)]
pub fn set_address_space(slot: usize, space: AddressSpace) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.addr_space = Some(space);
    }
}

fn configure_user_process(slot: usize, space: AddressSpace, entry: usize, user_sp: usize) {
    let mut table = PROCESS_TABLE.lock();
    if let Some(record) = &mut table[slot] {
        record.addr_space = Some(space);
        record.entry_point = Some(entry);
        record.user_stack_top = Some(user_sp);
        record.started = false;
    }
}

pub fn first_run_context(slot: usize) -> Option<(AddressSpace, *mut TrapFrame)> {
    let mut table = PROCESS_TABLE.lock();
    let record = table.get_mut(slot)?.as_mut()?;
    if record.started {
        return None;
    }
    if let (Some(space), Some(entry), Some(stack)) =
        (record.addr_space, record.entry_point, record.user_stack_top)
    {
        record.started = true;
        let tf = unsafe { TRAP_FRAMES[slot].get() };
        Some((space, tf))
    } else {
        None
    }
}

#[no_mangle]
extern "C" fn thread_exit() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn set_initial_user_args(slot: usize, args: [u64; 4]) {
    unsafe {
        let tf = TRAP_FRAMES[slot].get();
        (*tf).regs[0] = args[0];
        (*tf).regs[1] = args[1];
        (*tf).regs[2] = args[2];
        (*tf).regs[3] = args[3];
    }
}

fn map_user_elf_segments(
    space: &mut AddressSpace,
    elf: &user_elf::UserElf,
    path: &str,
) -> Result<(), MapError> {
    let elf_bytes = rootfs::read_file(path).ok_or(MapError::OutOfMemory)?;
    for seg in elf.segments.iter() {
        if seg.memsz == 0 {
            continue;
        }
        crate::info!(
            "map_user_elf_segments: vbase=0x{:x} mem_size=0x{:x} file_size=0x{:x}",
            seg.vaddr,
            seg.memsz,
            seg.filesz
        );
        let seg_start = seg.vaddr as usize;
        let seg_end = seg_start + seg.memsz as usize;
        let page_start = seg_start & !(PAGE_SIZE - 1);
        let page_end = align_up(seg_end, PAGE_SIZE);
        let writable = (seg.flags & PF_W) != 0;
        let executable = (seg.flags & PF_X) != 0;
        let data_len = seg.filesz as usize;

        for page_va in (page_start..page_end).step_by(PAGE_SIZE) {
            let phys = phys::alloc_page().ok_or(MapError::OutOfMemory)?;
            crate::info!(
                "map_user_elf_segments: page_va=0x{:x} phys=0x{:x}",
                page_va,
                phys
            );

            let page_first = page_va;
            let page_last = page_va + PAGE_SIZE;
            let copy_start = cmp::max(seg_start, page_first);
            let copy_end = cmp::min(seg_start + data_len, page_last);
            let kptr = unsafe { map_temp_page(phys) };
            unsafe {
                core::ptr::write_bytes(kptr, 0, PAGE_SIZE);
                if copy_start < copy_end {
                    let src_off = copy_start - seg_start;
                    let dst_off = copy_start - page_first;
                    let len = copy_end - copy_start;
                    core::ptr::copy_nonoverlapping(
                        elf_bytes.as_ptr().add(seg.offset as usize + src_off),
                        kptr.add(dst_off),
                        len,
                    );
                }
                unmap_temp_page();
            }
            unsafe {
                space.map_page_phys(page_va, phys, writable, executable)?;
            }
        }
    }
    Ok(())
}

pub fn fork(
    parent_slot: usize,
    parent_frame: &TrapFrame,
) -> Result<(ProcessId, usize), ProcessError> {
    let parent_record = {
        let table = PROCESS_TABLE.lock();
        table
            .get(parent_slot)
            .and_then(|entry| *entry)
            .ok_or(ProcessError::NoSuchProcess)?
    };

    let child_slot;
    let child_pid = ProcessId::new(NEXT_PID.fetch_add(1, Ordering::SeqCst));

    {
        let mut table = PROCESS_TABLE.lock();
        let (slot_index, slot) = table
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
            .ok_or(ProcessError::TableFull)?;
        child_slot = slot_index;

        let addr_space = if let Some(space) = parent_record.addr_space {
            Some(crate::mm::address_space::clone_space(&space))
        } else {
            None
        };

        *slot = Some(ProcessRecord {
            pid: child_pid,
            name: parent_record.name,
            entry: parent_record.entry,
            state: ProcessState::Runnable,
            slot: child_slot,
            addr_space,
            privileged: parent_record.privileged,
            entry_point: parent_record.entry_point,
            user_stack_top: parent_record.user_stack_top,
            started: true,
        });
    }

    unsafe {
        let child_tf = TRAP_FRAMES[child_slot].get();
        *child_tf = *parent_frame;
        // Reset return value for child
        (*child_tf).regs[0] = 0;

        // Rebase user stack pointer relative to new stack top
        let parent_top = user_stack_top_raw(parent_slot);
        let child_top = user_stack_top_raw(child_slot);
        let parent_sp = parent_frame.sp_el0 as usize;
        let used = parent_top.saturating_sub(parent_sp);
        (*child_tf).sp_el0 = child_top.saturating_sub(used) as u64;

        // Reset kernel stack pointer
        (*child_tf).sp_el1 = kernel_stack_top_raw(child_slot) as u64;

        // Clear kernel stack for determinism
        core::ptr::write_bytes(KERNEL_STACKS[child_slot].as_ptr(), 0, KERNEL_STACK_SIZE);
    }

    Ok((child_pid, child_slot))
}

pub unsafe fn exec(
    slot: usize,
    entry: ThreadEntry,
    arg: u64,
    frame: &mut TrapFrame,
) -> Result<(), ProcessError> {
    if entry as usize == 0 {
        return Err(ProcessError::InvalidArgument);
    }
    {
        let mut table = PROCESS_TABLE.lock();
        let record = table
            .get_mut(slot)
            .and_then(|slot| slot.as_mut())
            .ok_or(ProcessError::NoSuchProcess)?;
        record.entry = entry;
    }

    frame.regs = [0; 31];
    frame.regs[0] = arg;
    frame.regs[30] = thread_exit as usize as u64;
    frame.sp_el0 = user_stack_top_raw(slot) as u64;
    frame.sp_el1 = kernel_stack_top_raw(slot) as u64;
    frame.elr_el1 = entry as usize as u64;
    frame.spsr_el1 = 0;
    Ok(())
}
