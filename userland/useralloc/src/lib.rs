#![no_std]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;
use spin::Mutex;

const ALIGN: usize = 16;
const HEADER: usize = 16; // size_flags + next offset
const FOOTER: usize = 8;
const FREE: usize = 1;
const NONE: usize = usize::MAX;
const MIN_BLOCK: usize = HEADER + ALIGN + FOOTER;

#[derive(Copy, Clone)]
struct State {
    initialised: bool,
    head: usize,
}

impl State {
    const fn new() -> Self {
        // Keep the entire static allocator zero-initialisable so the linker
        // can place multi-megabyte heaps in NOLOAD .bss instead of bloating
        // every service ELF's .data. `head` is ignored until ensure_init().
        Self {
            initialised: false,
            head: 0,
        }
    }
}

#[repr(C, align(16))]
struct Heap<const N: usize>(UnsafeCell<[u8; N]>);
unsafe impl<const N: usize> Sync for Heap<N> {}

/// Reusable allocator for bare-metal user processes.
///
/// The old runtime allocators were monotonic bump heaps: every temporary
/// `Vec`/`String` permanently consumed heap space. This allocator keeps the
/// same fixed static memory budget but returns freed blocks to a coalescing
/// free list. It is lock protected so it remains correct after user threads
/// are introduced.
pub struct StaticFreeList<const N: usize> {
    heap: Heap<N>,
    state: Mutex<State>,
}

unsafe impl<const N: usize> Sync for StaticFreeList<N> {}

impl<const N: usize> StaticFreeList<N> {
    pub const fn new() -> Self {
        Self {
            heap: Heap(UnsafeCell::new([0; N])),
            state: Mutex::new(State::new()),
        }
    }

    #[inline]
    fn base(&self) -> usize {
        self.heap.0.get() as *mut u8 as usize
    }

    #[inline]
    fn usable_len(&self) -> usize {
        N & !(ALIGN - 1)
    }

    unsafe fn ensure_init(&self, st: &mut State) -> bool {
        if st.initialised {
            return true;
        }
        let len = self.usable_len();
        if len < MIN_BLOCK {
            return false;
        }
        self.write_header(0, len, NONE);
        self.write_footer(0, len, true);
        st.head = 0;
        st.initialised = true;
        true
    }

    #[inline]
    unsafe fn write_usize(&self, off: usize, value: usize) {
        ((self.base() + off) as *mut usize).write(value);
    }

    #[inline]
    unsafe fn read_usize(&self, off: usize) -> usize {
        ((self.base() + off) as *const usize).read()
    }

    #[inline]
    unsafe fn write_header(&self, off: usize, size: usize, next: usize) {
        self.write_usize(off, size | FREE);
        self.write_usize(off + 8, next);
    }

    #[inline]
    unsafe fn write_footer(&self, off: usize, size: usize, free: bool) {
        self.write_usize(off + size - FOOTER, size | if free { FREE } else { 0 });
    }

    #[inline]
    unsafe fn block_size(&self, off: usize) -> usize {
        self.read_usize(off) & !FREE
    }

    #[inline]
    unsafe fn next(&self, off: usize) -> usize {
        self.read_usize(off + 8)
    }

    #[inline]
    unsafe fn set_next(&self, off: usize, next: usize) {
        self.write_usize(off + 8, next)
    }

    unsafe fn alloc_locked(&self, st: &mut State, layout: Layout) -> *mut u8 {
        if !self.ensure_init(st) {
            return ptr::null_mut();
        }
        let align = layout.align().max(ALIGN);
        if !align.is_power_of_two() {
            return ptr::null_mut();
        }
        let payload = align_up(layout.size().max(1), ALIGN);
        let mut prev = NONE;
        let mut cur = st.head;

        while cur != NONE {
            let size = self.block_size(cur);
            let payload_base = self.base() + cur + HEADER;
            let aligned_payload = align_up(payload_base, align);
            let pad = aligned_payload - payload_base;
            let used = align_up(HEADER + pad + payload + FOOTER, ALIGN);
            if size >= used {
                let nxt = self.next(cur);
                if prev == NONE {
                    st.head = nxt;
                } else {
                    self.set_next(prev, nxt);
                }

                let remainder = size - used;
                let committed = if remainder >= MIN_BLOCK {
                    let rem = cur + used;
                    self.write_header(rem, remainder, st.head);
                    self.write_footer(rem, remainder, true);
                    st.head = rem;
                    used
                } else {
                    // Absorb a tail too small to form a standalone free block.
                    // Recording only `used` here creates an unowned gap that a
                    // later dealloc mistakes for the next block header.
                    size
                };

                self.write_usize(cur, committed); // allocated: FREE bit clear
                let ptr_off = cur + HEADER + pad;
                self.write_usize(ptr_off - 8, cur); // block back-pointer
                self.write_footer(cur, committed, false);
                return (self.base() + ptr_off) as *mut u8;
            }
            prev = cur;
            cur = self.next(cur);
        }
        ptr::null_mut()
    }

    unsafe fn dealloc_locked(&self, st: &mut State, ptr: *mut u8) {
        if ptr.is_null() || !st.initialised {
            return;
        }
        let base = self.base();
        let p = ptr as usize;
        if p < base + HEADER || p >= base + self.usable_len() {
            return; // allocator contract violation: fail closed instead of corrupting heap
        }
        let ptr_off = p - base;
        let block = self.read_usize(ptr_off - 8);
        if block >= self.usable_len() {
            return;
        }
        let raw = self.read_usize(block);
        if raw & FREE != 0 {
            return; // duplicate free: ignore in user process rather than poison heap
        }
        let size = raw;
        if size < MIN_BLOCK
            || block
                .checked_add(size)
                .map_or(true, |e| e > self.usable_len())
        {
            return;
        }

        let mut merged_start = block;
        let mut merged_size = size;
        if block >= FOOTER {
            let prev_footer = self.read_usize(block - FOOTER);
            if prev_footer & FREE != 0 {
                let prev_size = prev_footer & !FREE;
                if prev_size >= MIN_BLOCK && prev_size <= block {
                    merged_start = block - prev_size;
                    merged_size += prev_size;
                }
            }
        }
        let next_start = block + size;
        if next_start + HEADER <= self.usable_len() {
            let next_raw = self.read_usize(next_start);
            if next_raw & FREE != 0 {
                let next_size = next_raw & !FREE;
                if next_size >= MIN_BLOCK && next_start + next_size <= self.usable_len() {
                    merged_size += next_size;
                }
            }
        }

        // Remove every free-list node that is now inside the merged range.
        let merged_end = merged_start + merged_size;
        let mut cur = st.head;
        let mut new_head = NONE;
        let mut last = NONE;
        while cur != NONE {
            let nxt = self.next(cur);
            if cur < merged_start || cur >= merged_end {
                if last == NONE {
                    new_head = cur;
                } else {
                    self.set_next(last, cur);
                }
                last = cur;
            }
            cur = nxt;
        }
        if last != NONE {
            self.set_next(last, NONE);
        }
        self.write_header(merged_start, merged_size, new_head);
        self.write_footer(merged_start, merged_size, true);
        st.head = merged_start;
    }
}

unsafe impl<const N: usize> GlobalAlloc for StaticFreeList<N> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.alloc_locked(&mut self.state.lock(), layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        self.dealloc_locked(&mut self.state.lock(), ptr)
    }
}

#[inline]
const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    #[test]
    fn frees_are_reused_and_coalesced() {
        let a = Box::leak(Box::new(StaticFreeList::<4096>::new()));
        unsafe {
            let l = Layout::from_size_align(128, 16).unwrap();
            let p1 = GlobalAlloc::alloc(a, l);
            let p2 = GlobalAlloc::alloc(a, l);
            assert!(!p1.is_null() && !p2.is_null());
            GlobalAlloc::dealloc(a, p1, l);
            let p3 = GlobalAlloc::alloc(a, l);
            assert_eq!(p3, p1, "freed block should be reused");
            GlobalAlloc::dealloc(a, p2, l);
            GlobalAlloc::dealloc(a, p3, l);
            let big = GlobalAlloc::alloc(a, Layout::from_size_align(3000, 16).unwrap());
            assert!(!big.is_null(), "adjacent frees should coalesce");
        }
    }

    #[test]
    fn honors_large_alignment() {
        let a = Box::leak(Box::new(StaticFreeList::<4096>::new()));
        unsafe {
            let p = GlobalAlloc::alloc(a, Layout::from_size_align(33, 256).unwrap());
            assert!(!p.is_null());
            assert_eq!(p as usize % 256, 0);
        }
    }

    #[test]
    fn tiny_tail_is_absorbed() {
        let a = Box::leak(Box::new(StaticFreeList::<2048>::new()));
        unsafe {
            let l1 = Layout::from_size_align(128, 16).unwrap();
            let l2 = Layout::from_size_align(256, 16).unwrap();
            let p1 = GlobalAlloc::alloc(a, l1);
            let p2 = GlobalAlloc::alloc(a, l2);
            let p3 = GlobalAlloc::alloc(a, l1);
            GlobalAlloc::dealloc(a, p2, l2);
            let refill_l = Layout::from_size_align(240, 16).unwrap();
            let refill = GlobalAlloc::alloc(a, refill_l);
            assert_eq!(refill, p2);
            GlobalAlloc::dealloc(a, refill, refill_l);
            GlobalAlloc::dealloc(a, p1, l1);
            GlobalAlloc::dealloc(a, p3, l1);
            let big = GlobalAlloc::alloc(a, Layout::from_size_align(1600, 16).unwrap());
            assert!(!big.is_null());
        }
    }
}
