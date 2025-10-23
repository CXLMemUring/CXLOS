// Copyright 2025 Jonas Kruckenberg
#![allow(static_mut_refs)]
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::alloc::{GlobalAlloc, Layout};
use core::range::Range;
use core::sync::atomic::Ordering;

use loader_api::BootInfo;
#[cfg(target_arch = "x86_64")]
use talc::locking::AssumeUnlockable;
use talc::{ErrOnOom, Span, Talc, Talck};

use crate::mem::bootstrap_alloc::BootstrapAllocator;
use crate::{INITIAL_HEAP_SIZE_PAGES, arch};

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn serial_out(byte: u8) {
    core::arch::asm!(
        "out dx, al",
        in("al") byte,
        in("dx") 0x3F8u16,
        options(nostack, preserves_flags)
    );
}

#[repr(align(64))]
struct Aligned<T>(core::mem::MaybeUninit<T>);

#[cfg(target_arch = "x86_64")]
type TalcLock = AssumeUnlockable;
#[cfg(not(target_arch = "x86_64"))]
type TalcLock = spin::RawMutex;

static mut TALC_STORAGE: Aligned<Talck<TalcLock, ErrOnOom>> =
    Aligned(core::mem::MaybeUninit::uninit());

pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let inner = &*TALC_STORAGE.0.as_ptr();
        GlobalAlloc::alloc(inner, layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let inner = &*TALC_STORAGE.0.as_ptr();
        GlobalAlloc::dealloc(inner, ptr, layout)
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

pub fn init(boot_alloc: &mut BootstrapAllocator, boot_info: &BootInfo) {
    // allocator::init
    let layout =
        Layout::from_size_align(INITIAL_HEAP_SIZE_PAGES * arch::PAGE_SIZE, arch::PAGE_SIZE)
            .unwrap();

    let phys = boot_alloc.allocate_contiguous(layout).unwrap();
    // after allocate_contiguous

    let virt = {
        // Force heap mapping into kernel higher half using arch constant base
        let base = arch::KERNEL_ASPACE_RANGE.start.get();
        let start = base.checked_add(phys.get()).unwrap();
        #[cfg(target_arch = "x86_64")]
        { let _ = base; let _ = start; }
        Range::from(start..start.checked_add(layout.size()).unwrap())
    };
    // silent
    // Build initial heap span
    let span = Span::from_base_size(
        virt.start as *mut u8,
        virt.end.checked_sub(virt.start).unwrap(),
    );

    // Sanity-check span mapping: touch first 64 bytes
    #[cfg(target_arch = "x86_64")]
    unsafe { core::ptr::write_bytes(virt.start as *mut u8, 0, 64); }

    // Safety: just allocated the memory region
    unsafe {
        // Initialize Talc instance in aligned storage and configure span
        // debug: 'T' before TALC_STORAGE write
        TALC_STORAGE
            .0
            .as_mut_ptr()
            .write(Talc::new(ErrOnOom).lock());
        
        // Instance is available; we avoid allocations until span configured below
        let talc = &*TALC_STORAGE.0.as_ptr();
        // debug: 'l' before lock
        let mut guard = talc.lock();
        
        let old_heap = guard.claim(span).unwrap();
        guard.extend(old_heap, span);
        
        // Heap configured
        
    }

    // FIXME: Skip tracing::debug on x86_64 as it may hang
    #[cfg(not(target_arch = "x86_64"))]
    tracing::debug!("Kernel Heap: {virt:#x?}");

    // leaving allocator::init
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn print_nibble_hex(n: u8) {
    let ch = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
    serial_out(ch);
}
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn print_u64_hex(mut v: u64) {
    for shift in (0..64).step_by(4).rev() {
        let nib = ((v >> shift) & 0xF) as u8;
        print_nibble_hex(nib);
    }
}
