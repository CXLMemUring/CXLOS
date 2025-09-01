// Copyright 2025 Jonas Kruckenberg
#![allow(static_mut_refs)]
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{Ordering};
use core::range::Range;

use loader_api::BootInfo;
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

static mut TALC_STORAGE: Aligned<Talck<spin::RawMutex, ErrOnOom>> =
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
    // debug: 'C' entering allocator::init
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x43\n\
             out dx, al",
            options(nostack, preserves_flags)
        );
    }
    let layout =
        Layout::from_size_align(INITIAL_HEAP_SIZE_PAGES * arch::PAGE_SIZE, arch::PAGE_SIZE)
            .unwrap();

    let phys = boot_alloc.allocate_contiguous(layout).unwrap();
    // debug: 'H' after allocate_contiguous
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x48\n\
             out dx, al",
            options(nostack, preserves_flags)
        );
    }

    let virt = {
        // Force heap mapping into kernel higher half using arch constant base
        let base = arch::KERNEL_ASPACE_RANGE.start.get();
        let start = base.checked_add(phys.get()).unwrap();
        #[cfg(target_arch = "x86_64")]
        unsafe {
            serial_out(b'B'); print_u64_hex(base as u64);
            serial_out(b'S'); print_u64_hex(start as u64);
        }
        Range::from(start..start.checked_add(layout.size()).unwrap())
    };
    // debug: print phys map range and addresses
    #[cfg(target_arch = "x86_64")]
    unsafe {
        serial_out(b'M');
        serial_out(b's'); print_u64_hex(boot_info.physical_memory_map.start as u64);
        serial_out(b'e'); print_u64_hex(boot_info.physical_memory_map.end as u64);
        serial_out(b'v'); print_u64_hex(virt.start as u64);
        serial_out(b'p'); print_u64_hex(phys.get() as u64);
        serial_out(b'l'); print_u64_hex(layout.size() as u64);
        serial_out(b'V');
    }
    // Build initial heap span
    let span = Span::from_base_size(
        virt.start as *mut u8,
        virt.end.checked_sub(virt.start).unwrap(),
    );

    // Sanity-check span mapping: touch first 64 bytes
    #[cfg(target_arch = "x86_64")]
    unsafe {
        serial_out(b'w');
        core::ptr::write_bytes(virt.start as *mut u8, 0, 64);
        serial_out(b'W');
    }

    // Safety: just allocated the memory region
    unsafe {
        // Initialize Talc instance in aligned storage and configure span
        // debug: 'T' before TALC_STORAGE write
        #[cfg(target_arch = "x86_64")]
        serial_out(b'T');
        TALC_STORAGE.0.as_mut_ptr().write(Talc::new(ErrOnOom).lock());
        #[cfg(target_arch = "x86_64")]
        serial_out(b't');
        // Instance is available; we avoid allocations until span configured below
        let talc = &*TALC_STORAGE.0.as_ptr();
        // debug: 'l' before lock
        #[cfg(target_arch = "x86_64")]
        serial_out(b'l');
        let mut guard = talc.lock();
        // debug: 'L' after lock
        #[cfg(target_arch = "x86_64")]
        serial_out(b'L');
        let old_heap = guard.claim(span).unwrap();
        // debug: 'j' after claim
        #[cfg(target_arch = "x86_64")]
        serial_out(b'j');
        guard.extend(old_heap, span);
        // debug: 'k' after extend
        #[cfg(target_arch = "x86_64")]
        serial_out(b'k');
        // Heap configured
        #[cfg(target_arch = "x86_64")]
        serial_out(b'r');
        #[cfg(target_arch = "x86_64")]
        serial_out(b'R');
    }

    tracing::debug!("Kernel Heap: {virt:#x?}");
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn print_nibble_hex(n: u8) { let ch = if n < 10 { b'0' + n } else { b'a' + (n - 10) }; serial_out(ch); }
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn print_u64_hex(mut v: u64) {
    for shift in (0..64).step_by(4).rev() {
        let nib = ((v >> shift) & 0xF) as u8; print_nibble_hex(nib);
    }
}
    // debug: 'Z' leaving allocator::init
    #[cfg(target_arch = "x86_64")]
    unsafe {
        serial_out(b'Z');
    }
}
