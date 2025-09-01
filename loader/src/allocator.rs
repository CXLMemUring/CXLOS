// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![allow(static_mut_refs)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

use spin::Mutex;

// A very small, simple bump allocator suitable for the loader stage.
// - Single-grow, no deallocation (dealloc is a no-op)
// - Backed by a fixed-size static buffer in .bss, identity-mapped early
// - Thread-safe via a spin::Mutex (contention is negligible in the loader)

// 1 MiB loader heap should be ample for temporary Vec/alloc usage
const LOADER_HEAP_SIZE: usize = 1024 * 1024;

#[repr(align(64))]
struct Aligned<T>(T);

static mut HEAP: Aligned<[u8; LOADER_HEAP_SIZE]> = Aligned([0u8; LOADER_HEAP_SIZE]);
static OFFSET: Mutex<usize> = Mutex::new(0);

pub struct LoaderAllocator;

unsafe impl GlobalAlloc for LoaderAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = HEAP.0.as_ptr() as usize;
        let mut offset = OFFSET.lock();

        // Align current pointer
        let align_mask = layout.align().saturating_sub(1);
        let aligned = (base + *offset + align_mask) & !align_mask;
        let new_offset = aligned.checked_add(layout.size()).unwrap().saturating_sub(base);

        if new_offset <= LOADER_HEAP_SIZE {
            *offset = new_offset;
            aligned as *mut u8
        } else {
            null_mut()
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // No-op: the loader does not free temporary allocations
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: LoaderAllocator = LoaderAllocator;

#[alloc_error_handler]
fn oom(layout: Layout) -> ! {
    log::error!(
        "Loader OOM: size={} align={} (heap={} KiB)",
        layout.size(),
        layout.align(),
        LOADER_HEAP_SIZE / 1024
    );
    abort::abort()
}

