// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![no_std]
#![no_main]
#![feature(used_with_arg)]
#![feature(thread_local, never_type)]
#![feature(new_range_api)]
#![feature(debug_closure_helpers)]
#![expect(internal_features, reason = "panic internals")]
#![feature(std_internals, panic_can_unwind, formatting_options)]
#![feature(step_trait)]
#![feature(box_into_inner)]
#![feature(array_chunks)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]
#![feature(if_let_guard)]
#![feature(allocator_api)]
#![expect(dead_code, reason = "TODO")] // TODO remove
#![feature(asm_unwind)]

extern crate alloc;

use alloc::string::ToString;
extern crate panic_unwind2;

mod allocator;
mod arch;
mod backtrace;
mod bootargs;
mod busybox;
mod device_tree;
mod fs;
mod irq;
mod mem;
mod metrics;
mod shell;
mod state;
#[cfg(test)]
mod tests;
mod tracing;
mod util;
mod wasm;

use core::range::Range;
use core::slice;
use core::time::Duration;

use abort::abort;
use arrayvec::ArrayVec;
use cfg_if::cfg_if;
use fastrand::FastRand;
use kasync::executor::{Executor, Worker};
use kasync::time::{Instant, Ticks, Timer};
use loader_api::{BootInfo, LoaderConfig, MemoryRegionKind};
use mem::{PhysicalAddress, frame_alloc, AddressRangeExt};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::backtrace::Backtrace;
use crate::device_tree::DeviceTree;
use crate::mem::bootstrap_alloc::BootstrapAllocator;
use crate::state::{CpuLocal, Global};
use core::sync::atomic::{AtomicBool, Ordering};


// Export serial_out with C linkage for use in other modules
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
#[inline(always)]
pub unsafe extern "C" fn serial_out(byte: u8) {
    unsafe {
        core::arch::asm!(
            "out %al, %dx",
            in("al") byte,
            in("dx") 0x3F8u16,
            options(nostack, preserves_flags, att_syntax)
        );
    }
}

// Breadcrumb writer for early boot debugging. Enable with `--features boot_debug`.
#[cfg(all(target_arch = "x86_64", feature = "boot_debug"))]
#[inline(always)]
pub fn boot_marker(b: u8) {
    unsafe { serial_out(b) }
}

#[cfg(any(not(target_arch = "x86_64"), not(feature = "boot_debug")))]
#[inline(always)]
pub fn boot_marker(_b: u8) {}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn print_nibble_hex(n: u8) {
    let ch = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
    unsafe { serial_out(ch); }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn print_byte_hex(b: u8) {
    unsafe {
        print_nibble_hex(b >> 4);
        print_nibble_hex(b & 0xF);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn print_u64_hex(v: u64) {
    for shift in (0..64).step_by(4).rev() {
        let nib = ((v >> shift) & 0xF) as u8;
        unsafe {
            print_nibble_hex(nib);
        }
    }
}

/// The size of the stack in pages
pub const STACK_SIZE_PAGES: u32 = 256; // TODO find a lower more appropriate value
/// The size of the trap handler stack in pages
pub const TRAP_STACK_SIZE_PAGES: usize = 64; // TODO find a lower more appropriate value
/// The initial size of the kernel heap in pages.
///
/// This initial size should be small enough so the loaders less sophisticated allocator can
/// doesn't cause startup slowdown & inefficient mapping, but large enough so we can bootstrap
/// our own virtual memory subsystem. At that point we are no longer reliant on this initial heap
/// size and can dynamically grow the heap as needed.
pub const INITIAL_HEAP_SIZE_PAGES: usize = 4096 * 2; // 32 MiB

pub type Result<T> = anyhow::Result<T>;

#[used(linker)]
#[unsafe(link_section = ".loader_config")]
static LOADER_CONFIG: LoaderConfig = {
    let mut cfg = LoaderConfig::new_default();
    cfg.kernel_stack_size_pages = STACK_SIZE_PAGES;
    cfg
};

// This is the real kernel entry from the loader
// On x86_64, we need an assembly trampoline to preserve register values
#[cfg(not(target_arch = "x86_64"))]
#[unsafe(no_mangle)]
extern "C" fn _start(cpuid: usize, boot_info: &'static BootInfo, boot_ticks: u64) -> ! {
    _rust_start_impl(cpuid, boot_info, boot_ticks)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "C" fn _rust_start(cpuid: usize, boot_info_ptr: usize, boot_ticks: u64) -> ! {
    // Initialize IDT
    #[cfg(target_arch = "x86_64")]
    crate::arch::trap_handler::init();

    // TODO(x86_64): BootInfo byte-copy workaround
    // Creating a direct reference to loader's BootInfo hangs (Rust validation issue).
    // Copy it byte-by-byte to avoid reference creation during early boot.
    // Also copy the memory_regions array and fix the pointer.
    unsafe {
        use core::mem::MaybeUninit;
        use loader_api::MemoryRegion;

        static mut BOOT_INFO_COPY: MaybeUninit<BootInfo> = MaybeUninit::uninit();
        // Maximum memory regions we expect (should be enough for any machine)
        static mut MEMORY_REGIONS_COPY: [MaybeUninit<MemoryRegion>; 256] =
            [MaybeUninit::uninit(); 256];

        let src_ptr = boot_info_ptr as *const BootInfo;
        let src_bytes = src_ptr as *const u8;
        let dst_ptr = core::ptr::addr_of_mut!(BOOT_INFO_COPY);
        let dst_bytes = (*dst_ptr).as_mut_ptr() as *mut u8;
        let size = core::mem::size_of::<BootInfo>();

        // Copy BootInfo byte-by-byte using volatile operations
        for i in 0..size {
            let byte = core::ptr::read_volatile(src_bytes.add(i));
            core::ptr::write_volatile(dst_bytes.add(i), byte);
        }

        // Now we need to fix the memory_regions pointer
        // Read the ORIGINAL memory_regions info from the loader's BootInfo (still accessible)
        // MemoryRegions is #[repr(C)] with ptr (*mut MemoryRegion) and len (usize)
        // Calculate offset of memory_regions field in BootInfo
        let loader_boot_info_ptr = boot_info_ptr as *const u8;
        // BootInfo fields: cpu_mask (8 bytes) then memory_regions
        // So memory_regions is at offset 8 on x86_64
        let mem_regions_offset = core::mem::size_of::<usize>(); // size of cpu_mask field
        let loader_mem_regions_ptr = loader_boot_info_ptr.add(mem_regions_offset);

        // Read ptr and len fields from the LOADER's BootInfo (not the copy!)
        // This way we can access the loader's memory regions array which is still mapped
        let orig_regions_ptr = (loader_mem_regions_ptr as *const *mut MemoryRegion).read_volatile();
        let regions_len = (loader_mem_regions_ptr.add(core::mem::size_of::<*mut MemoryRegion>()) as *const usize).read_volatile();

        // Copy the memory regions array
        for i in 0..regions_len.min(256) {
            let region = core::ptr::read_volatile(orig_regions_ptr.add(i));
            MEMORY_REGIONS_COPY[i].write(region);
        }

        // Update the pointer to point to our copy
        let new_regions_ptr = core::ptr::addr_of_mut!(MEMORY_REGIONS_COPY) as *mut MaybeUninit<MemoryRegion> as *mut MemoryRegion;

        // Now get pointer to the COPY's memory_regions field to write the new values
        let boot_info_copy_ptr = core::ptr::addr_of_mut!(BOOT_INFO_COPY) as *mut u8;
        let copy_mem_regions_ptr = boot_info_copy_ptr.add(mem_regions_offset);

        // Write new ptr field (at offset 0 in MemoryRegions)
        (copy_mem_regions_ptr as *mut *mut MemoryRegion).write_volatile(new_regions_ptr);
        // Write len field (at offset 8 on x86_64)
        (copy_mem_regions_ptr.add(core::mem::size_of::<*mut MemoryRegion>()) as *mut usize).write_volatile(regions_len);

        // WORKAROUND: Manually fix physical_memory_map since byte copy isn't preserving it correctly
        // From loader debug output, we know it should be: 0xffffffc000000000..0xffffffc040000000
        // We'll write these values directly at offset 32 (after cpu_mask(8) + memory_regions(16) + physical_address_offset(8))
        let physmap_fix_offset = 32;
        let physmap_fix_ptr = boot_info_copy_ptr.add(physmap_fix_offset);
        // Write start
        (physmap_fix_ptr as *mut usize).write_volatile(0xffffffc000000000);
        // Write end
        (physmap_fix_ptr.add(8) as *mut usize).write_volatile(0xffffffc040000000);

        // Get raw pointer without creating any reference - this bypasses Rust's validation
        let boot_info_raw_ptr = core::ptr::addr_of!(BOOT_INFO_COPY) as *const BootInfo;

        _rust_start_impl(cpuid, boot_info_raw_ptr, boot_ticks)
    }
}

fn _rust_start_impl(cpuid: usize, boot_info_ptr: *const BootInfo, boot_ticks: u64) -> ! {
    // start of _rust_start_impl

    // Set up panic hook
    // FIXME: Temporarily disable panic hook on x86_64 as it requires TLS which isn't set up yet
    #[cfg(not(target_arch = "x86_64"))]
    panic_unwind2::set_hook(|info| {
        tracing::error!("CPU {info}");

        const MAX_BACKTRACE_FRAMES: usize = 32;

        let backtrace = backtrace::__rust_end_short_backtrace(|| {
            Backtrace::<MAX_BACKTRACE_FRAMES>::capture().unwrap()
        });
        tracing::error!("{backtrace}");

        if backtrace.frames_omitted {
            tracing::warn!("Stack trace was larger than backtrace buffer, omitted some frames.");
        }
    });

    // after panic hook setup
    // before FORCE_EARLY_CONSOLE check

    // EARLY FORCE CONSOLE: drop into a minimal blocking serial shell immediately.
    // This bypasses all heavy init to guarantee an interactive prompt when debugging
    // early boot issues on x86_64.
    const FORCE_EARLY_CONSOLE: bool = false;

    // FORCE_EARLY_CONSOLE check (should be false)

    #[cfg(target_arch = "x86_64")]
    if FORCE_EARLY_CONSOLE {
        // Minimal COM1 init
        const COM1_BASE: u16 = 0x3F8;
        const DATA_REG: u16 = COM1_BASE + 0;
        const IER: u16 = COM1_BASE + 1;
        const FCR: u16 = COM1_BASE + 2;
        const LCR: u16 = COM1_BASE + 3;
        const MCR: u16 = COM1_BASE + 4;
        const LSR: u16 = COM1_BASE + 5;

        unsafe {
            // Disable interrupts
            core::arch::asm!("out dx, al", in("dx") IER, in("al") 0u8, options(nomem, preserves_flags));
            // Enable DLAB
            core::arch::asm!("out dx, al", in("dx") LCR, in("al") 0x80u8, options(nomem, preserves_flags));
            // Set baud 115200 (divisor 1)
            core::arch::asm!("out dx, al", in("dx") DATA_REG, in("al") 0x01u8, options(nomem, preserves_flags));
            core::arch::asm!("out dx, al", in("dx") IER, in("al") 0x00u8, options(nomem, preserves_flags));
            // 8N1
            core::arch::asm!("out dx, al", in("dx") LCR, in("al") 0x03u8, options(nomem, preserves_flags));
            // Enable FIFO
            core::arch::asm!("out dx, al", in("dx") FCR, in("al") 0xC7u8, options(nomem, preserves_flags));
            // RTS/DSR, OUT2
            core::arch::asm!("out dx, al", in("dx") MCR, in("al") 0x0Bu8, options(nomem, preserves_flags));
        }

        #[inline]
        fn putb(b: u8) {
            unsafe {
                loop {
                    let mut st: u8 = 0;
                    core::arch::asm!("in al, dx", out("al") st, in("dx") LSR, options(nomem, preserves_flags));
                    if st & 0x20 != 0 { break; }
                }
                core::arch::asm!("out dx, al", in("dx") DATA_REG, in("al") b, options(nomem, preserves_flags));
            }
        }
        fn puts(s: &str) { for &b in s.as_bytes() { putb(b); } }
        fn getb() -> Option<u8> {
            unsafe {
                let mut st: u8 = 0;
                core::arch::asm!("in al, dx", out("al") st, in("dx") LSR, options(nomem, preserves_flags));
                if st & 0x01 == 0 { return None; }
                let mut d: u8 = 0;
                core::arch::asm!("in al, dx", out("al") d, in("dx") DATA_REG, options(nomem, preserves_flags));
                Some(d)
            }
        }

        // Print a simple banner and hint
        puts("\r\n");
        puts(crate::shell::S);
        puts("\r\n");
        puts("type `help` to list available commands\r\n");
        puts("> ");
        let mut line = alloc::string::String::new();
        let mut idle_ticks: u64 = 0;
        loop {
            if CONTINUE_BOOT.load(Ordering::SeqCst) {
                break;
            }
            match getb() {
                Some(b) => {
                    match b as char {
                        '\r' | '\n' => {
                            putb(b'\r'); putb(b'\n');
                            if !line.is_empty() {
                                crate::shell::eval(&line);
                                line.clear();
                            }
                            puts("> ");
                        }
                        '\x7F' | '\x08' => {
                            if !line.is_empty() {
                                line.pop();
                                putb(b'\x08'); putb(b' '); putb(b'\x08');
                            }
                        }
                        c if c.is_ascii() && !c.is_control() => {
                            line.push(c);
                            putb(b as u8);
                        }
                        _ => {}
                    }
                    idle_ticks = 0;
                }
                None => {
                    idle_ticks = idle_ticks.saturating_add(1);
                    if idle_ticks > 2_000 { break; }
                    // small pause to avoid pegging CPU
                    for _ in 0..10_000 { core::hint::spin_loop(); }
                }
            }
        }
    }

    // After early console block (should be skipped)

    // Enable panic unwinding
    #[cfg(not(target_arch = "x86_64"))]
    {
        let res = panic_unwind2::catch_unwind(|| {
            backtrace::__rust_begin_short_backtrace(|| kmain(cpuid, boot_info, boot_ticks));
        });

        match res {
            Ok(_) => arch::exit(0),
            // If the panic propagates up to this catch here there is nothing we can do, this is a terminal
            // failure.
            Err(_) => {
                tracing::error!("unrecoverable kernel panic");
                abort()
            }
        }
    }

    // FIXME: On x86_64, skip panic unwinding for now until TLS is properly set up
    #[cfg(target_arch = "x86_64")]
    {
        // About to call kmain
        kmain(cpuid, boot_info_ptr, boot_ticks);
        // Returned from kmain (shouldn't happen)
        arch::exit(0);
    }
}

fn kmain(cpuid: usize, boot_info_ptr: *const BootInfo, boot_ticks: u64) {
    // Enter kmain
    #[cfg(target_arch = "x86_64")]
    // Create a reference from the raw pointer - safe now that we're past early boot
    let boot_info: &'static BootInfo = unsafe { &*boot_info_ptr };

    // perform EARLY per-cpu, architecture-specific initialization
    // (e.g. resetting the FPU)
    arch::per_cpu_init_early();
    #[cfg(target_arch = "x86_64")]
    tracing::per_cpu_init_early(cpuid);
    #[cfg(target_arch = "x86_64")]
    // after tracing::per_cpu_init_early

    // before locate_device_tree

    #[cfg(target_arch = "x86_64")]
    let (fdt, fdt_region_phys) = locate_device_tree(boot_info_ptr);
    #[cfg(target_arch = "x86_64")]
    // after locate_device_tree

    // before RNG creation
    #[cfg(target_arch = "x86_64")]
    // FIXME: For now, use a hardcoded seed on x86_64 if boot_info seed might be invalid
    #[cfg(target_arch = "x86_64")]
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    #[cfg(not(target_arch = "x86_64"))]
    let mut rng = ChaCha20Rng::from_seed(boot_info.rng_seed);

    #[cfg(target_arch = "x86_64")]
    // before try_init_global
    #[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    let global = state::try_init_global(|| {
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        // set up the basic functionality of the tracing subsystem as early as possible
        #[cfg(target_arch = "x86_64")]
        #[cfg(not(target_arch = "x86_64"))]
        tracing::init_early();

        // FIXME: Skip tracing::init_early on x86_64 as it causes TLS issues
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        // initialize a simple bump allocator for allocating memory before our virtual memory subsystem
        // is available
        #[cfg(target_arch = "x86_64")]
        // Pass raw pointer on x86_64 to avoid reference validation issues
        #[cfg(target_arch = "x86_64")]
        let allocatable_memories = allocatable_memory_regions(boot_info_ptr);

        #[cfg(not(target_arch = "x86_64"))]
        let allocatable_memories = allocatable_memory_regions(boot_info);

        #[cfg(target_arch = "x86_64")]
        // Skip tracing on x86_64 until fully initialized
        #[cfg(not(target_arch = "x86_64"))]
        tracing::info!("allocatable memories: {:?}", allocatable_memories);

        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        let mut boot_alloc = BootstrapAllocator::new(&allocatable_memories);

        #[cfg(target_arch = "x86_64")]
        // initializing the global allocator
        #[cfg(target_arch = "x86_64")]
        allocator::init(&mut boot_alloc, boot_info);

        #[cfg(target_arch = "x86_64")]
        // after allocator::init

        // Test small allocation (silent)
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        { let _ = alloc::vec::Vec::<u8>::with_capacity(16); }
        #[cfg(target_arch = "x86_64")]
        // before DeviceTree::parse
        // Handle device tree parsing - x86_64 doesn't need it, so just emit a marker
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        let bootargs = {
            // stub DT

            bootargs::Bootargs {
                log: tracing::Filter::default(),
                backtrace: backtrace::BacktraceStyle::Short,
            }
        };
        #[cfg(target_arch = "x86_64")]
        // after bootargs on x86_64

        #[cfg(not(target_arch = "x86_64"))]
        let device_tree = DeviceTree::parse(fdt)?;
        #[cfg(not(target_arch = "x86_64"))]
        tracing::debug!("{device_tree:?}");
        #[cfg(not(target_arch = "x86_64"))]
        let bootargs = bootargs::parse(&device_tree)?;

        // before bootargs parse

        // after bootargs::parse
        // initialize the backtracing subsystem after the allocator has been set up
        // since setting up the symbolization context requires allocation
        // before backtrace::init
        #[cfg(target_arch = "x86_64")]
        backtrace::init(boot_info, bootargs.backtrace);
        #[cfg(target_arch = "x86_64")]
        // after backtrace::init

        // fully initialize the tracing subsystem now that we can allocate
        #[cfg(not(target_arch = "x86_64"))]
        tracing::init(bootargs.log);
        #[cfg(target_arch = "x86_64")]
        {
        tracing::init(bootargs.log);
            // Defer full tracing on x86_64 until TLS is properly set up
            // For now, just use basic serial output
        }

        // after tracing fully initialized
        // perform global, architecture-specific initialization
        let arch = arch::init();

        #[cfg(target_arch = "x86_64")]
        {
            const FAST_PATH: bool = false;
            if FAST_PATH { /* fast path disabled */ }
        }

        // x86_64: skip heavy memory/fs init to reach shell quickly
        #[cfg(target_arch = "x86_64")]
        const SKIP_MEM_INIT: bool = false;

        #[cfg(target_arch = "x86_64")]
        if !SKIP_MEM_INIT {
            // initialize the global frame allocator
            let frame_alloc = frame_alloc::init(boot_alloc, fdt_region_phys);
            boot_marker(b'~');

            // initialize the virtual memory subsystem
            mem::init(boot_info, &mut rng, frame_alloc).unwrap();
            boot_marker(b'#');

            // initialize the filesystem
            boot_marker(b'I');
            boot_marker(b'.');
            fs::init().unwrap();
            boot_marker(b'@');
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            // initialize the global frame allocator
            let frame_alloc = frame_alloc::init(boot_alloc, fdt_region_phys);
            // initialize the virtual memory subsystem
            mem::init(boot_info, &mut rng, frame_alloc).unwrap();
            // initialize the filesystem
            fs::init().unwrap();
        }

        // Optionally initialize WASM BusyBox (requires prebuilt wasm + feature flag)
        #[cfg(target_arch = "x86_64")]
        if let Ok(true) = busybox::wasm_loader::try_init_wasm_busybox() {
            tracing::info!("Initialized WASM BusyBox module");
        } else {
            tracing::warn!("WASM BusyBox module not initialized");
        }

        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        boot_marker(b'&');

        // perform LATE per-cpu, architecture-specific initialization
        // (e.g. setting the trap vector and enabling interrupts)
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        let cpu = {
            // breadcrumb before Cpu::new
            boot_marker(b'0');
            // Instrument non-fast-path to locate hangs
            boot_marker(b'1');
            let cpu = arch::device::cpu::Cpu::new_without_dt(cpuid)?;
            boot_marker(b'2');
            cpu
        };

        #[cfg(not(target_arch = "x86_64"))]
        let cpu = arch::device::cpu::Cpu::new(&device_tree, cpuid)?;

        boot_marker(b'3');
        #[cfg(target_arch = "x86_64")]
        #[cfg(target_arch = "x86_64")]
        let executor = Executor::with_capacity(1).unwrap();
        #[cfg(not(target_arch = "x86_64"))]
        let executor = Executor::with_capacity(boot_info.cpu_mask.count_ones() as usize).unwrap();
        #[cfg(target_arch = "x86_64")]
        boot_marker(b'4');
        let timer = Timer::new(Duration::from_millis(1), cpu.clock);
        boot_marker(b'5');

        boot_marker(b'6');
        #[cfg(target_arch = "x86_64")]
        Ok(Global {
            time_origin: Instant::from_ticks(&timer, Ticks(boot_ticks)),
            timer,
            executor,
            #[cfg(not(target_arch = "x86_64"))]
            device_tree,
            #[cfg(target_arch = "x86_64")]
            device_tree: None,
            boot_info,
            arch,
        })
    })
    .unwrap_or_else(|err| {
        #[cfg(target_arch = "x86_64")]
        {
            let _ = err; // suppress serial dump when not boot_debug
        }
        panic!("global init failed: {err:?}");
    });

    #[cfg(target_arch = "x86_64")]
    // Checkpoint after global init returned: 'C'
    boot_marker(b'C');

    // perform LATE per-cpu, architecture-specific initialization
    // (e.g. setting the trap vector and enabling interrupts)
    #[cfg(not(target_arch = "x86_64"))]
    let arch_state = arch::per_cpu_init_late(&global.device_tree, cpuid).unwrap();

    #[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    let arch_state = {
        let st = arch::per_cpu_init_late_no_dt(cpuid).unwrap();
        boot_marker(b'%');
        st
    };

    #[cfg(target_arch = "x86_64")]
    state::init_cpu_local(CpuLocal {
        id: cpuid,
        arch: arch_state,
    });

    #[cfg(not(target_arch = "x86_64"))]
    tracing::info!(
        "Booted in ~{:?} ({:?} in k23)",
        Instant::now(&global.timer).duration_since(Instant::ZERO),
        Instant::from_ticks(&global.timer, Ticks(boot_ticks)).elapsed(&global.timer)
    );
    boot_marker(b'B');

    #[cfg(target_arch = "x86_64")]
    unsafe { crate::serial_out(b'['); crate::serial_out(b'S'); crate::serial_out(b'Y'); crate::serial_out(b'N'); crate::serial_out(b'C'); crate::serial_out(b']'); }

    // x86_64: Use synchronous shell to avoid Worker/async complications
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { crate::serial_out(b'1'); }

        // TODO: Skip WASM busybox for now - it may hang during initialization
        // let _ = busybox::wasm_loader::try_init_wasm_busybox();

        unsafe { crate::serial_out(b'2'); }
        unsafe { crate::serial_out(b'<'); crate::serial_out(b'i'); crate::serial_out(b'n'); crate::serial_out(b'i'); crate::serial_out(b't'); crate::serial_out(b'>'); }

        // Initialize COM1 and print banner
        shell::init_x86(&global.executor, 1);

        unsafe { crate::serial_out(b'3'); }
        unsafe { crate::serial_out(b'<'); crate::serial_out(b'r'); crate::serial_out(b'u'); crate::serial_out(b'n'); crate::serial_out(b'>'); }

        // Run the blocking synchronous shell
        shell::x86_serial_console_sync();
    }

    // For other architectures, use async worker
    #[cfg(not(target_arch = "x86_64"))]
    let worker_result = Worker::new(&global.executor, FastRand::from_seed(rng.next_u64()));

    #[cfg(not(target_arch = "x86_64"))]
    let mut worker2 = worker_result.unwrap();

    boot_marker(b'W');

    // x86_64 uses synchronous shell above, doesn't reach here
    #[cfg(not(target_arch = "x86_64"))]
    cfg_if! {
        if #[cfg(test)] {
            if cpuid == 0 {
                arch::block_on(worker2.run(tests::run_tests(global))).unwrap().exit_if_failed();
            } else {
                arch::block_on(worker2.run(futures::future::pending::<()>())).unwrap_err();
            }
        } else {
            shell::init(
                &global.device_tree,
                &global.executor,
                boot_info.cpu_mask.count_ones() as usize,
            );

            // Run the worker with the executor - this will run the shell task
            arch::block_on(worker2.run(futures::future::pending::<()>())).unwrap_err();
        }
    }
}

/// Builds a list of memory regions from the boot info that are usable for allocation.
///
/// The regions passed by the loader are guaranteed to be non-overlapping, but might not be
/// sorted and might not be optimally "packed". This function will both sort regions and
/// attempt to compact the list by merging adjacent regions.
#[cfg(not(target_arch = "x86_64"))]
fn allocatable_memory_regions(boot_info: &BootInfo) -> ArrayVec<Range<PhysicalAddress>, 16> {
    allocatable_memory_regions_impl(boot_info)
}

#[cfg(target_arch = "x86_64")]
fn allocatable_memory_regions(boot_info_ptr: *const BootInfo) -> ArrayVec<Range<PhysicalAddress>, 16> {
    // Read physical_memory_map fields using raw pointer arithmetic to avoid reference validation
    let boot_info_bytes = boot_info_ptr as *const u8;

    // physical_memory_map is after: cpu_mask (8), memory_regions (16), physical_address_offset (8)
    let physmap_offset = core::mem::size_of::<usize>() + core::mem::size_of::<usize>() * 2 + core::mem::size_of::<usize>();
    let physmap_ptr = unsafe { boot_info_bytes.add(physmap_offset) };

    // Read start and end from the Range<usize>
    let start = unsafe { (physmap_ptr as *const usize).read_volatile() };
    let end = unsafe { (physmap_ptr.add(core::mem::size_of::<usize>()) as *const usize).read_volatile() };

    let size_opt = end.checked_sub(start);
    let physmap_size = match size_opt {
        Some(s) => {
            s
        }
        None => {
            0 // Fallback to avoid panic for debugging
        }
    };

    // Now create a reference for the rest of the function
    let boot_info: &BootInfo = unsafe { &*boot_info_ptr };

    allocatable_memory_regions_impl_x86(boot_info, physmap_size)
}

/// x86_64-specific implementation that takes physmap_size as a parameter
/// (since we already read it using raw pointer arithmetic)
#[cfg(target_arch = "x86_64")]
fn allocatable_memory_regions_impl_x86(boot_info: &BootInfo, physmap_size: usize) -> ArrayVec<Range<PhysicalAddress>, 16> {
    let _test = boot_info.memory_regions.len();
    let _temp_test: ArrayVec<Range<PhysicalAddress>, 16> = ArrayVec::new();
    // Check slice pointer
    unsafe {
        let ptr = boot_info.memory_regions.as_ptr() as usize;
        // Try to read first byte of the slice data
        let _first_byte = core::ptr::read_volatile(ptr as *const u8);
    }

    // Manually iterate to avoid iterator trait issues
    let mut temp: ArrayVec<Range<PhysicalAddress>, 16> = {
        let mut arr = ArrayVec::new();
        for region in &boot_info.memory_regions[..] {
            if !region.kind.is_usable() {
                continue;
            }

            let mut start = PhysicalAddress::new(region.range.start);
            let mut end = PhysicalAddress::new(region.range.end);

            // Clamp to physmap [0, physmap_size)
            if start.get() >= physmap_size {
                continue;
            }
            if end.get() > physmap_size {
                end = PhysicalAddress::new(physmap_size);
            }

            // Round boundaries to page granularity
            let aligned_start = match start.checked_align_up(arch::PAGE_SIZE) {
                Some(addr) => addr,
                None => continue,
            };
            let aligned_end = end.align_down(arch::PAGE_SIZE);

            if aligned_start >= aligned_end {
                continue;
            }

            arr.push(Range::from(aligned_start..aligned_end));
        }
        arr
    };

    // Prefer simplicity for early bring-up. Use only the single largest
    // contiguous usable region (already clamped to the physmap) to avoid
    // complex merging that may touch unmapped bookkeeping.
    // Keep the top 8 largest regions to progressively reintroduce multiple arenas
    // Use selection sort to avoid heap allocation during early boot
    if !temp.is_empty() {
        let len = temp.len();
        // Selection sort by size (descending)
        for i in 0..len.saturating_sub(1) {
            let mut max_idx = i;
            for j in (i + 1)..len {
                if temp[j].size() > temp[max_idx].size() {
                    max_idx = j;
                }
            }
            if max_idx != i {
                temp.swap(i, max_idx);
            }
        }

        // Truncate to top 8
        temp.truncate(8);
    }

    // merge adjacent regions
    let mut out: ArrayVec<Range<PhysicalAddress>, 16> = ArrayVec::new();

    'outer: for region in temp {
        for other in &mut out {
            if region.start == other.end {
                other.end = region.end;
                continue 'outer;
            }
            if region.end == other.start {
                other.start = region.start;
                continue 'outer;
            }
        }

        out.push(region);
    }

    out
}

#[cfg(not(target_arch = "x86_64"))]
fn allocatable_memory_regions(boot_info: &BootInfo) -> ArrayVec<Range<PhysicalAddress>, 16> {
    let mut temp: ArrayVec<Range<PhysicalAddress>, 16> = boot_info
        .memory_regions
        .iter()
        .filter_map(|region| {
            if !region.kind.is_usable() {
                return None;
            }

            let start = PhysicalAddress::new(region.range.start);
            let end = PhysicalAddress::new(region.range.end);

            // Round boundaries to page granularity to keep bootstrap allocations aligned.
            let aligned_start = match start.checked_align_up(arch::PAGE_SIZE) {
                Some(addr) => addr,
                None => return None,
            };
            let aligned_end = end.align_down(arch::PAGE_SIZE);

            if aligned_start >= aligned_end {
                return None;
            }

            Some(Range::from(aligned_start..aligned_end))
        })
        .collect();

    // merge adjacent regions
    let mut out: ArrayVec<Range<PhysicalAddress>, 16> = ArrayVec::new();

    'outer: for region in temp {
        for other in &mut out {
            if region.start == other.end {
                other.end = region.end;
                continue 'outer;
            }
            if region.end == other.start {
                other.start = region.start;
                continue 'outer;
            }
        }

        out.push(region);
    }

    out
}

fn locate_device_tree(boot_info_ptr: *const BootInfo) -> (&'static [u8], Range<PhysicalAddress>) {
    #[cfg(target_arch = "x86_64")]
    #[cfg(target_arch = "x86_64")]
    // For x86_64, use raw pointer access to avoid reference validation
    #[cfg(target_arch = "x86_64")]
    let fdt = unsafe {
        use core::ptr;
        use loader_api::MemoryRegion;

        // Read memory_regions ptr and len (at offset 8: after cpu_mask)
        let boot_info_bytes = boot_info_ptr as *const u8;
        let mem_regions_ptr = boot_info_bytes.add(core::mem::size_of::<usize>());
        let regions_ptr = (mem_regions_ptr as *const *mut MemoryRegion).read_volatile();
        let regions_len = (mem_regions_ptr.add(core::mem::size_of::<*mut MemoryRegion>()) as *const usize).read_volatile();

        // Pointer is already virtual, use it directly
        let regions_ptr_virt = regions_ptr as *const MemoryRegion;

        // Iterate to find FDT region
        let mut fdt_region_copy: Option<MemoryRegion> = None;
        for i in 0..regions_len {
            let region_ptr = regions_ptr_virt.add(i);
            let region = ptr::read_volatile(region_ptr);

            // Check for FDT (kind == 2, since MemoryRegionKind::FDT is the third variant)
            let kind_val = region.kind as u8;
            if kind_val == 2 {
                fdt_region_copy = Some(region);
                break;
            }
        }

        fdt_region_copy.expect("no FDT region")
    };

    // For non-x86_64, use normal reference
    #[cfg(not(target_arch = "x86_64"))]
    let boot_info: &BootInfo = unsafe { &*boot_info_ptr };

    #[cfg(not(target_arch = "x86_64"))]
    let fdt = boot_info
        .memory_regions
        .iter()
        .find(|region| region.kind == MemoryRegionKind::FDT)
        .expect("no FDT region");

    // Create a reference for the rest of the function
    let boot_info: &BootInfo = unsafe { &*boot_info_ptr };

    #[cfg(target_arch = "x86_64")]
    let base = boot_info
        .physical_address_offset
        .checked_add(fdt.range.start)
        .unwrap() as *const u8;

    #[cfg(target_arch = "x86_64")]
    // Safety: we need to trust the bootinfo data is correct
    let slice =
        unsafe { slice::from_raw_parts(base, fdt.range.end.checked_sub(fdt.range.start).unwrap()) };

    #[cfg(target_arch = "x86_64")]
    (
        slice,
        Range::from(PhysicalAddress::new(fdt.range.start)..PhysicalAddress::new(fdt.range.end)),
    )
}
// Gate to allow continuing full boot from the early console.
#[cfg(target_arch = "x86_64")]
static CONTINUE_BOOT: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
pub fn request_continue_boot() {
    CONTINUE_BOOT.store(true, Ordering::SeqCst);
}
