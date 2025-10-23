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
use mem::{PhysicalAddress, frame_alloc};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::backtrace::Backtrace;
use crate::device_tree::DeviceTree;
use crate::mem::bootstrap_alloc::BootstrapAllocator;
use crate::state::{CpuLocal, Global};

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

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn print_nibble_hex(n: u8) {
    let ch = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
    serial_out(ch);
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
    let boot_info = unsafe { &*(boot_info_ptr as *const BootInfo) };
    _rust_start_impl(cpuid, boot_info, boot_ticks)
}

fn _rust_start_impl(cpuid: usize, boot_info: &'static BootInfo, boot_ticks: u64) -> ! {
    // Early serial probe: write 'R' (0x52) to COM1 (0x3F8) to confirm entry
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x52\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // Debug: output 'H' before panic hook setup
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x48\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // FIXME: Temporarily disable panic hook on x86_64 as it's hanging
    // This might be due to TLS not being properly initialized or
    // panic_unwind2 having issues on x86_64
    #[cfg(not(target_arch = "x86_64"))]
    panic_unwind2::set_hook(|info| {
        tracing::error!("CPU {info}");

        // FIXME 32 seems adequate for unoptimized builds where the callstack can get quite deep
        //  but (at least at the moment) is absolute overkill for optimized builds. Sadly there
        //  is no good way to do conditional compilation based on the opt-level.
        const MAX_BACKTRACE_FRAMES: usize = 32;

        let backtrace = backtrace::__rust_end_short_backtrace(|| {
            Backtrace::<MAX_BACKTRACE_FRAMES>::capture().unwrap()
        });
        tracing::error!("{backtrace}");

        if backtrace.frames_omitted {
            tracing::warn!("Stack trace was larger than backtrace buffer, omitted some frames.");
        }
    });

    // Debug: output 'U' after panic hook setup (or skip on x86_64)
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x55\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // Unwinding expects at least one landing pad in the callstack, but capturing all unwinds that
    // bubble up to this point is also a good idea since we can perform some last cleanup and
    // print an error message.

    // Debug: output 'C' before catch_unwind
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x43\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // FIXME: On x86_64, skip the panic unwinding for now and call kmain directly
    #[cfg(target_arch = "x86_64")]
    {
        kmain(cpuid, boot_info, boot_ticks);
        arch::exit(0);
    }

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
}

fn kmain(cpuid: usize, boot_info: &'static BootInfo, boot_ticks: u64) {
    // Enter kmain
    // perform EARLY per-cpu, architecture-specific initialization
    // (e.g. resetting the FPU)
    arch::per_cpu_init_early();

    tracing::per_cpu_init_early(cpuid);

    // after tracing::per_cpu_init_early

    // before locate_device_tree

    let (fdt, fdt_region_phys) = locate_device_tree(boot_info);

    // after locate_device_tree

    // before RNG creation

    // FIXME: For now, use a hardcoded seed on x86_64 if boot_info seed might be invalid
    #[cfg(target_arch = "x86_64")]
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    #[cfg(not(target_arch = "x86_64"))]
    let mut rng = ChaCha20Rng::from_seed(boot_info.rng_seed);

    // before try_init_global

    let global = state::try_init_global(|| {
        // set up the basic functionality of the tracing subsystem as early as possible

        tracing::init_early();
        // after init_early

        // initialize a simple bump allocator for allocating memory before our virtual memory subsystem
        // is available
        let allocatable_memories = allocatable_memory_regions(boot_info);

        // FIXME: Skip tracing::info on x86_64 as it hangs
        #[cfg(not(target_arch = "x86_64"))]
        tracing::info!("allocatable memories: {:?}", allocatable_memories);

        let mut boot_alloc = BootstrapAllocator::new(&allocatable_memories);
        // after boot_alloc new

        // initializing the global allocator
        // before allocator::init
        allocator::init(&mut boot_alloc, boot_info);

        // after allocator::init

        // Test small allocation (silent)
        #[cfg(target_arch = "x86_64")]
        { let _ = alloc::vec::Vec::<u8>::with_capacity(16); }

        // before DeviceTree::parse
        // Handle device tree parsing - x86_64 doesn't need it, so just emit a marker
        #[cfg(target_arch = "x86_64")]
        let bootargs = {
            // stub DT

            bootargs::Bootargs {
                log: tracing::Filter::default(),
                backtrace: backtrace::BacktraceStyle::Short,
            }
        };

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
        backtrace::init(boot_info, bootargs.backtrace);
        // after backtrace::init

        // fully initialize the tracing subsystem now that we can allocate
        #[cfg(not(target_arch = "x86_64"))]
        {
            tracing::init(bootargs.log);
        }
        // On x86_64, skip tracing init to reach the shell quickly
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b't'); }

        // after tracing fully initialized
        // perform global, architecture-specific initialization
        let arch = arch::init();
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'^'); }

        // FAST PATH (x86_64): run a blocking serial console directly to ensure input works
        #[cfg(target_arch = "x86_64")]
        {
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
                    // wait for THRE
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

            use alloc::string::String;
            puts("\r\n> ");
            let mut line = String::new();
            loop {
                if let Some(b) = getb() {
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
                }
            }
        }

        // initialize the global frame allocator
        // at this point we have parsed and processed the flattened device tree, so we pass it to the
        // frame allocator for reuse
        let frame_alloc = frame_alloc::init(boot_alloc, fdt_region_phys);
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'~'); }

        // initialize the virtual memory subsystem
        mem::init(boot_info, &mut rng, frame_alloc).unwrap();
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'#'); }
        // after mem::init

        // initialize the filesystem
        // probe: 'I' before fs::init
        #[cfg(target_arch = "x86_64")]
        unsafe {
            serial_out(b'I');
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'.'); }
        fs::init().unwrap();
        // checkpoint: 'i' after fs::init
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'@'); }

        // Optionally initialize WASM BusyBox (requires prebuilt wasm + feature flag)
        if let Ok(true) = busybox::wasm_loader::try_init_wasm_busybox() {
            tracing::info!("Initialized WASM BusyBox module");
        } else {
            tracing::warn!("WASM BusyBox module not initialized");
        }
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'&'); }

        // perform LATE per-cpu, architecture-specific initialization
        // (e.g. setting the trap vector and enabling interrupts)
        #[cfg(target_arch = "x86_64")]
        let cpu = {
            // x86_64: Create a fake device tree just to satisfy the API
            // The x86_64 Cpu::new doesn't actually use it
            use device_tree::DeviceTree;

            // This is a horrible hack but necessary because DeviceTree uses ouroboros
            // and can't be easily created without Bump allocator
            // Since x86_64 Cpu::new ignores the device tree parameter anyway, we can pass garbage
            let fake_dt_ptr = 0x1234usize as *const DeviceTree;
            let fake_dt = unsafe { &*fake_dt_ptr };

            // This will work because x86_64 Cpu::new never dereferences the device tree
            arch::device::cpu::Cpu::new(fake_dt, cpuid)?
        };

        #[cfg(not(target_arch = "x86_64"))]
        let cpu = arch::device::cpu::Cpu::new(&device_tree, cpuid)?;

        let executor = Executor::with_capacity(boot_info.cpu_mask.count_ones() as usize).unwrap();
        let timer = Timer::new(Duration::from_millis(1), cpu.clock);

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
            let msg = err.to_string();
            unsafe {
                serial_out(b'!');
                for &byte in msg.as_bytes() {
                    serial_out(byte);
                }
            }
        }
        panic!("global init failed: {err:?}");
    });

    // Checkpoint after global init returned: 'C'
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x43\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // perform LATE per-cpu, architecture-specific initialization
    // (e.g. setting the trap vector and enabling interrupts)
    #[cfg(not(target_arch = "x86_64"))]
    let arch_state = arch::per_cpu_init_late(&global.device_tree, cpuid).unwrap();

    #[cfg(target_arch = "x86_64")]
    let arch_state = {
        // x86_64 per_cpu_init_late doesn't actually use device tree
        // Create a fake reference like before
        let fake_dt_ptr = 0x1234usize as *const DeviceTree;
        let fake_dt = unsafe { &*fake_dt_ptr };
        let st = arch::per_cpu_init_late(fake_dt, cpuid).unwrap();
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'%'); }
        st
    };

    state::init_cpu_local(CpuLocal {
        id: cpuid,
        arch: arch_state,
    });

    tracing::info!(
        "Booted in ~{:?} ({:?} in k23)",
        Instant::now(&global.timer).duration_since(Instant::ZERO),
        Instant::from_ticks(&global.timer, Ticks(boot_ticks)).elapsed(&global.timer)
    );

    let mut worker2 = Worker::new(&global.executor, FastRand::from_seed(rng.next_u64())).unwrap();

    cfg_if! {
        if #[cfg(test)] {
            if cpuid == 0 {
                arch::block_on(worker2.run(tests::run_tests(global))).unwrap().exit_if_failed();
            } else {
                arch::block_on(worker2.run(futures::future::pending::<()>())).unwrap_err(); // the only way `run` can return is when the executor is closed
            }
        } else {
            #[cfg(not(target_arch = "x86_64"))]
            shell::init(
                &global.device_tree,
                &global.executor,
                boot_info.cpu_mask.count_ones() as usize,
            );

            #[cfg(target_arch = "x86_64")]
            {
                // x86_64: shell::init doesn't actually use device tree
                // Create a fake reference like before
                let fake_dt_ptr = 0x1234usize as *const DeviceTree;
                let fake_dt = unsafe { &*fake_dt_ptr };
                // debug: entering shell::init
                #[cfg(target_arch = "x86_64")]
                unsafe { serial_out(b'>'); }
                shell::init(
                    fake_dt,
                    &global.executor,
                    boot_info.cpu_mask.count_ones() as usize,
                );
            }
            arch::block_on(worker2.run(futures::future::pending::<()>())).unwrap_err(); // the only way `run` can return is when the executor is closed
        }
    }
}

/// Builds a list of memory regions from the boot info that are usable for allocation.
///
/// The regions passed by the loader are guaranteed to be non-overlapping, but might not be
/// sorted and might not be optimally "packed". This function will both sort regions and
/// attempt to compact the list by merging adjacent regions.
fn allocatable_memory_regions(boot_info: &BootInfo) -> ArrayVec<Range<PhysicalAddress>, 16> {
    let temp: ArrayVec<Range<PhysicalAddress>, 16> = boot_info
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

fn locate_device_tree(boot_info: &BootInfo) -> (&'static [u8], Range<PhysicalAddress>) {
    let fdt = boot_info
        .memory_regions
        .iter()
        .find(|region| region.kind == MemoryRegionKind::FDT)
        .expect("no FDT region");

    let base = boot_info
        .physical_address_offset
        .checked_add(fdt.range.start)
        .unwrap() as *const u8;

    // Safety: we need to trust the bootinfo data is correct
    let slice =
        unsafe { slice::from_raw_parts(base, fdt.range.end.checked_sub(fdt.range.start).unwrap()) };
    (
        slice,
        Range::from(PhysicalAddress::new(fdt.range.start)..PhysicalAddress::new(fdt.range.end)),
    )
}
