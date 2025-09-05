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

use alloc::format;
extern crate panic_unwind2;

mod allocator;
mod arch;
mod backtrace;
mod bootargs;
mod device_tree;
mod irq;
mod mem;
mod metrics;
mod shell;
mod busybox;
mod fs;
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
        unsafe { print_nibble_hex(nib); }
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
    // Early checkpoint: 'A'
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x41\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }
    // perform EARLY per-cpu, architecture-specific initialization
    // (e.g. resetting the FPU)
    arch::per_cpu_init_early();

    tracing::per_cpu_init_early(cpuid);

    // checkpoint: 'p' after tracing::per_cpu_init_early
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x70\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // checkpoint: 'D' before locate_device_tree
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x44\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    let (fdt, fdt_region_phys) = locate_device_tree(boot_info);

    // checkpoint: 'd' after locate_device_tree
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x64\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // checkpoint: 'r' before RNG creation
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x72\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // FIXME: For now, use a hardcoded seed on x86_64 if boot_info seed might be invalid
    #[cfg(target_arch = "x86_64")]
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    
    #[cfg(not(target_arch = "x86_64"))]
    let mut rng = ChaCha20Rng::from_seed(boot_info.rng_seed);

    // checkpoint: 'G' before try_init_global
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8\n\
             mov al, 0x47\n\
             out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    let global = state::try_init_global(|| {
        // set up the basic functionality of the tracing subsystem as early as possible

        tracing::init_early();
        // checkpoint: 'a' after init_early
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8\n\
                 mov al, 0x61\n\
                 out dx, al",
                options(nomem, nostack, preserves_flags)
            );
        }

        // initialize a simple bump allocator for allocating memory before our virtual memory subsystem
        // is available
        let allocatable_memories = allocatable_memory_regions(boot_info);

        // FIXME: Skip tracing::info on x86_64 as it hangs
        #[cfg(not(target_arch = "x86_64"))]
        tracing::info!("allocatable memories: {:?}", allocatable_memories);

        let mut boot_alloc = BootstrapAllocator::new(&allocatable_memories);
        // checkpoint: 'b' after boot_alloc new
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8\n\
                 mov al, 0x62\n\
                 out dx, al",
                options(nomem, nostack, preserves_flags)
            );
        }

        // initializing the global allocator
        // checkpoint: 'I' before allocator::init
        #[cfg(target_arch = "x86_64")]
        unsafe {
            serial_out(b'I');
        }
        allocator::init(&mut boot_alloc, boot_info);

        // checkpoint: 'c' after allocator::init  
        #[cfg(target_arch = "x86_64")]
        unsafe {
            serial_out(b'c');
        }
        
        // Test that allocator is working with a small allocation
        #[cfg(target_arch = "x86_64")]
        {
            use alloc::vec::Vec;
            unsafe { serial_out(b'v'); }
            let test_vec = Vec::<u8>::with_capacity(16);
            unsafe { serial_out(b'V'); }
            drop(test_vec);
            unsafe { serial_out(b'!'); }
        }
        
        // checkpoint: 'x' before DeviceTree::parse
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8\n\
                 mov al, 0x78\n\
                 out dx, al",
                options(nomem, nostack, preserves_flags)
            );
        }
        // Handle device tree parsing - x86_64 doesn't need it
        #[cfg(target_arch = "x86_64")]
        let bootargs = {
            match DeviceTree::parse(fdt) {
                Ok(dt) => {
                    unsafe { serial_out(b'd'); }
                    bootargs::parse(&dt)?
                }
                Err(e) if format!("{:?}", e).contains("x86_64 stub") => {
                    // Expected error for x86_64, use default bootargs
                    unsafe { serial_out(b'E'); }
                    bootargs::Bootargs {
                        log: tracing::Filter::default(),
                        backtrace: backtrace::BacktraceStyle::Short,
                    }
                }
                Err(e) => {
                    // Unexpected error
                    return Err(e);
                }
            }
        };
        
        // checkpoint: '+' after bootargs on x86_64
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'+'); }
        
        #[cfg(not(target_arch = "x86_64"))]
        let device_tree = DeviceTree::parse(fdt)?;
        #[cfg(not(target_arch = "x86_64"))]
        tracing::debug!("{device_tree:?}");
        #[cfg(not(target_arch = "x86_64"))]
        let bootargs = bootargs::parse(&device_tree)?;
        
        // checkpoint: '=' before 'e' output
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'='); }
        
        // checkpoint: 'e' after bootargs::parse
        #[cfg(target_arch = "x86_64")]
        unsafe {
            serial_out(b'e');
        }
        // initialize the backtracing subsystem after the allocator has been set up
        // since setting up the symbolization context requires allocation
        // probe: 'F' before backtrace::init
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'F'); }
        backtrace::init(boot_info, bootargs.backtrace);
        // checkpoint: 'f' after backtrace::init
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'f'); }

        // fully initialize the tracing subsystem now that we can allocate
        tracing::init(bootargs.log);
        // checkpoint: 'B' already printed elsewhere; add 'g'
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8\n\
                 mov al, 0x67\n\
                 out dx, al",
                options(nomem, nostack, preserves_flags)
            );
        }

        // Checkpoint after tracing fully initialized: 'B'
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8\n\
                 mov al, 0x42\n\
                 out dx, al",
                options(nomem, nostack, preserves_flags)
            );
        }
        // perform global, architecture-specific initialization
        let arch = arch::init();

        // initialize the global frame allocator
        // at this point we have parsed and processed the flattened device tree, so we pass it to the
        // frame allocator for reuse
        let frame_alloc = frame_alloc::init(boot_alloc, fdt_region_phys);

        // initialize the virtual memory subsystem
        mem::init(boot_info, &mut rng, frame_alloc).unwrap();
        // checkpoint: 'h' after mem::init
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "mov dx, 0x3F8\n\
                 mov al, 0x68\n\
                 out dx, al",
                options(nomem, nostack, preserves_flags)
            );
        }

        // initialize the filesystem
        // probe: 'I' before fs::init
        #[cfg(target_arch = "x86_64")]
        unsafe {
            serial_out(b'I');
            // Deep instrumentation: print address and first 16 bytes of fs::init
            let fn_ptr = fs::init as usize;
            serial_out(b'P');
            print_u64_hex(fn_ptr as u64);
            serial_out(b':');
            let mut i = 0;
            while i < 16 {
                let byte = *(fn_ptr as *const u8).add(i);
                print_byte_hex(byte);
                i += 1;
            }
            serial_out(b'p');
        }
        fs::init().unwrap();
        // checkpoint: 'i' after fs::init
        #[cfg(target_arch = "x86_64")]
        unsafe { serial_out(b'i'); }

        // Optionally initialize WASM BusyBox (requires prebuilt wasm + feature flag)
        if let Ok(true) = busybox::wasm_loader::try_init_wasm_busybox() {
            tracing::info!("Initialized WASM BusyBox module");
        } else {
            tracing::warn!("WASM BusyBox module not initialized");
        }

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
    .unwrap();

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
        arch::per_cpu_init_late(fake_dt, cpuid).unwrap()
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
            let range = Range::from(
                PhysicalAddress::new(region.range.start)..PhysicalAddress::new(region.range.end),
            );

            region.kind.is_usable().then_some(range)
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
