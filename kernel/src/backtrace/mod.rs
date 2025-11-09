// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

mod print;
mod symbolize;

use core::str::FromStr;
use core::{fmt, slice};

use arrayvec::ArrayVec;
use fallible_iterator::FallibleIterator;
use loader_api::BootInfo;
use symbolize::SymbolizeContext;
use unwind2::FrameIter;

use crate::backtrace::print::BacktraceFmt;
use crate::mem::VirtualAddress;

// x86_64 workaround: OnceLock's spinlock hangs during early boot
#[cfg(not(target_arch = "x86_64"))]
use spin::OnceLock;
#[cfg(not(target_arch = "x86_64"))]
static BACKTRACE_INFO: OnceLock<BacktraceInfo> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
static mut BACKTRACE_INFO_X86: Option<BacktraceInfo> = None;

#[cfg(all(target_arch = "x86_64", feature = "boot_debug"))]
#[inline(always)]
unsafe fn serial_out(byte: u8) {
    core::arch::asm!(
        "out dx, al",
        in("al") byte,
        in("dx") 0x3F8u16,
        options(nostack, preserves_flags)
    );
}

// Helper function to get backtrace info on x86_64
#[cfg(target_arch = "x86_64")]
fn get_backtrace_info() -> Option<&'static BacktraceInfo> {
    unsafe {
        let ptr = core::ptr::addr_of!(BACKTRACE_INFO_X86);
        (*ptr).as_ref()
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn get_backtrace_info() -> Option<&'static BacktraceInfo> {
    BACKTRACE_INFO.get()
}

#[cold]
pub fn init(boot_info: &'static BootInfo, backtrace_style: BacktraceStyle) {
    // debug: 'F' entering backtrace::init
    #[cfg(target_arch = "x86_64")]
    unsafe {
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        BACKTRACE_INFO.get_or_init(|| BacktraceInfo::new(boot_info, backtrace_style));
    }

    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 workaround: skip backtrace initialization during early boot
        // TODO: investigate why BacktraceInfo::new causes null pointer dereferences
        unsafe {
        }
        let _ = boot_info;
        let _ = backtrace_style;
    }

    // debug: 'f' leaving backtrace::init
    #[cfg(target_arch = "x86_64")]
    unsafe {
    }
}

/// Information about the kernel required to build a backtrace
struct BacktraceInfo {
    /// The base virtual address of the kernel ELF. ELF debug info expects zero-based addresses,
    /// but the kernel is located at some address in the higher half. This offset is used to convert
    /// between the two.
    kernel_virt_base: u64,
    /// The memory of our own ELF
    elf: &'static [u8],
    /// The actual state required for converting addresses into symbols. This is *very* heavy to
    /// compute though, so we only construct it lazily in [`BacktraceInfo::symbolize_context`].
    #[cfg(not(target_arch = "x86_64"))]
    symbolize_context: OnceLock<SymbolizeContext<'static>>,
    #[cfg(target_arch = "x86_64")]
    symbolize_context: core::cell::UnsafeCell<Option<SymbolizeContext<'static>>>,
    backtrace_style: BacktraceStyle,
}

#[derive(Debug)]
pub struct UnknownBacktraceStyleError;

#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub enum BacktraceStyle {
    #[default]
    Short,
    Full,
}

#[derive(Clone)]
pub struct Backtrace<'a, const MAX_FRAMES: usize> {
    symbolize_ctx: Option<&'a SymbolizeContext<'static>>,
    pub frames: ArrayVec<usize, MAX_FRAMES>,
    pub frames_omitted: bool,
    style: BacktraceStyle,
}

// === impl BacktraceInfo ===

impl BacktraceInfo {
    fn new(boot_info: &'static BootInfo, backtrace_style: BacktraceStyle) -> Self {
        // debug: '1' entering BacktraceInfo::new
        #[cfg(target_arch = "x86_64")]
        unsafe {
        }
        BacktraceInfo {
            kernel_virt_base: boot_info.kernel_virt.start as u64,
            // Safety: we have to trust the loaders BootInfo here
            elf: unsafe {
                // Prefer high-half mapping via physical memory map when available
                let base = if boot_info.physical_address_offset != 0 {
                    boot_info
                        .physical_address_offset
                        .checked_add(boot_info.kernel_phys.start)
                        .unwrap()
                } else {
                    boot_info
                        .physical_memory_map
                        .start
                        .checked_add(boot_info.kernel_phys.start)
                        .unwrap()
                } as *const u8;
                // debug: '2' after computing ELF base
                #[cfg(target_arch = "x86_64")]

                #[cfg(target_arch = "x86_64")]

                let result = slice::from_raw_parts(
                    base,
                    boot_info
                        .kernel_phys
                        .end
                        .checked_sub(boot_info.kernel_phys.start)
                        .unwrap(),
                );

                #[cfg(target_arch = "x86_64")]

                result
            },
            #[cfg(not(target_arch = "x86_64"))]
            symbolize_context: OnceLock::new(),
            #[cfg(target_arch = "x86_64")]
            symbolize_context: core::cell::UnsafeCell::new(None),
            backtrace_style,
        }
    }

    fn symbolize_context(&self) -> &SymbolizeContext<'static> {
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.symbolize_context.get_or_init(|| {
                tracing::debug!("Setting up symbolize context...");

                let elf = xmas_elf::ElfFile::new(self.elf).unwrap();
                SymbolizeContext::new(elf, self.kernel_virt_base).unwrap()
            })
        }

        #[cfg(target_arch = "x86_64")]
        unsafe {
            let ptr = self.symbolize_context.get();
            if (*ptr).is_none() {
                tracing::debug!("Setting up symbolize context...");
                let elf = xmas_elf::ElfFile::new(self.elf).unwrap();
                *ptr = Some(SymbolizeContext::new(elf, self.kernel_virt_base).unwrap());
            }
            (*ptr).as_ref().unwrap()
        }
    }
}

// === impl Backtrace ===

impl<const MAX_FRAMES: usize> Backtrace<'_, MAX_FRAMES> {
    /// Captures a backtrace at the callsite of this function, returning an owned representation.
    ///
    /// The returned object is almost entirely self-contained. It can be cloned, or send to other threads.
    ///
    /// Note that this step is quite cheap, contrary to the `Backtrace` implementation in the standard
    /// library this resolves the symbols (the expensive step) lazily, so this struct can be constructed
    /// in performance sensitive codepaths and only later resolved.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`unwind2::Error`] if walking the stack fails.
    #[inline]
    pub fn capture() -> Result<Self, unwind2::Error> {
        Self::new_inner(FrameIter::new())
    }

    /// Constructs a backtrace from the provided register context, returning an owned representation.
    ///
    /// The returned object is almost entirely self-contained. It can be cloned, or send to other threads.
    ///
    /// Note that this step is quite cheap, contrary to the `Backtrace` implementation in the standard
    /// library this resolves the symbols (the expensive step) lazily, so this struct can be constructed
    /// in performance sensitive codepaths and only later resolved.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`unwind2::Error`] if walking the stack fails.
    #[inline]
    pub fn from_registers(
        regs: unwind2::Registers,
        pc: VirtualAddress,
    ) -> Result<Self, unwind2::Error> {
        let iter = FrameIter::from_registers(regs, pc.get());
        Self::new_inner(iter)
    }

    fn new_inner(iter: FrameIter) -> Result<Self, unwind2::Error> {
        let mut frames = ArrayVec::new();

        let mut iter = iter.take(MAX_FRAMES);

        while let Some(frame) = iter.next()? {
            frames.try_push(frame.ip()).unwrap();
        }
        let frames_omitted = iter.next()?.is_some();

        Ok(Self {
            symbolize_ctx: get_backtrace_info().map(|info| info.symbolize_context()),
            frames,
            frames_omitted,
            style: get_backtrace_info()
                .map(|info| info.backtrace_style)
                .unwrap_or_default(),
        })
    }
}

impl<const MAX_FRAMES: usize> fmt::Display for Backtrace<'_, MAX_FRAMES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "stack backtrace:")?;

        let style = if f.alternate() {
            BacktraceStyle::Full
        } else {
            self.style
        };

        let mut bt_fmt = BacktraceFmt::new(f, style);

        let mut omitted_count: usize = 0;
        let mut first_omit = true;
        // If we're using a short backtrace, ignore all frames until we're told to start printing.
        let mut print = style != BacktraceStyle::Short;

        for ip in &self.frames {
            let mut any = false; // did we print any symbols?

            // if the symbolication state isn't setup, yet we can't print symbols the addresses will have
            // to suffice...
            if let Some(symbolize_ctx) = self.symbolize_ctx {
                let mut syms = symbolize_ctx.resolve_unsynchronized(*ip as u64).unwrap();

                while let Some(sym) = syms.next().unwrap() {
                    any = true;
                    // `__rust_end_short_backtrace` means we are done hiding symbols
                    // for now. Print until we see `__rust_begin_short_backtrace`.
                    if style == BacktraceStyle::Short
                        && let Some(sym) = sym.name().map(|s| s.as_raw_str())
                    {
                        if sym.contains("__rust_end_short_backtrace") {
                            print = true;
                            break;
                        }
                        if print && sym.contains("__rust_begin_short_backtrace") {
                            print = false;
                            break;
                        }
                        if !print {
                            omitted_count += 1;
                        }
                    }

                    if print {
                        if omitted_count > 0 {
                            debug_assert!(style == BacktraceStyle::Short);
                            // only print the message between the middle of frames
                            if !first_omit {
                                let _ = writeln!(
                                    bt_fmt.formatter(),
                                    "      [... omitted {} frame{} ...]",
                                    omitted_count,
                                    if omitted_count > 1 { "s" } else { "" }
                                );
                            }
                            first_omit = false;
                            omitted_count = 0;
                        }
                        bt_fmt.frame().print_symbol(*ip, sym)?;
                    }
                }
            } else {
                // no symbolize context always means no symbols
                any = false;
            }

            if !any && print {
                bt_fmt.frame().print_raw(*ip)?;
            }
        }

        if style == BacktraceStyle::Short {
            writeln!(
                f,
                "note: Some details are omitted, \
             run with `backtrace=full` bootarg for a verbose backtrace."
            )?;
        }
        if self.symbolize_ctx.is_none() {
            writeln!(
                f,
                "note: backtrace subsystem wasn't initialized, no symbols were printed."
            )?;
        }

        Ok(())
    }
}

// === impl BacktraceStyle ===

impl FromStr for BacktraceStyle {
    type Err = UnknownBacktraceStyleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "short" => Ok(BacktraceStyle::Short),
            "full" => Ok(BacktraceStyle::Full),
            _ => Err(UnknownBacktraceStyleError),
        }
    }
}

impl fmt::Display for UnknownBacktraceStyleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "unknown backtrace style")
    }
}

impl core::error::Error for UnknownBacktraceStyleError {}

/// Fixed frame used to clean the backtrace with `backtrace=short`.
#[inline(never)]
pub fn __rust_begin_short_backtrace<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let result = f();

    // prevent this frame from being tail-call optimised away
    core::hint::black_box(());

    result
}

/// Fixed frame used to clean the backtrace with `backtrace=short`.
#[inline(never)]
pub fn __rust_end_short_backtrace<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let result = f();

    // prevent this frame from being tail-call optimised away
    core::hint::black_box(());

    result
}
