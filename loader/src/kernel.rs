// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::error::Error;
use core::fmt::Formatter;
use core::range::Range;
use core::{fmt, slice};
use loader_api::LoaderConfig;
use xmas_elf::program::{ProgramHeader, Type};

/// The inlined kernel
static INLINED_KERNEL_BYTES: KernelBytes = KernelBytes(*include_bytes!(env!("KERNEL")));
/// Wrapper type for the inlined bytes to ensure proper alignment
#[repr(C, align(4096))]
struct KernelBytes(pub [u8; include_bytes!(env!("KERNEL")).len()]);

/// The decompressed and parsed kernel ELF plus the embedded loader configuration data
pub struct Kernel<'a> {
    pub elf_file: xmas_elf::ElfFile<'a>,
    pub _loader_config: &'a LoaderConfig,
}

impl Kernel<'static> {
    pub fn from_static(phys_off: usize) -> crate::Result<Self> {
        // Safety: The kernel elf file is inlined into the loader executable as part of the build setup
        // which means we just need to parse it here.
        let elf_file = xmas_elf::ElfFile::new(unsafe {
            let base = phys_off
                .checked_add(INLINED_KERNEL_BYTES.0.as_ptr().addr())
                .unwrap();

            slice::from_raw_parts(base as *mut u8, INLINED_KERNEL_BYTES.0.len())
        })
        .map_err(Error::Elf)?;

        let loader_config = {
            let section = elf_file
                .find_section_by_name(".loader_config")
                .expect("missing .loader_config section");
            let raw = section.raw_data(&elf_file);

            let ptr: *const LoaderConfig = raw.as_ptr().cast();
            // Safety: kernel is inlined into the loader, so ptr is always valid
            let cfg = unsafe { &*ptr };

            cfg.assert_valid();
            cfg
        };

        Ok(Kernel {
            elf_file,
            _loader_config: loader_config,
        })
    }
}

impl Kernel<'_> {
    pub fn phys_range(&self) -> Range<usize> {
        let fdt = INLINED_KERNEL_BYTES.0.as_ptr_range();
        Range::from(fdt.start as usize..fdt.end as usize)
    }

    /// Returns the size of the kernel in memory.
    pub fn mem_size(&self) -> u64 {
        let max_addr = self
            .loadable_program_headers()
            .map(|ph| ph.virtual_addr() + ph.mem_size())
            .max()
            .unwrap_or(0);

        let min_addr = self
            .loadable_program_headers()
            .map(|ph| ph.virtual_addr())
            .min()
            .unwrap_or(0);

        max_addr - min_addr
    }

    /// Returns the largest alignment of any loadable segment in the kernel and by extension
    /// the overall alignment for the kernel.
    pub fn max_align(&self) -> u64 {
        let load_program_headers = self.loadable_program_headers();

        load_program_headers.map(|ph| ph.align()).max().unwrap_or(1)
    }

    fn loadable_program_headers(&self) -> impl Iterator<Item = ProgramHeader<'_>> + '_ {
        self.elf_file
            .program_iter()
            .filter(|ph| ph.get_type().unwrap() == Type::Load)
    }
}

impl fmt::Display for Kernel<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Idx Name              Offset   Vaddr            Filesz   Memsz"
        )?;

        for (idx, sec) in self.elf_file.section_iter().enumerate() {
            writeln!(
                f,
                "{idx:>3} {name:<17} {offset:#08x} {vaddr:#016x} {filesz:#08x} {memsz:#08x}",
                name = sec.get_name(&self.elf_file).unwrap_or(""),
                offset = sec.offset(),
                vaddr = sec.address(),
                filesz = sec.entry_size(),
                memsz = sec.size(),
            )?;
        }
        Ok(())
    }
}
