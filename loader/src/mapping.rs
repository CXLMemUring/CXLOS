// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::alloc::Layout;
use core::num::NonZeroUsize;
use core::range::Range;
use core::{cmp, ptr, slice};

use bitflags::bitflags;
use fallible_iterator::FallibleIterator;
use loader_api::TlsTemplate;
use xmas_elf::P64;
use xmas_elf::dynamic::Tag;
use xmas_elf::program::{SegmentData, Type};
use xmas_elf::sections;

use crate::error::Error;
use crate::frame_alloc::FrameAllocator;
use crate::kernel::Kernel;
use crate::machine_info::MachineInfo;
use crate::page_alloc::PageAllocator;
use crate::{SelfRegions, arch};

bitflags! {
    #[derive(Debug, Copy, Clone, PartialEq)]
    pub struct Flags: u8 {
        const READ = 1 << 0;
        const WRITE = 1 << 1;
        const EXECUTE = 1 << 2;
    }
}

pub fn identity_map_self(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    self_regions: &SelfRegions,
) -> crate::Result<()> {
    log::trace!(
        "Identity mapping loader executable region {:#x?}...",
        self_regions.executable
    );
    identity_map_range(
        root_pgtable,
        frame_alloc,
        self_regions.executable,
        Flags::READ | Flags::EXECUTE,
    )?;

    log::trace!(
        "Identity mapping loader read-only region {:#x?}...",
        self_regions.read_only
    );
    identity_map_range(
        root_pgtable,
        frame_alloc,
        self_regions.read_only,
        Flags::READ,
    )?;

    log::trace!(
        "Identity mapping loader read-write region {:#x?}...",
        self_regions.read_write
    );
    identity_map_range(
        root_pgtable,
        frame_alloc,
        self_regions.read_write,
        Flags::READ | Flags::WRITE,
    )?;

    Ok(())
}

#[inline]
fn identity_map_range(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    phys: Range<usize>,
    flags: Flags,
) -> crate::Result<()> {
    // Align to page boundaries
    let aligned_start = align_down(phys.start, arch::PAGE_SIZE);
    let aligned_end = checked_align_up(phys.end, arch::PAGE_SIZE).unwrap();
    let len = NonZeroUsize::new(aligned_end.checked_sub(aligned_start).unwrap()).unwrap();

    // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
    // abort startup anyway
    unsafe {
        arch::map_contiguous(
            root_pgtable,
            frame_alloc,
            aligned_start,
            aligned_start,
            len,
            flags,
            0, // called before translation into higher half
        )
    }
}

pub fn map_physical_memory(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    page_alloc: &mut PageAllocator,
    minfo: &MachineInfo,
) -> crate::Result<(usize, Range<usize>)> {
    let alignment = arch::page_size_for_level(2);

    let phys = minfo.memory_hull();
    let phys = Range::from(
        align_down(phys.start, alignment)..checked_align_up(phys.end, alignment).unwrap(),
    );

    let virt = Range::from(
        arch::KERNEL_ASPACE_BASE.checked_add(phys.start).unwrap()
            ..arch::KERNEL_ASPACE_BASE.checked_add(phys.end).unwrap(),
    );
    let size = NonZeroUsize::new(phys.end.checked_sub(phys.start).unwrap()).unwrap();

    debug_assert!(phys.start.is_multiple_of(alignment) && phys.end.is_multiple_of(alignment));
    debug_assert!(virt.start.is_multiple_of(alignment) && virt.end.is_multiple_of(alignment));

    log::trace!("Mapping physical memory {phys:#x?} => {virt:#x?}...");
    // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
    // abort startup anyway
    unsafe {
        arch::map_contiguous(
            root_pgtable,
            frame_alloc,
            virt.start,
            phys.start,
            size,
            Flags::READ | Flags::WRITE,
            0, // called before translation into higher half
        )?;
    }

    // exclude the physical memory map region from page allocation
    page_alloc.reserve(virt.start, size.get());

    Ok((arch::KERNEL_ASPACE_BASE, virt))
}

pub fn map_kernel(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    page_alloc: &mut PageAllocator,
    kernel: &Kernel,
    minfo: &MachineInfo,
    phys_off: usize,
) -> crate::Result<(Range<usize>, Option<TlsAllocation>)> {
    // Determine if the kernel is linked-at-VA (high canonical VAs) or PIE/relocatable
    let mut min_vaddr = usize::MAX;
    let mut max_vaddr = 0usize;
    for ph in kernel.elf_file.program_iter() {
        let mem = usize::try_from(ph.mem_size()).unwrap_or(0);
        let align = usize::try_from(ph.align()).unwrap_or(1);
        if mem == 0 || align < crate::arch::PAGE_SIZE { continue; }
        let v = usize::try_from(ph.virtual_addr()).unwrap_or(0);
        min_vaddr = core::cmp::min(min_vaddr, v);
        max_vaddr = core::cmp::max(max_vaddr, v.saturating_add(mem));
    }

    let linked_at_va = min_vaddr >= arch::KERNEL_ASPACE_BASE;
    let (kernel_virt, virt_base_for_map) = if linked_at_va {
        // Map directly at the kernel's linked virtual addresses
        let start = align_down(min_vaddr, usize::try_from(kernel.max_align())?);
        let end = checked_align_up(max_vaddr, usize::try_from(kernel.max_align())?).unwrap();
        let range = Range::from(start..end);
        log::trace!("map_kernel: Linked-at-VA. Using direct virtual range {:#x?}", range);
        (range, 0usize)
    } else {
        // Allocate a virtual base for the image and map segments relative to it
        let range = page_alloc
            .allocate(
                Layout::from_size_align(
                    usize::try_from(kernel.mem_size())?,
                    usize::try_from(kernel.max_align())?,
                )
                .unwrap(),
            );
        log::trace!("map_kernel: PIE image. Allocated virtual range {:#x?}", range);
        (range, range.start)
    };

    log::trace!("map_kernel: Getting phys_base");
    let phys_base = if cfg!(target_arch = "x86_64") {
        // On x86_64, the kernel ELF is accessed through identity mapping
        kernel.elf_file.input.as_ptr() as usize
    } else if cfg!(target_arch = "riscv64") {
        // On RISC-V, the kernel ELF is accessed through physical memory mapping
        kernel.elf_file.input.as_ptr() as usize - arch::KERNEL_ASPACE_BASE
    } else {
        panic!("Unsupported architecture");
    };

    log::trace!("map_kernel: phys_base={:#x}", phys_base);
    assert!(
        phys_base.is_multiple_of(arch::PAGE_SIZE),
        "Loaded ELF file is not sufficiently aligned"
    );

    let mut maybe_tls_allocation = None;

    // Compute the effective entry VA for mapping (linked-at-VA vs PIE)
    let elf_entry = usize::try_from(kernel.elf_file.header.pt2.entry_point())?;
    let entry_va = if linked_at_va { elf_entry } else { virt_base_for_map.checked_add(elf_entry).unwrap() };

    // Load the segments into virtual memory.
    for raw_ph in kernel.elf_file.program_iter() {
        let ph = ProgramHeader::try_from(raw_ph)?;

        // Prefer TLS detection using section flags to avoid false positives
        if is_tls_segment(&ph, &kernel.elf_file) {
            let old = maybe_tls_allocation.replace(handle_tls_segment(
                root_pgtable,
                frame_alloc,
                page_alloc,
                &ph,
                virt_base_for_map,
                phys_base,
                minfo,
                phys_off,
            )?);
            log::trace!("TLS detected in segment vaddr={:#x} size={:#x}", ph.virtual_address, ph.mem_size);
            if old.is_some() {
                log::warn!("Multiple TLS segments detected; ignoring subsequent ones");
            }
            continue;
        }

        // LOAD-like detection: page-aligned and has memory size
        if ph.mem_size > 0 && ph.align >= arch::PAGE_SIZE {
            // Determine if this segment contains the chosen entry; if so, force EXEC
            let seg_start = virt_base_for_map.checked_add(ph.virtual_address).unwrap();
            let seg_end = seg_start.checked_add(ph.mem_size).unwrap();
            let force_exec = entry_va >= seg_start && entry_va < seg_end;
            handle_load_segment(
                root_pgtable,
                frame_alloc,
                &ph,
                phys_base,
                virt_base_for_map,
                phys_off,
                force_exec,
            )?;
            continue;
        }
    }

    // Apply relocations in virtual memory (via .dynamic section)
    // Use virt_base_for_map so RELA offsets are interpreted correctly:
    //  - linked-at-VA: base 0, RELA gives absolute VA
    //  - PIE: base = allocated image start, RELA gives image-relative VA
    handle_dynamic_relocations(&kernel.elf_file, virt_base_for_map, phys_base, phys_off)?;

    //     // Mark some memory regions as read-only after relocations have been
    //     // applied.
    //     for ph in kernel.elf_file.program_iter() {
    //         if ph.get_type().unwrap() == Type::GnuRelro {
    //             handle_relro_segment(
    //                 aspace,
    //                 &ProgramHeader::try_from(ph).unwrap(),
    //                 kernel_virt.start,
    //                 flush,
    //             )?;
    //         }
    //     }

    Ok((kernel_virt, maybe_tls_allocation))
}

/// Map an ELF LOAD segment.
fn handle_load_segment(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    ph: &ProgramHeader,
    phys_base: usize,
    virt_base: usize,
    phys_off: usize,
    force_exec: bool,
) -> crate::Result<()> {
    let mut flags = flags_for_segment(ph);
    if force_exec {
        flags |= Flags::EXECUTE;
    }

    log::trace!(
        "Handling Segment: LOAD off {offset:#016x} vaddr {vaddr:#016x} align {align} filesz {filesz:#016x} memsz {memsz:#016x} flags {flags:?}",
        offset = ph.offset,
        vaddr = ph.virtual_address,
        align = ph.align,
        filesz = ph.file_size,
        memsz = ph.mem_size
    );

    // Map file-backed bytes page-accurately to avoid over-aligning physical source
    // which could point at unrelated data. Use 4KiB alignment for both sides.
    let phys = {
        let start = phys_base.checked_add(ph.offset).unwrap();
        let end = start.checked_add(ph.file_size).unwrap();
        Range::from(align_down(start, arch::PAGE_SIZE)..checked_align_up(end, arch::PAGE_SIZE).unwrap())
    };

    let virt = {
        // If virt_base==0 we are mapping at linked VA; otherwise map at PIE base
        let start = virt_base.checked_add(ph.virtual_address).unwrap();
        let end = start.checked_add(ph.file_size).unwrap();
        Range::from(align_down(start, arch::PAGE_SIZE)..checked_align_up(end, arch::PAGE_SIZE).unwrap())
    };

    log::trace!("mapping {virt:#x?} => {phys:#x?}");
    // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
    // abort startup anyway
    unsafe {
        arch::map_contiguous(
            root_pgtable,
            frame_alloc,
            virt.start,
            phys.start,
            NonZeroUsize::new(phys.end.checked_sub(phys.start).unwrap()).unwrap(),
            flags,
            arch::KERNEL_ASPACE_BASE,
        )?;
    }

    if ph.file_size < ph.mem_size {
        handle_bss_section(
            root_pgtable,
            frame_alloc,
            ph,
            flags,
            phys_base,
            virt_base,
            phys_off,
        )?;
    }

    Ok(())
}

/// BSS sections are special, since they take up virtual memory that is not present in the "physical" elf file.
///
/// Usually, this means just allocating zeroed frames and mapping them "in between" the pages
/// backed by the elf file. However, quite often the boundary between DATA and BSS sections is
/// *not* page aligned (since that would unnecessarily bloat the elf file) which means for us
/// that we need special handling for the last DATA page that is only partially filled with data
/// and partially filled with zeroes. Here's how we do this:
///
/// 1. We calculate the size of the segments zero initialized part.
/// 2. We then figure out whether the boundary is page-aligned or if there are DATA bytes we need to account for.
///    2.1. IF there are data bytes to account for, we allocate a zeroed frame,
///    2.2. we then copy over the relevant data from the DATA section into the new frame
///    2.3. and lastly replace last page previously mapped by `handle_load_segment` to stitch things up.
/// 3. If the BSS section is larger than that one page, we allocate additional zeroed frames and map them in.
fn handle_bss_section(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    ph: &ProgramHeader,
    flags: Flags,
    phys_base: usize,
    virt_base: usize,
    phys_off: usize,
) -> crate::Result<()> {
    // If virt_base==0 we are mapping at linked VA; otherwise map at PIE base
    let virt_start = virt_base.checked_add(ph.virtual_address).unwrap();
    let zero_start = virt_start.checked_add(ph.file_size).unwrap();
    let zero_end = virt_start.checked_add(ph.mem_size).unwrap();

    let data_bytes_before_zero = zero_start & 0xfff;

    log::trace!(
        "handling BSS {:#x?}, data bytes before {data_bytes_before_zero}",
        zero_start..zero_end
    );

    if data_bytes_before_zero != 0 {
        let last_page = align_down(
            virt_start
                .checked_add(ph.file_size.saturating_sub(1))
                .unwrap(),
            arch::PAGE_SIZE,
        );
        let last_frame = align_down(
            phys_base.checked_add(ph.offset + ph.file_size - 1).unwrap(),
            arch::PAGE_SIZE,
        );

        let new_frame = frame_alloc.allocate_one_zeroed(arch::KERNEL_ASPACE_BASE)?;

        // Safety: we just allocated the frame
        unsafe {
            // Access both source and destination via the mapped physical window at phys_off
            let src = slice::from_raw_parts(
                phys_off.checked_add(last_frame).unwrap() as *const u8,
                data_bytes_before_zero,
            );
            let dst = slice::from_raw_parts_mut(
                phys_off.checked_add(new_frame).unwrap() as *mut u8,
                data_bytes_before_zero,
            );

            log::trace!("copying {data_bytes_before_zero} bytes from {src:p} to {dst:p}...");
            ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), dst.len());
        }

        // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
        // abort startup anyway
        unsafe {
            arch::remap_contiguous(
                root_pgtable,
                last_page,
                new_frame,
                NonZeroUsize::new(arch::PAGE_SIZE).unwrap(),
                phys_off,
            );
        }
    }

    log::trace!("zero_start {zero_start:#x} zero_end {zero_end:#x}");
    let (mut virt, len) = {
        // zero_start either lies at a page boundary OR somewhere within the first page
        // by aligning up, we move it to the beginning of the *next* page.
        let start = checked_align_up(zero_start, arch::PAGE_SIZE).unwrap();
        let end = checked_align_up(zero_end, arch::PAGE_SIZE).unwrap();
        (start, end.checked_sub(start).unwrap())
    };

    if len > 0 {
        let mut phys_iter = frame_alloc.allocate_zeroed(
            Layout::from_size_align(len, arch::PAGE_SIZE).unwrap(),
            arch::KERNEL_ASPACE_BASE,
        );

        while let Some((phys, len)) = phys_iter.next()? {
            log::trace!(
                "mapping additional zeros {virt:#x}..{:#x}",
                virt.checked_add(len.get()).unwrap()
            );

            // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
            // abort startup anyway
            unsafe {
                arch::map_contiguous(
                    root_pgtable,
                    phys_iter.alloc(),
                    virt,
                    phys,
                    len,
                    flags,
                    arch::KERNEL_ASPACE_BASE,
                )?;
            }

            virt += len.get();
        }
    }

    Ok(())
}

fn handle_dynamic_relocations(
    elf_file: &xmas_elf::ElfFile,
    virt_base: usize,
    phys_base: usize,
    phys_off: usize,
) -> crate::Result<()> {
    log::trace!("parsing RELA info via .dynamic section...");

    if let Some(rela_info) = parse_rela_from_dynamic_section(elf_file)? {
        log::trace!(
            "RELA table: vaddr={:#x} count={} entsize={}",
            rela_info.offset,
            rela_info.count,
            rela_info.entry_size
        );
        // Access RELA entries via the already mapped virtual image
        // RELA tag gives a virtual address; our image is mapped at virt_base
        let rela_vaddr = usize::try_from(rela_info.offset)?;
        let relas_ptr = virt_base.checked_add(rela_vaddr).unwrap() as *const u8;

        // Compute the maximum valid virtual address range for the image from PT_LOAD segments
        let image_limit = {
            let mut max_end = 0usize;
            for prog_header in elf_file.program_iter() {
                let seg_vaddr = usize::try_from(prog_header.virtual_addr()).unwrap_or(0);
                let seg_memsz = usize::try_from(prog_header.mem_size()).unwrap_or(0);
                max_end = core::cmp::max(max_end, seg_vaddr.saturating_add(seg_memsz));
            }
            max_end
        };

        // Collect LOAD-like segments for VA->PA translation for file-backed bytes
        // tuple: (seg_vaddr, seg_offset, seg_filesz)
        let mut load_segments: alloc::vec::Vec<(usize, usize, usize)> = alloc::vec::Vec::new();
        for ph in elf_file.program_iter() {
            let filesz = usize::try_from(ph.file_size()).unwrap_or(0);
            let memsz = usize::try_from(ph.mem_size()).unwrap_or(0);
            let align = usize::try_from(ph.align()).unwrap_or(1);
            if memsz == 0 || align < crate::arch::PAGE_SIZE { continue; }
            let vaddr = usize::try_from(ph.virtual_addr()).unwrap_or(0);
            let off = usize::try_from(ph.offset()).unwrap_or(0);
            load_segments.push((vaddr, off, filesz));
        }

        // Manually parse RELA entries from the mapped bytes to avoid alignment/aliasing issues.
        // Entry size is provided by dynamic tag (RelaEnt)
        let count = usize::try_from(rela_info.count)?;
        let entry_size = usize::try_from(rela_info.entry_size)?;
        let total_len = count * entry_size;
        let bytes = unsafe { core::slice::from_raw_parts(relas_ptr, total_len) };
        if total_len >= 24 {
            // Dump first entry raw words for diagnostics
            let w0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
            let w1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
            let w2 = if entry_size >= 24 {
                u64::from_le_bytes(bytes[16..24].try_into().unwrap())
            } else {
                0
            };
            log::trace!(
                "RELA[0] raw: w0(off)={:#x} w1={:#x} w2={:#x}",
                w0,
                w1,
                w2
            );
        }

        #[derive(Copy, Clone)]
        struct Reloc { rtype: u32, offset: usize, addend: isize }
        let mut to_apply: alloc::vec::Vec<Reloc> = alloc::vec::Vec::with_capacity(count);

        for i in 0..count {
            let off = i * entry_size;
            // Bounds check to prevent out-of-bounds reads
            let end = off + entry_size;
            if end > bytes.len() {
                log::error!(
                    "RELA entry {} out of bounds: off={:#x} end={:#x} len={:#x}",
                    i,
                    off,
                    end,
                    bytes.len()
                );
                break;
            }

            // Manual little-endian decoding to avoid memcpy precondition traps
            let mut read_u64 = |p: usize| -> u64 {
                let mut v = 0u64;
                let b = &bytes[p..p + 8];
                v |= b[0] as u64;
                v |= (b[1] as u64) << 8;
                v |= (b[2] as u64) << 16;
                v |= (b[3] as u64) << 24;
                v |= (b[4] as u64) << 32;
                v |= (b[5] as u64) << 40;
                v |= (b[6] as u64) << 48;
                v |= (b[7] as u64) << 56;
                v
            };
            let mut read_i64 = |p: usize| -> i64 { read_u64(p) as i64 };

            // The standard x86_64 Rela64 layout is 24 bytes: offset(8), info(8), addend(8).
            // Some linkers may report a different entry size; we still assume the same field order.
            let mut r_offset = read_u64(off);
            let mut r_info = read_u64(off + 8);
            let mut r_addend = read_i64(off + 16);

            // Primary interpretation: [offset][info][addend]
            let mut rtype = (r_info & 0xFFFF_FFFF) as u32; // type in low 32 bits
            let mut offset = usize::try_from(r_offset).unwrap_or(usize::MAX);
            let mut addend = isize::try_from(r_addend).unwrap_or(0);

            // Fallback interpretation for unexpected large types: [offset][addend][info]
            if rtype > 0x10000 {
                let alt_info = read_u64(off + entry_size - 8);
                let alt_addend = read_i64(off + 8);
                let alt_type = (alt_info & 0xFFFF_FFFF) as u32;
                if alt_type <= 0x1000 {
                    r_info = alt_info;
                    r_addend = alt_addend;
                    rtype = alt_type;
                    addend = isize::try_from(r_addend).unwrap_or(0);
                }
            }

            log::trace!(
                "RELA entry i={}: off={:#x} info={:#x} type={} addend={:#x}",
                i,
                r_offset,
                r_info,
                rtype,
                addend
            );

            to_apply.push(Reloc { rtype, offset, addend });
        }

        // Apply after decoupling from source bytes
        log::trace!("applying relocations in virtual memory...");
        for r in to_apply {
            apply_relocation(
                r.rtype,
                r.offset,
                r.addend,
                virt_base,
                image_limit,
                phys_base,
                phys_off,
                &load_segments,
            );
        }
    }

    Ok(())
}

fn is_tls_segment(ph: &ProgramHeader, elf_file: &xmas_elf::ElfFile) -> bool {
    // Identify TLS by intersecting any SHF_TLS section with the segment's VA range
    let seg_start = ph.virtual_address as u64;
    let seg_end = seg_start.saturating_add(ph.mem_size as u64);
    for sh in elf_file.section_iter() {
        // Skip sections with zero size or without TLS flag
        let size = sh.size();
        if size == 0 { continue; }
        if (sh.flags() & sections::SHF_TLS) == 0 { continue; }

        let s_start = sh.address();
        let s_end = s_start.saturating_add(size);
        let intersects = !(s_end <= seg_start || s_start >= seg_end);
        if intersects {
            return true;
        }
    }
    false
}

fn apply_relocation(
    rtype: u32,
    offset: usize,
    addend: isize,
    virt_base: usize,
    image_limit: usize,
    phys_base: usize,
    phys_off: usize,
    load_segments: &[(usize, usize, usize)],
) {
    // we only support local (symidx==0) relocations from the dynamic table
    // which the kernel should be emitting for PIE images

    // Common
    const R_RISCV_RELATIVE: u32 = 3; // used on riscv
    const R_X86_64_RELATIVE: u32 = 8; // used on x86_64

    // Arch-specific IDs (avoid collisions by gating references below)
    // RISC-V
    const R_RISCV_64: u32 = 2; // ABS64 on riscv
    // x86_64
    const R_X86_64_64: u32 = 1; // ABS64 on x86_64
    const R_X86_64_PC32: u32 = 2; // PC32 on x86_64 (shares value 2 with R_RISCV_64)
    const R_X86_64_DTPMOD64: u32 = 16; // TLS module ID on x86_64
    const R_X86_64_GLOB_DAT: u32 = 6; // Set GOT entry to symbol value
    const R_X86_64_JUMP_SLOT: u32 = 7; // Set PLT entry to symbol value
    const R_X86_64_32: u32 = 10; // 32-bit absolute
    const R_X86_64_32S: u32 = 11; // 32-bit sign-extended
    const R_X86_64_TPOFF64: u32 = 45; // TLS LE offset

    log::trace!("reloc type={} offset={:#x} addend={:#x}", rtype, offset, addend);
    if offset >= image_limit {
        log::warn!(
            "Skipping relocation: target offset {:#x} beyond image limit {:#x}",
            offset,
            image_limit
        );
        return;
    }

    // Helper: translate a target virtual offset within the image (r_offset) to a physical address
    // using file-backed LOAD segments. Only returns Some for addresses within file_size.
    let va_to_pa = |r_off: usize| -> Option<usize> {
        for (seg_vaddr, seg_off, seg_filesz) in load_segments.iter().copied() {
            if r_off >= seg_vaddr && r_off < seg_vaddr.saturating_add(seg_filesz) {
                let delta = r_off - seg_vaddr;
                return Some(phys_base.saturating_add(seg_off).saturating_add(delta));
            }
        }
        None
    };

    match rtype {
        // RELATIVE (x86_64/riscv)
        R_RISCV_RELATIVE | R_X86_64_RELATIVE => {
            // Calculate address at which to apply the relocation.
            // dynamic relocations offsets are relative to the virtual layout of the elf,
            // not the physical file
            let target = virt_base.checked_add(offset).unwrap();

            // Calculate the value to store at the relocation target.
            let value = virt_base.wrapping_add_signed(addend);

            // log::trace!("reloc R_RISCV_RELATIVE offset: {:#x}; addend: {:#x} => target {target:?} value {value:?}", rela.get_offset(), rela.get_addend());
            // Prefer writing via the physical window to avoid RO virtual mappings
            if let Some(pa) = va_to_pa(offset) {
                unsafe { ((phys_off + pa) as *mut usize).write_unaligned(value) }
            } else {
                // Fallback to writing via virtual address (should be mapped RW if valid)
                unsafe { (target as *mut usize).write_unaligned(value) }
            }
        }
        // ABS 64-bit (riscv/x86_64) with symidx==0: store addend as absolute
        R_RISCV_64 | R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            let target = virt_base.checked_add(offset).unwrap();
            let value = virt_base.wrapping_add_signed(addend);
            log::trace!(
                "ABS-like: type={} target={:#x} write={:#x}",
                rtype,
                target,
                value
            );
            if let Some(pa) = va_to_pa(offset) {
                unsafe { ((phys_off + pa) as *mut usize).write_unaligned(value) }
            } else {
                unsafe { (target as *mut usize).write_unaligned(value) }
            }
        }
        // x86_64 PC32: value = S + A - P. When symidx==0 many linkers encode
        // a base-relative PC32, so treat S as the image base (virt_base):
        // value = virt_base + A - P.
        // Write a 32-bit signed value at target.
        r if r == R_X86_64_PC32 => {
            #[cfg(target_arch = "x86_64")]
            {
                let target = virt_base.checked_add(offset).unwrap();
                let p = target as isize;
                let s = virt_base as isize; // treat symidx==0 as base-relative
                let val = s.wrapping_add(addend).wrapping_sub(p);
                log::trace!(
                    "R_X86_64_PC32: S(base)={:#x} P={:#x} A={:#x} => val={:#x}",
                    s,
                    p,
                    addend,
                    val
                );
                if let Some(pa) = va_to_pa(offset) {
                    unsafe { ((phys_off + pa) as *mut i32).write_unaligned(val as i32) }
                } else {
                    unsafe { (target as *mut i32).write_unaligned(val as i32) }
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                unimplemented!(
                    "x86_64 PC32 relocation encountered on non-x86_64 target"
                );
            }
        }
        // x86_64 TLS: for a statically-linked single module, DTPMOD64 is 1
        R_X86_64_DTPMOD64 => {
            let target = virt_base.checked_add(offset).unwrap();
            let module_id: usize = 1;
            if let Some(pa) = va_to_pa(offset) {
                unsafe { ((phys_off + pa) as *mut usize).write_unaligned(module_id) }
            } else {
                unsafe { (target as *mut usize).write_unaligned(module_id) }
            }
        }
        // 32-bit absolute relocations
        R_X86_64_32 | R_X86_64_32S => {
            let target = virt_base.checked_add(offset).unwrap();
            let value = virt_base.wrapping_add_signed(addend) as u32;
            if let Some(pa) = va_to_pa(offset) {
                unsafe { ((phys_off + pa) as *mut u32).write_unaligned(value) }
            } else {
                unsafe { (target as *mut u32).write_unaligned(value) }
            }
        }
        // TLS local-exec offset relative to thread pointer. We don't resolve at load-time;
        // leave addend as-is which is already an offset encoded by linker.
        R_X86_64_TPOFF64 => {
            let target = virt_base.checked_add(offset).unwrap();
            let value = addend as usize;
            if let Some(pa) = va_to_pa(offset) {
                unsafe { ((phys_off + pa) as *mut usize).write_unaligned(value) }
            } else {
                unsafe { (target as *mut usize).write_unaligned(value) }
            }
        }
        // Unknown relocation: Log and skip to keep boot progressing.
        _ => {
            log::warn!(
                "Skipping unsupported relocation type {} at offset {:#x} addend={:#x}",
                rtype,
                offset,
                addend
            );
        }
    }
}

/// Map the kernel thread-local storage (TLS) memory regions.
fn handle_tls_segment(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    page_alloc: &mut PageAllocator,
    ph: &ProgramHeader,
    _virt_base: usize,
    phys_base: usize,
    minfo: &MachineInfo,
    phys_off: usize,
) -> crate::Result<TlsAllocation> {
    // For x86_64 TLS variant II, we need extra space before the TLS data for negative offsets
    #[cfg(target_arch = "x86_64")]
    let pre_offset = arch::PAGE_SIZE; // Allocate one page before TLS data for negative offsets
    #[cfg(not(target_arch = "x86_64"))]
    let pre_offset = 0;

    let per_cpu_size = ph.mem_size + pre_offset;
    let layout = Layout::from_size_align(per_cpu_size, cmp::max(ph.align, arch::PAGE_SIZE))
        .unwrap()
        .repeat(minfo.hart_mask.count_ones() as usize)
        .unwrap()
        .0
        .pad_to_align();
    log::trace!("allocating TLS segment {layout:?}...");

    let virt = page_alloc.allocate(layout);
    let mut virt_start = virt.start;

    let mut phys_iter = frame_alloc.allocate_zeroed(layout, phys_off);
    while let Some((phys, len)) = phys_iter.next()? {
        log::trace!(
            "Mapping TLS region {virt_start:#x}..{:#x} {len}, phys={phys:#x}...",
            virt_start.checked_add(len.get()).unwrap()
        );

        // Debug: Check if the physical memory is properly zeroed
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // On x86_64, physical memory is accessed through the virtual mapping
            let virt_addr = phys_off.checked_add(phys).unwrap();
            let phys_ptr = virt_addr as *const u64;
            let first_val = *phys_ptr;
            if first_val != 0 {
                log::error!(
                    "TLS physical memory at {phys:#x} not zeroed! Contains: {first_val:#x}"
                );
                if first_val == 0xACE0BACE {
                    log::error!("Found stack canary pattern in freshly allocated TLS memory!");
                }
            }
        }

        // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
        // abort startup anyway
        unsafe {
            arch::map_contiguous(
                root_pgtable,
                phys_iter.alloc(),
                virt_start,
                phys,
                len,
                Flags::READ | Flags::WRITE,
                phys_off,
            )?;
        }

        virt_start += len.get();
    }

    // Compute source address of TLS initializer bytes from the ELF file buffer.
    // PT_TLS data lives in the file image and is not mapped into the kernel's virtual image.
    let template_src = {
        #[cfg(target_arch = "x86_64")]
        {
            // Kernel ELF is identity-mapped, read directly from file buffer
            phys_base.checked_add(ph.offset).unwrap()
        }
        #[cfg(target_arch = "riscv64")]
        {
            // Kernel ELF must be accessed through the physical window after MMU
            phys_off.checked_add(phys_base).unwrap().checked_add(ph.offset).unwrap()
        }
    };

    Ok(TlsAllocation {
        virt,
        template: TlsTemplate {
            start_addr: template_src,
            mem_size: ph.mem_size,
            file_size: ph.file_size,
            align: ph.align,
        },
        #[cfg(target_arch = "x86_64")]
        pre_offset,
    })
}

#[derive(Debug)]
pub struct TlsAllocation {
    /// The TLS region in virtual memory
    virt: Range<usize>,
    /// The template we allocated for
    pub template: TlsTemplate,
    /// Extra space allocated before TLS data for x86_64 negative offsets
    #[cfg(target_arch = "x86_64")]
    pre_offset: usize,
}

impl TlsAllocation {
    pub fn region_for_hart(&self, hartid: usize) -> Range<usize> {
        #[cfg(target_arch = "x86_64")]
        let per_cpu_size = self.template.mem_size + self.pre_offset;
        #[cfg(not(target_arch = "x86_64"))]
        let per_cpu_size = self.template.mem_size;

        let aligned_size =
            checked_align_up(per_cpu_size, cmp::max(self.template.align, arch::PAGE_SIZE)).unwrap();
        let allocation_start = self.virt.start + (aligned_size * hartid);

        // For x86_64, the TLS base should point to after the pre_offset area
        #[cfg(target_arch = "x86_64")]
        let tls_start = allocation_start + self.pre_offset;
        #[cfg(not(target_arch = "x86_64"))]
        let tls_start = allocation_start;

        Range::from(tls_start..tls_start + self.template.mem_size)
    }

    pub fn initialize_for_hart(&self, hartid: usize) {
        let region = self.region_for_hart(hartid);
        log::trace!("TLS: hart={} region={:#x?}", hartid, region);

        // Safety: We have to trust the loaders BootInfo here
        unsafe {
            // For x86_64, we need to set up the TLS self-pointer at offset 0
            // This is required by the System V ABI for TLS
            #[cfg(target_arch = "x86_64")]
            {
                // Write the TLS base address at offset 0 (self-pointer)
                let tls_base_ptr = region.start as *mut usize;
                *tls_base_ptr = region.start;
                log::trace!(
                    "Set TLS self-pointer at {:#x} to {:#x}",
                    region.start,
                    region.start
                );
            }

            // First, copy the initialized data if any
            if self.template.file_size != 0 {
                log::trace!(
                    "TLS copy: hart={} src={:#x} -> dst={:#x} size={}",
                    hartid,
                    self.template.start_addr,
                    region.start,
                    self.template.file_size
                );
                let src: &[u8] = slice::from_raw_parts(
                    self.template.start_addr as *const u8,
                    self.template.file_size,
                );
                let dst: &mut [u8] =
                    slice::from_raw_parts_mut(region.start as *mut u8, self.template.file_size);

                // sanity check to ensure our destination allocated memory is actually zeroed.
                // if it's not, that likely means we're about to override something important
                #[cfg(target_arch = "x86_64")]
                {
                    // On x86_64, we already wrote the TLS self-pointer at offset 0
                    // Check that everything except the first 8 bytes is zero
                    debug_assert!(dst[8..].iter().all(|&x| x == 0));
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    debug_assert!(dst.iter().all(|&x| x == 0));
                }

                // Check if source contains the canary pattern
                if src.len() >= 8 {
                    let first_qword = u64::from_ne_bytes(src[0..8].try_into().unwrap());
                    if first_qword == 0xACE0BACE {
                        log::error!("TLS template source contains stack canary pattern!");
                        log::error!("Template start_addr: {:#x}", self.template.start_addr);
                        log::error!("First 64 bytes of source: {:x?}", &src[..64.min(src.len())]);
                    }
                }

                dst.copy_from_slice(src);
                log::trace!("TLS copy complete: hart={}", hartid);
            }

            // Then zero the BSS section (from file_size to mem_size)
            if self.template.mem_size > self.template.file_size {
                let bss_start = region.start + self.template.file_size;
                let bss_size = self.template.mem_size - self.template.file_size;
                log::trace!(
                    "TLS BSS zero: hart={} start={:#x} size={}",
                    hartid,
                    bss_start,
                    bss_size
                );
                let bss: &mut [u8] = slice::from_raw_parts_mut(bss_start as *mut u8, bss_size);
                bss.fill(0);
            }

            // For x86_64, ensure the self-pointer wasn't overwritten
            #[cfg(target_arch = "x86_64")]
            {
                let tls_base_ptr = region.start as *mut usize;
                if *tls_base_ptr != region.start {
                    log::warn!("TLS self-pointer was overwritten, restoring it");
                    *tls_base_ptr = region.start;
                }
            }

            log::trace!("TLS init done: hart={}", hartid);
        }
    }
}

pub fn map_kernel_stacks(
    root_pgtable: usize,
    frame_alloc: &mut FrameAllocator,
    page_alloc: &mut PageAllocator,
    minfo: &MachineInfo,
    per_cpu_size_pages: usize,
    phys_off: usize,
) -> crate::Result<StacksAllocation> {
    let per_cpu_size = per_cpu_size_pages * arch::PAGE_SIZE;
    let per_cpu_size_with_guard = per_cpu_size + arch::PAGE_SIZE;

    let layout_with_guard = Layout::from_size_align(per_cpu_size_with_guard, arch::PAGE_SIZE)
        .unwrap()
        .repeat(minfo.hart_mask.count_ones() as usize)
        .unwrap()
        .0;

    let virt = page_alloc.allocate(layout_with_guard);
    log::trace!("Mapping stacks region {virt:#x?}...");

    for hart in 0..minfo.hart_mask.count_ones() {
        let layout = Layout::from_size_align(per_cpu_size, arch::PAGE_SIZE).unwrap();

        let mut virt = virt
            .end
            .checked_sub(per_cpu_size_with_guard * hart as usize)
            .and_then(|a| a.checked_sub(per_cpu_size))
            .unwrap();

        log::trace!("Allocating stack {layout:?}...");
        // The stacks region doesn't need to be zeroed, since we will be filling it with
        // the canary pattern anyway
        let mut phys_iter = frame_alloc.allocate(layout);

        while let Some((phys, len)) = phys_iter.next()? {
            log::trace!(
                "mapping stack for hart {hart} {virt:#x}..{:#x} => {phys:#x}..{:#x}",
                virt.checked_add(len.get()).unwrap(),
                phys.checked_add(len.get()).unwrap()
            );

            // Safety: Leaving the address space in an invalid state here is fine since on panic we'll
            // abort startup anyway
            unsafe {
                arch::map_contiguous(
                    root_pgtable,
                    phys_iter.alloc(),
                    virt,
                    phys,
                    len,
                    Flags::READ | Flags::WRITE,
                    phys_off,
                )?;
            }

            virt += len.get();
        }
    }

    Ok(StacksAllocation {
        virt,
        per_cpu_size,
        per_cpu_size_with_guard,
    })
}

pub struct StacksAllocation {
    /// The TLS region in virtual memory
    virt: Range<usize>,
    per_cpu_size: usize,
    per_cpu_size_with_guard: usize,
}

impl StacksAllocation {
    pub fn region_for_cpu(&self, cpuid: usize) -> Range<usize> {
        let end = self.virt.end - (self.per_cpu_size_with_guard * cpuid);

        Range::from((end - self.per_cpu_size)..end)
    }
}

struct ProgramHeader<'a> {
    pub p_flags: xmas_elf::program::Flags,
    pub align: usize,
    pub offset: usize,
    pub virtual_address: usize,
    pub file_size: usize,
    pub mem_size: usize,
    ph: xmas_elf::program::ProgramHeader<'a>,
}

impl ProgramHeader<'_> {
    pub fn parse_rela(&self, elf_file: &xmas_elf::ElfFile) -> crate::Result<Option<RelaInfo>> {
        // Disabled: this path depends on xmas-elf's program type decoding which
        // panics for unknown/OS-specific headers on some toolchains. We now
        // obtain RELA info from the .dynamic section instead.
        Ok(None)
    }
}

struct RelaInfo {
    pub offset: u64,      // Virtual address of RELA table
    pub count: u64,       // Number of entries
    pub entry_size: u64,  // Size of each entry in bytes
}

// Parse the .dynamic section to find DT_RELA/DT_RELASZ/DT_RELAENT without using
// program header type decoding.
fn parse_rela_from_dynamic_section(
    elf_file: &xmas_elf::ElfFile,
) -> crate::Result<Option<RelaInfo>> {
    let Some(section) = elf_file.find_section_by_name(".dynamic") else {
        return Ok(None);
    };
    let raw = section.raw_data(elf_file);
    // Each Elf64_Dyn entry is two u64 words: d_tag (i64) and d_val/p (u64)
    if raw.len() < 16 || raw.len() % 16 != 0 {
        return Ok(None);
    }

    const DT_RELA: u64 = 7;
    const DT_RELASZ: u64 = 8;
    const DT_RELAENT: u64 = 9;

    let mut rela: Option<u64> = None;
    let mut relasz: Option<u64> = None;
    let mut relaent: Option<u64> = None;

    for chunk in raw.chunks_exact(16) {
        let tag = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let val = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        match tag {
            DT_RELA => rela = Some(val),
            DT_RELASZ => relasz = Some(val),
            DT_RELAENT => relaent = Some(val),
            _ => {}
        }
    }

    let Some(offset) = rela else { return Ok(None) };
    let total = relasz.unwrap_or(0);
    let ent = relaent.unwrap_or(24);
    if total == 0 || ent == 0 { return Ok(None) }

    Ok(Some(RelaInfo { offset, count: total / ent, entry_size: ent }))
}

impl<'a> TryFrom<xmas_elf::program::ProgramHeader<'a>> for ProgramHeader<'a> {
    type Error = Error;

    fn try_from(ph: xmas_elf::program::ProgramHeader<'a>) -> Result<Self, Self::Error> {
        Ok(Self {
            p_flags: ph.flags(),
            align: usize::try_from(ph.align())?,
            offset: usize::try_from(ph.offset())?,
            virtual_address: usize::try_from(ph.virtual_addr())?,
            file_size: usize::try_from(ph.file_size())?,
            mem_size: usize::try_from(ph.mem_size())?,
            ph,
        })
    }
}

fn flags_for_segment(ph: &ProgramHeader) -> Flags {
    let mut out = Flags::empty();

    if ph.p_flags.is_read() {
        out |= Flags::READ;
    }

    if ph.p_flags.is_write() {
        out |= Flags::WRITE;
    }

    if ph.p_flags.is_execute() {
        out |= Flags::EXECUTE;
    }

    assert!(
        !out.contains(Flags::WRITE | Flags::EXECUTE),
        "elf segment (virtual range {:#x}..{:#x}) is marked as write-execute",
        ph.virtual_address,
        ph.virtual_address + ph.mem_size
    );

    out
}

#[must_use]
#[inline]
pub const fn checked_align_up(this: usize, align: usize) -> Option<usize> {
    assert!(
        align.is_power_of_two(),
        "checked_align_up: align is not a power-of-two"
    );

    // SAFETY: `align` has been checked to be a power of 2 above
    let align_minus_one = unsafe { align.unchecked_sub(1) };

    // addr.wrapping_add(align_minus_one) & 0usize.wrapping_sub(align)
    if let Some(addr_plus_align) = this.checked_add(align_minus_one) {
        let aligned = addr_plus_align & 0usize.wrapping_sub(align);
        debug_assert!(aligned.is_multiple_of(align));
        debug_assert!(aligned >= this);
        Some(aligned)
    } else {
        None
    }
}

#[must_use]
#[inline]
pub const fn align_down(this: usize, align: usize) -> usize {
    assert!(
        align.is_power_of_two(),
        "align_down: align is not a power-of-two"
    );

    let aligned = this & 0usize.wrapping_sub(align);
    debug_assert!(aligned.is_multiple_of(align));
    debug_assert!(aligned <= this);
    aligned
}
