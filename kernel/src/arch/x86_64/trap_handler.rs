// Copyright 2025 bubblepipe
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::boxed::Box;
use core::arch::{asm, naked_asm};
use core::cell::Cell;

use cpu_local::cpu_local;
use x86::trap::{Exception, Trap};

use crate::arch::PAGE_SIZE;
use crate::backtrace::Backtrace;
use crate::mem::VirtualAddress;
use crate::state::{cpu_local, global};
use crate::TRAP_STACK_SIZE_PAGES;

cpu_local! {
    static IN_TRAP: Cell<bool> = Cell::new(false);
    static TRAP_STACK: [u8; TRAP_STACK_SIZE_PAGES * PAGE_SIZE] = const { [0; TRAP_STACK_SIZE_PAGES * PAGE_SIZE] };
}

/// x86_64 Interrupt Descriptor Table
#[repr(C, align(16))]
struct Idt {
    entries: [IdtEntry; 256],
}

/// x86_64 IDT Entry (Gate Descriptor)
#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,      // bits 0-15 of handler address
    selector: u16,        // code segment selector
    ist: u8,              // interrupt stack table offset (bits 0-2), rest reserved
    type_attr: u8,        // type and attributes
    offset_mid: u16,      // bits 16-31 of handler address
    offset_high: u32,     // bits 32-63 of handler address
    reserved: u32,        // reserved (must be zero)
}

impl IdtEntry {
    const fn missing() -> Self {
        IdtEntry {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: usize, selector: u16, ist: u8, type_attr: u8) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = selector;
        self.ist = ist & 0x7;  // only lower 3 bits
        self.type_attr = type_attr;
        self.reserved = 0;
    }
}

static mut IDT: Idt = Idt {
    entries: [IdtEntry::missing(); 256],
};

/// IDT Pointer structure for LIDT instruction
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// Trap frame saved by exception handlers
#[repr(C)]
#[derive(Clone, Default)]
pub struct TrapFrame {
    // Segment registers
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,

    // General purpose registers (pushed by handler)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,

    // Interrupt/exception info (pushed by our stub)
    pub vector: u64,
    pub error_code: u64,

    // Pushed by CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const INTERRUPT_GATE: u8 = 0x8E;  // Present, DPL=0, Type=0xE (Interrupt Gate)
const TRAP_GATE: u8 = 0x8F;       // Present, DPL=0, Type=0xF (Trap Gate)

#[cold]
pub fn init() {
    // Output 'H' directly to serial
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x48",
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // Get code segment selector (assumes flat memory model, GDT entry 1 is code segment)
    let code_segment: u16 = 0x08;  // GDT entry 1 (8 bytes each, 0-indexed)

    // Output 'h' before setting up handlers
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x68",
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    // Safety: We're initializing a static mut, which is safe during init
    unsafe {
        // Set up exception handlers (0-31)
        IDT.entries[0].set_handler(exception_0 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[1].set_handler(exception_1 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[2].set_handler(exception_2 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[3].set_handler(exception_3 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[4].set_handler(exception_4 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[5].set_handler(exception_5 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[6].set_handler(exception_6 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[7].set_handler(exception_7 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[8].set_handler(exception_8 as usize, code_segment, 1, INTERRUPT_GATE);  // Double fault uses IST
        IDT.entries[9].set_handler(exception_9 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[10].set_handler(exception_10 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[11].set_handler(exception_11 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[12].set_handler(exception_12 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[13].set_handler(exception_13 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[14].set_handler(exception_14 as usize, code_segment, 0, INTERRUPT_GATE);  // Page fault
        IDT.entries[15].set_handler(exception_15 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[16].set_handler(exception_16 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[17].set_handler(exception_17 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[18].set_handler(exception_18 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[19].set_handler(exception_19 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[20].set_handler(exception_20 as usize, code_segment, 0, INTERRUPT_GATE);
        IDT.entries[21].set_handler(exception_21 as usize, code_segment, 0, INTERRUPT_GATE);

        for i in 22..32 {
            IDT.entries[i].set_handler(exception_generic as usize, code_segment, 0, INTERRUPT_GATE);
        }

        // Set up IRQ handlers (32-47 for PIC interrupts)
        for i in 32..48 {
            IDT.entries[i].set_handler(irq_generic as usize, code_segment, 0, INTERRUPT_GATE);
        }

        // Output 'i' before lidt
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x69",
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );

        // Load IDT - use proper syntax
        let idtr = IdtPointer {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: core::ptr::addr_of!(IDT) as u64,
        };

        // Use Intel syntax for lidt which is more standard
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &idtr,
            options(readonly, nostack, preserves_flags)
        );

        // Output 'K' after lidt
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x4B",
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }
}

// Exception stubs - these save state and call the common handler
// Exceptions without error codes (push dummy 0)
macro_rules! exception_no_error {
    ($name:ident, $num:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            unsafe {
                naked_asm!(
                    "push 0",              // dummy error code
                    "push {vector}",       // push vector number
                    "jmp {common}",        // jump to common handler
                    vector = const $num,
                    common = sym exception_common,
                );
            }
        }
    };
}

// Exceptions with error codes (CPU pushes error code)
macro_rules! exception_with_error {
    ($name:ident, $num:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            unsafe {
                naked_asm!(
                    "push {vector}",       // push vector number
                    "jmp {common}",        // jump to common handler
                    vector = const $num,
                    common = sym exception_common,
                );
            }
        }
    };
}

exception_no_error!(exception_0, 0);    // Divide Error
exception_no_error!(exception_1, 1);    // Debug
exception_no_error!(exception_2, 2);    // NMI
exception_no_error!(exception_3, 3);    // Breakpoint
exception_no_error!(exception_4, 4);    // Overflow
exception_no_error!(exception_5, 5);    // Bound Range Exceeded
exception_no_error!(exception_6, 6);    // Invalid Opcode
exception_no_error!(exception_7, 7);    // Device Not Available
exception_with_error!(exception_8, 8);  // Double Fault
exception_no_error!(exception_9, 9);    // Coprocessor Segment Overrun
exception_with_error!(exception_10, 10); // Invalid TSS
exception_with_error!(exception_11, 11); // Segment Not Present
exception_with_error!(exception_12, 12); // Stack Segment Fault
exception_with_error!(exception_13, 13); // General Protection Fault
exception_with_error!(exception_14, 14); // Page Fault
exception_no_error!(exception_15, 15);  // Reserved
exception_no_error!(exception_16, 16);  // x87 FPU Error
exception_with_error!(exception_17, 17); // Alignment Check
exception_no_error!(exception_18, 18);  // Machine Check
exception_no_error!(exception_19, 19);  // SIMD Exception
exception_no_error!(exception_20, 20);  // Virtualization Exception
exception_with_error!(exception_21, 21); // Control Protection Exception

exception_no_error!(exception_generic, 255);
exception_no_error!(irq_generic, 254);

/// Common exception entry point that saves all registers
#[unsafe(naked)]
unsafe extern "C" fn exception_common() {
    unsafe {
        naked_asm!(
            // At this point stack has: SS, RSP, RFLAGS, CS, RIP, error_code, vector

            // Save all general purpose registers
            "push r15",
            "push r14",
            "push r13",
            "push r12",
            "push r11",
            "push r10",
            "push r9",
            "push r8",
            "push rbp",
            "push rdi",
            "push rsi",
            "push rdx",
            "push rcx",
            "push rbx",
            "push rax",

            // Save segment registers
            "mov rax, gs",
            "push rax",
            "mov rax, fs",
            "push rax",
            "mov rax, es",
            "push rax",
            "mov rax, ds",
            "push rax",

            // Set up kernel data segments
            "mov ax, 0x10",  // GDT entry 2 (data segment)
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",

            // Call Rust handler with pointer to trap frame
            "mov rdi, rsp",
            "call {handler}",

            // Restore segment registers
            "pop rax",
            "mov ds, ax",
            "pop rax",
            "mov es, ax",
            "pop rax",
            "mov fs, ax",
            "pop rax",
            "mov gs, ax",

            // Restore general purpose registers
            "pop rax",
            "pop rbx",
            "pop rcx",
            "pop rdx",
            "pop rsi",
            "pop rdi",
            "pop rbp",
            "pop r8",
            "pop r9",
            "pop r10",
            "pop r11",
            "pop r12",
            "pop r13",
            "pop r14",
            "pop r15",

            // Remove vector and error code from stack
            "add rsp, 16",

            // Return from interrupt
            "iretq",

            handler = sym default_trap_handler,
        );
    }
}

/// Main trap handler called from assembly
extern "C" fn default_trap_handler(frame: &mut TrapFrame) {
    // Output 'T' to show trap handler was called
    unsafe {
        core::arch::asm!(
            "mov dx, 0x3F8",
            "mov al, 0x54",
            "out dx, al",
            options(nomem, nostack, preserves_flags)
        );
    }

    let vector = frame.vector;
    let error_code = frame.error_code;

    // Only output for non-page-fault exceptions to avoid spam
    if vector != 14 {
        unsafe {
            let marker = if vector < 10 {
                b'0' + vector as u8
            } else if vector < 36 {
                b'A' + (vector - 10) as u8
            } else {
                b'Z'
            };
            core::arch::asm!(
                "mov dx, 0x3F8",
                "mov al, {0}",
                "out dx, al",
                in(reg_byte) marker,
                options(nomem, nostack, preserves_flags)
            );
        }
    }

    let rip = VirtualAddress::new(frame.rip as usize).unwrap();
    let rbp = VirtualAddress::new(frame.rbp as usize).unwrap();

    // Read CR2 for page faults
    let cr2 = if vector == 14 {
        static mut PF_COUNT: usize = 0;
        unsafe {
            PF_COUNT += 1;
            // Output '.' every 10 page faults to show progress
            if PF_COUNT % 10 == 0 {
                core::arch::asm!(
                    "mov dx, 0x3F8",
                    "mov al, 0x2E",  // '.'
                    "out dx, al",
                    options(nomem, nostack, preserves_flags)
                );
            }
        }

        let mut addr: u64;
        unsafe {
            asm!("mov {}, cr2", out(reg) addr, options(nomem, nostack));
        }
        VirtualAddress::new(addr as usize)
    } else {
        None
    };

    // Check for recursive faults
    if IN_TRAP.replace(true) {
        handle_recursive_fault(frame, rip);
    }

    'handler: {
        // Try to convert vector to specific exception type
        match vector {
            14 => {
                // Page fault
                let fault_addr = cr2.unwrap_or_else(|| VirtualAddress::new(0).unwrap());

                // Try page fault handler first
                if crate::mem::handle_page_fault(
                    Trap::Exception(Exception::PageFault),
                    fault_addr
                ).is_break() {
                    break 'handler;
                }

                // Try WASM exception handler
                if crate::wasm::trap_handler::handle_wasm_exception(rip, rbp, fault_addr).is_break() {
                    break 'handler;
                }

                // Fatal kernel page fault
                handle_kernel_exception(vector, error_code, frame, rip, cr2);
            }
            6 => {
                // Invalid opcode - might be WASM
                if crate::wasm::trap_handler::handle_wasm_exception(
                    rip,
                    rbp,
                    VirtualAddress::new(0).unwrap()
                ).is_break() {
                    break 'handler;
                }

                handle_kernel_exception(vector, error_code, frame, rip, cr2);
            }
            32..=47 => {
                // Hardware interrupt (IRQ)
                handle_irq(vector - 32);
            }
            _ => {
                // Other exceptions
                handle_kernel_exception(vector, error_code, frame, rip, cr2);
            }
        }
    }

    IN_TRAP.set(false);
}

fn handle_irq(irq: u64) {
    // For now, just acknowledge the interrupt
    // TODO: Implement proper IRQ handling with APIC/PIC

    // Send EOI to PIC if using legacy PIC
    if irq < 16 {
        unsafe {
            if irq >= 8 {
                // Slave PIC
                asm!("out 0xA0, al", in("al") 0x20u8, options(nomem, nostack));
            }
            // Master PIC
            asm!("out 0x20, al", in("al") 0x20u8, options(nomem, nostack));
        }
    }

    // Wake executor if needed
    if let Some(global) = crate::state::try_global() {
        global.executor.wake_one();
    }
}

fn handle_kernel_exception(
    vector: u64,
    error_code: u64,
    frame: &TrapFrame,
    rip: VirtualAddress,
    cr2: Option<VirtualAddress>,
) -> ! {
    let exception_name = match vector {
        0 => "Divide Error",
        1 => "Debug",
        2 => "NMI",
        3 => "Breakpoint",
        4 => "Overflow",
        5 => "Bound Range Exceeded",
        6 => "Invalid Opcode",
        7 => "Device Not Available",
        8 => "Double Fault",
        10 => "Invalid TSS",
        11 => "Segment Not Present",
        12 => "Stack Segment Fault",
        13 => "General Protection Fault",
        14 => "Page Fault",
        16 => "x87 FPU Error",
        17 => "Alignment Check",
        18 => "Machine Check",
        19 => "SIMD Exception",
        _ => "Unknown Exception",
    };

    tracing::error!(
        "KERNEL TRAP: {} (vector={}, error_code={:#x}, rip={:#x})",
        exception_name, vector, error_code, rip.get()
    );

    if let Some(addr) = cr2 {
        tracing::error!("  CR2 (fault address) = {:#x}", addr.get());
    }

    tracing::error!(
        "  RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
        frame.rax, frame.rbx, frame.rcx, frame.rdx
    );
    tracing::error!(
        "  RSI={:#x} RDI={:#x} RBP={:#x} RSP={:#x}",
        frame.rsi, frame.rdi, frame.rbp, frame.rsp
    );

    // Try to capture a backtrace
    // x86_64 register mapping: RAX, RDX, RCX, RBX, RSI, RDI, RBP, RSP, R8-R15, RIP
    let regs = unwind2::Registers {
        gp: [
            frame.rax as usize,  // 0: RAX
            frame.rdx as usize,  // 1: RDX
            frame.rcx as usize,  // 2: RCX
            frame.rbx as usize,  // 3: RBX
            frame.rsi as usize,  // 4: RSI
            frame.rdi as usize,  // 5: RDI
            frame.rbp as usize,  // 6: RBP
            frame.rsp as usize,  // 7: RSP
            frame.r8 as usize,   // 8: R8
            frame.r9 as usize,   // 9: R9
            frame.r10 as usize,  // 10: R10
            frame.r11 as usize,  // 11: R11
            frame.r12 as usize,  // 12: R12
            frame.r13 as usize,  // 13: R13
            frame.r14 as usize,  // 14: R14
            frame.r15 as usize,  // 15: R15
            frame.rip as usize,  // 16: RIP
        ],
    };

    if let Ok(backtrace) = Backtrace::<32>::from_registers(regs.clone(), rip) {
        tracing::error!("{backtrace}");
    } else {
        tracing::error!("Failed to capture backtrace");
    }

    // Begin unwinding
    let payload = Box::new((exception_name, vector, error_code));
    IN_TRAP.set(false);

    // Safety: we saved the register state in the trap frame
    unsafe {
        panic_unwind2::begin_unwind(payload, regs, rip.get());
    }
}

fn handle_recursive_fault(frame: &TrapFrame, rip: VirtualAddress) -> ! {
    tracing::error!("RECURSIVE FAULT at RIP={:#x}", rip.get());
    tracing::error!(
        "  RAX={:#x} RBX={:#x} RCX={:#x} RDX={:#x}",
        frame.rax, frame.rbx, frame.rcx, frame.rdx
    );

    let payload = Box::new("recursive fault in trap handler");

    let regs = unwind2::Registers {
        gp: [
            frame.rax as usize,  // 0: RAX
            frame.rdx as usize,  // 1: RDX
            frame.rcx as usize,  // 2: RCX
            frame.rbx as usize,  // 3: RBX
            frame.rsi as usize,  // 4: RSI
            frame.rdi as usize,  // 5: RDI
            frame.rbp as usize,  // 6: RBP
            frame.rsp as usize,  // 7: RSP
            frame.r8 as usize,   // 8: R8
            frame.r9 as usize,   // 9: R9
            frame.r10 as usize,  // 10: R10
            frame.r11 as usize,  // 11: R11
            frame.r12 as usize,  // 12: R12
            frame.r13 as usize,  // 13: R13
            frame.r14 as usize,  // 14: R14
            frame.r15 as usize,  // 15: R15
            frame.rip as usize,  // 16: RIP
        ],
    };

    unsafe {
        panic_unwind2::begin_unwind(payload, regs, rip.get());
    }
}
