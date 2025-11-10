// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Basic kernel shell for debugging purposes, taken from
//! <https://github.com/hawkw/mycelium/blob/main/src/shell.rs> (MIT)

pub const S: &str = r#"
CXLOS Kernel Shell
=================
"#;

// Serial input ring buffer (lock-free for interrupt context)
const SERIAL_BUFFER_SIZE: usize = 256;
static SERIAL_BUFFER: [AtomicU8; SERIAL_BUFFER_SIZE] = [const { AtomicU8::new(0) }; SERIAL_BUFFER_SIZE];
static SERIAL_READ_POS: AtomicUsize = AtomicUsize::new(0);
static SERIAL_WRITE_POS: AtomicUsize = AtomicUsize::new(0);

/// Called from interrupt handler when serial data arrives
pub fn on_serial_interrupt(ch: u8) {
    let write_pos = SERIAL_WRITE_POS.load(Ordering::Acquire);
    let read_pos = SERIAL_READ_POS.load(Ordering::Acquire);
    let next_write = (write_pos + 1) % SERIAL_BUFFER_SIZE;

    // Check if buffer is full
    if next_write != read_pos {
        SERIAL_BUFFER[write_pos].store(ch, Ordering::Release);
        SERIAL_WRITE_POS.store(next_write, Ordering::Release);
    }
    // If buffer is full, drop the character
}

/// Try to read a character from the serial input buffer
fn try_read_serial() -> Option<u8> {
    let read_pos = SERIAL_READ_POS.load(Ordering::Acquire);
    let write_pos = SERIAL_WRITE_POS.load(Ordering::Acquire);

    if read_pos == write_pos {
        // Buffer is empty
        None
    } else {
        let ch = SERIAL_BUFFER[read_pos].load(Ordering::Acquire);
        let next_read = (read_pos + 1) % SERIAL_BUFFER_SIZE;
        SERIAL_READ_POS.store(next_read, Ordering::Release);
        Some(ch)
    }
}

use alloc::string::{String, ToString};
use alloc::format;
use core::fmt;
use core::fmt::Write;
use core::ops::DerefMut;
use core::range::Range;
use core::str::FromStr;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use fallible_iterator::FallibleIterator;
use kasync::executor::Executor;
use spin::{Barrier, OnceLock};

use crate::busybox::{self, commands};
use crate::device_tree::DeviceTree;
use crate::mem::{Mmap, PhysicalAddress, with_kernel_aspace};
use crate::state::global;
use crate::{arch, irq};

static COMMANDS: &[Command] = &[PANIC, FAULT, VERSION, SHUTDOWN, BOOT];

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn serial_write_byte_blocking(b: u8) {
    const COM1_BASE: u16 = 0x3F8;
    const DATA_REG: u16 = COM1_BASE + 0;
    const LSR: u16 = COM1_BASE + 5;
    unsafe {
        // wait for THR empty, with a simple timeout to avoid hard hangs
        let mut spins: u32 = 0;
        loop {
            let mut st: u8 = 0;
            core::arch::asm!("in al, dx", out("al") st, in("dx") LSR, options(nomem, preserves_flags));
            if st & 0x20 != 0 { break; }
            spins = spins.wrapping_add(1);
            if spins > 1_000_000 { break; }
        }
        core::arch::asm!("out dx, al", in("dx") DATA_REG, in("al") b, options(nomem, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
fn serial_write_str_blocking(s: &str) {
    for b in s.bytes() { serial_write_byte_blocking(b); }
}

#[cfg(target_arch = "x86_64")]
fn serial_write_line_blocking(s: &str) {
    serial_write_str_blocking(s);
    serial_write_str_blocking("\r\n");
}

pub fn init(devtree: &'static DeviceTree, sched: &'static Executor, num_cpus: usize) {
    // The `Barrier` below is here so that the maybe verbose startup logging is
    // out of the way before dropping the user into the kernel shell. If we don't
    // wait for the last CPU to have finished initializing it will mess up the shell output.
    static SYNC: OnceLock<Barrier> = OnceLock::new();
    // On x86_64 we currently run only on the boot CPU.
    // Avoid waiting for non-existent secondary CPUs.
    #[cfg(target_arch = "x86_64")]
    let n = 1;
    #[cfg(not(target_arch = "x86_64"))]
    let n = core::cmp::max(num_cpus, 1);
    let barrier = SYNC.get_or_init(|| Barrier::new(n));

    if barrier.wait().is_leader() {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // Print banner directly to serial as a fallback
            for &b in S.as_bytes() { crate::serial_out(b); }
            let hint = b"type `help` to list available commands\r\n";
            for &b in hint { crate::serial_out(b); }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            tracing::info!("{S}");
            tracing::info!("type `help` to list available commands (cpus={n})");
        }

        #[cfg(target_arch = "x86_64")]
        {
            // For x86_64, spawn a simple polling-based serial console
            sched
                .try_spawn(async move {
                    x86_serial_console().await;
                })
                .unwrap();
        }

        // For RISC-V, use the UART from device tree
        #[cfg(not(target_arch = "x86_64"))]
        sched
            .try_spawn(async move {
                let (mut uart, _mmap, irq_num) = init_uart(devtree);

                let mut line = String::new();
                loop {
                    let res = irq::next_event(irq_num).await;
                    assert!(res.is_ok());
                    let mut newline = false;

                    let ch = uart.recv() as char;
                    uart.write_char(ch).unwrap();
                    match ch {
                        '\n' | '\r' => {
                            newline = true;
                            uart.write_str("\n\r").unwrap();
                        }
                        '\u{007F}' => {
                            line.pop();
                        }
                        ch => line.push(ch),
                    }

                    if newline {
                        eval(&line);
                        line.clear();
                    }
                }
            })
            .unwrap();
    }
}

// x86_64: variant of init that does not require a DeviceTree reference
#[cfg(target_arch = "x86_64")]
pub fn init_x86(sched: &'static Executor, num_cpus: usize) {
    let _ = num_cpus; // not used

    unsafe { crate::serial_out(b'<'); crate::serial_out(b'i'); crate::serial_out(b'n'); crate::serial_out(b'i'); crate::serial_out(b't'); crate::serial_out(b'>'); }

    unsafe {
        crate::serial_out(b'<'); crate::serial_out(b'C'); crate::serial_out(b'O'); crate::serial_out(b'M'); crate::serial_out(b'1'); crate::serial_out(b'>');
        // Initialize COM1 properly
        const COM1_BASE: u16 = 0x3F8;
        const IER: u16 = COM1_BASE + 1;
        const FCR: u16 = COM1_BASE + 2;
        const LCR: u16 = COM1_BASE + 3;
        const MCR: u16 = COM1_BASE + 4;

        // Disable interrupts
        core::arch::asm!("out dx, al", in("dx") IER, in("al") 0u8, options(nomem, preserves_flags));
        // Enable FIFO, clear them, with 14-byte threshold
        core::arch::asm!("out dx, al", in("dx") FCR, in("al") 0xC7u8, options(nomem, preserves_flags));
        // 8 bits, no parity, one stop bit
        core::arch::asm!("out dx, al", in("dx") LCR, in("al") 0x03u8, options(nomem, preserves_flags));
        // RTS/DSR set
        core::arch::asm!("out dx, al", in("dx") MCR, in("al") 0x03u8, options(nomem, preserves_flags));

        crate::serial_out(b'<'); crate::serial_out(b'P'); crate::serial_out(b'R'); crate::serial_out(b'I'); crate::serial_out(b'N'); crate::serial_out(b'T'); crate::serial_out(b'>');

        // Print simple test message
        crate::serial_out(b'\r');
        crate::serial_out(b'\n');
        crate::serial_out(b'T');
        crate::serial_out(b'E');
        crate::serial_out(b'S');
        crate::serial_out(b'T');
        crate::serial_out(b'\r');
        crate::serial_out(b'\n');

    }

    // Don't spawn async task - we'll use synchronous shell instead
    unsafe { crate::serial_out(b'<'); crate::serial_out(b'/'); crate::serial_out(b'i'); crate::serial_out(b'n'); crate::serial_out(b'i'); crate::serial_out(b't'); crate::serial_out(b'>'); }
}

// Non-async blocking version of serial console for x86_64
#[cfg(target_arch = "x86_64")]
pub fn x86_serial_console_sync() -> ! {
    unsafe { crate::serial_out(b'{'); crate::serial_out(b'S'); crate::serial_out(b'Y'); crate::serial_out(b'N'); crate::serial_out(b'C'); crate::serial_out(b'}'); }

    use alloc::string::String;

    unsafe { crate::serial_out(b'1'); }

    const COM1_BASE: u16 = 0x3F8;
    const DATA_REG: u16 = COM1_BASE;
    const LINE_STATUS_REG: u16 = COM1_BASE + 5;

    unsafe { crate::serial_out(b'2'); }

    fn has_data() -> bool {
        unsafe {
            let status: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") status,
                in("dx") LINE_STATUS_REG,
                options(nomem, preserves_flags)
            );
            status & 0x01 != 0
        }
    }

    fn read_byte() -> u8 {
        unsafe {
            let data: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") data,
                in("dx") DATA_REG,
                options(nomem, preserves_flags)
            );
            data
        }
    }

    fn write_byte(byte: u8) {
        // Use the known-working serial_out from main.rs
        // Avoid all status checks which cause hangs
        unsafe {
            crate::serial_out(byte);
        }
    }

    fn write_str(s: &str) {
        for b in s.bytes() { write_byte(b); }
    }

    unsafe { crate::serial_out(b'3'); }

    let mut line_buffer = String::new();

    unsafe { crate::serial_out(b'4'); }

    // Signal that we're in the input loop - use simple ASCII
    write_byte(b'R');
    write_byte(b'E');
    write_byte(b'A');
    write_byte(b'D');
    write_byte(b'Y');
    write_byte(b'\r');
    write_byte(b'\n');
    write_byte(b'>');
    write_byte(b' ');

    unsafe { crate::serial_out(b'5'); }

    // Initialize PIC (Programmable Interrupt Controller)
    unsafe {
        // ICW1: Initialize PIC
        core::arch::asm!("out 0x20, al", in("al") 0x11u8, options(nomem, nostack));
        core::arch::asm!("out 0xA0, al", in("al") 0x11u8, options(nomem, nostack));

        // ICW2: Set vector offsets (master at 32, slave at 40)
        core::arch::asm!("out 0x21, al", in("al") 32u8, options(nomem, nostack));
        core::arch::asm!("out 0xA1, al", in("al") 40u8, options(nomem, nostack));

        // ICW3: Tell master there's a slave at IRQ2
        core::arch::asm!("out 0x21, al", in("al") 0x04u8, options(nomem, nostack));
        core::arch::asm!("out 0xA1, al", in("al") 0x02u8, options(nomem, nostack));

        // ICW4: 8086 mode
        core::arch::asm!("out 0x21, al", in("al") 0x01u8, options(nomem, nostack));
        core::arch::asm!("out 0xA1, al", in("al") 0x01u8, options(nomem, nostack));

        // Unmask all interrupts (OCW1)
        core::arch::asm!("out 0x21, al", in("al") 0x00u8, options(nomem, nostack));
        core::arch::asm!("out 0xA1, al", in("al") 0x00u8, options(nomem, nostack));
    }

    unsafe { crate::serial_out(b'P'); } // PIC initialized

    // Enable serial port interrupts
    // IER (Interrupt Enable Register) = COM1_BASE + 1
    const INTERRUPT_ENABLE_REG: u16 = COM1_BASE + 1;
    unsafe {
        // Enable "Received Data Available" interrupt (bit 0)
        core::arch::asm!(
            "out dx, al",
            in("al") 0x01u8,  // Enable RX interrupt
            in("dx") INTERRUPT_ENABLE_REG,
            options(nomem, preserves_flags)
        );
    }

    // Try to initialize serial port FIFO to clear any stale data
    // FCR (FIFO Control Register) = COM1_BASE + 2
    const FIFO_CONTROL_REG: u16 = COM1_BASE + 2;
    unsafe {
        // Enable FIFO and clear both RX and TX FIFOs
        core::arch::asm!(
            "out dx, al",
            in("al") 0x07u8,  // Enable FIFO (bit 0), Clear RX (bit 1), Clear TX (bit 2)
            in("dx") FIFO_CONTROL_REG,
            options(nomem, preserves_flags)
        );
    }

    unsafe { crate::serial_out(b'I'); } // Serial interrupt enabled

    // Enable CPU interrupts with STI
    unsafe {
        core::arch::asm!("sti", options(nomem, nostack));
    }

    unsafe { crate::serial_out(b'S'); } // STI executed

    // Skip command testing - it causes issues
    // Just show that we reached this point and start heartbeat

    write_byte(b'O');
    write_byte(b'K');
    write_byte(b'\r');
    write_byte(b'\n');

    let mut heartbeat_counter = 0u32;

    unsafe { crate::serial_out(b'6'); }

    // Output prompt using simple write_byte to avoid corruption
    write_byte(b'>');
    write_byte(b' ');

    loop {
        // Check for input from interrupt buffer
        if let Some(ch) = try_read_serial() {
            // Process the character
            if ch >= 32 && ch < 127 || ch == b'\r' || ch == b'\n' {
                // Echo the character
                write_byte(ch);

                if ch == b'\r' || ch == b'\n' {
                    write_byte(b'\r');
                    write_byte(b'\n');

                    // Process command
                    let trimmed = line_buffer.trim();
                    if !trimmed.is_empty() {
                        // Just echo "CMD:" and the command for now
                        // Avoid complex string operations that cause corruption
                        write_byte(b'C');
                        write_byte(b'M');
                        write_byte(b'D');
                        write_byte(b':');
                        for b in trimmed.bytes() {
                            write_byte(b);
                        }
                        write_byte(b'\r');
                        write_byte(b'\n');
                    }

                    line_buffer.clear();
                    write_byte(b'>');
                    write_byte(b' ');
                } else {
                    // Add to line buffer
                    line_buffer.push(ch as char);
                }
            }
        }

        // Small delay when no input
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

fn init_uart(devtree: &DeviceTree) -> (uart_16550::SerialPort, Mmap, u32) {
    let s = devtree.find_by_path("/soc/serial").unwrap();
    assert!(s.is_compatible(["ns16550a"]));

    let clock_freq = s.property("clock-frequency").unwrap().as_u32().unwrap();
    let mut regs = s.regs().unwrap();
    let reg = regs.next().unwrap().unwrap();
    assert!(regs.next().unwrap().is_none());
    let irq_num = s.property("interrupts").unwrap().as_u32().unwrap();

    let mmap = with_kernel_aspace(|aspace| {
        // FIXME: this is gross, we're using the PhysicalAddress as an alignment utility :/
        let size = PhysicalAddress::new(reg.size.unwrap())
            .checked_align_up(arch::PAGE_SIZE)
            .unwrap()
            .get();

        let range_phys = {
            let start = PhysicalAddress::new(reg.starting_address);
            Range::from(start..start.checked_add(size).unwrap())
        };

        let mmap = Mmap::new_phys(
            aspace.clone(),
            range_phys,
            size,
            arch::PAGE_SIZE,
            Some("UART-16550".to_string()),
        )
        .unwrap();

        mmap.commit(aspace.lock().deref_mut(), Range::from(0..size), true)
            .unwrap();

        mmap
    });

    // Safety: info comes from device tree
    let uart = unsafe { uart_16550::SerialPort::new(mmap.range().start.get(), clock_freq, 115200) };

    (uart, mmap, irq_num)
}

#[cfg(target_arch = "x86_64")]
pub async fn x86_serial_console() -> ! {
    unsafe { crate::serial_out(b'{'); crate::serial_out(b'C'); crate::serial_out(b'O'); crate::serial_out(b'N'); crate::serial_out(b'S'); crate::serial_out(b'O'); crate::serial_out(b'L'); crate::serial_out(b'E'); crate::serial_out(b'}'); }

    use alloc::string::String;

    use kasync::task::yield_now;

    const COM1_BASE: u16 = 0x3F8;
    const DATA_REG: u16 = COM1_BASE + 0;
    const IER: u16 = COM1_BASE + 1;
    const FCR: u16 = COM1_BASE + 2;
    const LCR: u16 = COM1_BASE + 3;
    const MCR: u16 = COM1_BASE + 4;
    const LINE_STATUS_REG: u16 = COM1_BASE + 5;

    // Helper to check if data is available
    fn has_data() -> bool {
        unsafe {
            let status: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") status,
                in("dx") LINE_STATUS_REG,
                options(nomem, preserves_flags)
            );
            status & 0x01 != 0
        }
    }

    // Helper to read a byte from serial port
    fn read_byte() -> u8 {
        unsafe {
            let data: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") data,
                in("dx") DATA_REG,
                options(nomem, preserves_flags)
            );
            data
        }
    }

    // Helper to write a byte to serial port
    fn write_byte(byte: u8) {
        unsafe {
            // Wait for transmit buffer to be empty
            loop {
                let status: u8;
                core::arch::asm!(
                    "in al, dx",
                    out("al") status,
                    in("dx") LINE_STATUS_REG,
                    options(nomem, preserves_flags)
                );
                if status & 0x20 != 0 {
                    break;
                }
            }

            // Write the byte
            core::arch::asm!(
                "out dx, al",
                in("al") byte,
                in("dx") DATA_REG,
                options(nomem, preserves_flags)
            );
        }
    }

    // Minimal 16550 init for reliable RX/TX on QEMU
    fn serial_init() {
        unsafe {
            // Disable interrupts
            core::arch::asm!("out dx, al", in("dx") IER, in("al") 0u8, options(nomem, preserves_flags));
            // Enable DLAB
            core::arch::asm!("out dx, al", in("dx") LCR, in("al") 0x80u8, options(nomem, preserves_flags));
            // Set baud to 115200 (divisor = 1)
            core::arch::asm!("out dx, al", in("dx") DATA_REG, in("al") 0x01u8, options(nomem, preserves_flags)); // DLL
            core::arch::asm!("out dx, al", in("dx") IER, in("al") 0x00u8, options(nomem, preserves_flags));     // DLM
            // 8N1, clear DLAB
            core::arch::asm!("out dx, al", in("dx") LCR, in("al") 0x03u8, options(nomem, preserves_flags));
            // Enable FIFO, clear, 14-byte threshold
            core::arch::asm!("out dx, al", in("dx") FCR, in("al") 0xC7u8, options(nomem, preserves_flags));
            // RTS/DSR set, OUT2 set
            core::arch::asm!("out dx, al", in("dx") MCR, in("al") 0x0Bu8, options(nomem, preserves_flags));
        }
    }

    // Helper to write a string
    fn write_str(s: &str) {
        for b in s.bytes() { write_byte(b); }
    }

    // Initialize COM1 then print a clear startup pattern
    serial_init();

    // Output VERY distinctive pattern
    unsafe {
    }
    write_str("CXLOS x86_64 Shell\r\n");
    write_str("type `help` to list available commands\r\n> ");

    let mut line = String::new();

    loop {
        // Poll for input
        if has_data() {
            let ch = read_byte() as char;

            match ch {
                '\r' | '\n' => {
                    // Echo newline
                    write_byte(b'\r');
                    write_byte(b'\n');

                    // Process the command
                    if !line.is_empty() {
                        eval(&line);
                        line.clear();
                        write_str("> ");
                    }
                }
                '\x7F' | '\x08' => {
                    // Backspace or Delete
                    if !line.is_empty() {
                        line.pop();
                        // Echo backspace sequence: backspace, space, backspace
                        write_byte(b'\x08');
                        write_byte(b' ');
                        write_byte(b'\x08');
                    }
                }
                '\x03' => {
                    // Ctrl+C
                    write_byte(b'^');
                    write_byte(b'C');
                    write_byte(b'\r');
                    write_byte(b'\n');
                    line.clear();
                    write_str("> ");
                }
                ch if ch.is_ascii() && !ch.is_control() => {
                    line.push(ch);
                    // Echo the character
                    write_byte(ch as u8);
                }
                _ => {
                    // Ignore non-printable characters
                }
            }
        } else {
            // Yield to other tasks when no input is available
            yield_now().await;
        }
    }
}

pub fn eval(line: &str) {
    if line == "help" {
        // Non-x86_64: use tracing
        #[cfg(not(target_arch = "x86_64"))]
        {
            tracing::info!(target: "shell", "available commands:");
            print_help("", COMMANDS);
            tracing::info!(target: "shell", "");
            tracing::info!(target: "shell", "BusyBox commands:");
            tracing::info!(target: "shell", "  busybox --- list all busybox commands");
            tracing::info!(target: "shell", "  or run any busybox command directly (e.g., echo, pwd, uname)");
        }

        // x86_64: print directly to serial; avoid tracing to prevent hangs
        #[cfg(target_arch = "x86_64")]
        {
            serial_write_line_blocking("available commands:");
            for cmd in COMMANDS {
                use core::fmt::Write;
                let mut buf = alloc::string::String::new();
                let _ = write!(&mut buf, "  {}", cmd);
                serial_write_line_blocking(&buf);
            }
            serial_write_line_blocking("");
            serial_write_line_blocking("BusyBox commands:");
            serial_write_line_blocking("  busybox --- list all busybox commands");
            serial_write_line_blocking("  or run any busybox command directly (e.g., echo, pwd, uname)");
        }
        return;
    }

    if line == "busybox" {
        // Non-x86_64: use tracing
        #[cfg(not(target_arch = "x86_64"))]
        {
            tracing::info!(target: "shell", "BusyBox v1.36.1 commands:");
            for cmd in busybox::BUSYBOX_COMMANDS {
                tracing::info!(target: "shell", "  {} --- {}", cmd.name, cmd.description);
            }
        }
        // x86_64: mirror list to serial only
        #[cfg(target_arch = "x86_64")]
        {
            serial_write_line_blocking("BusyBox v1.36.1 commands:");
            for cmd in busybox::BUSYBOX_COMMANDS {
                use core::fmt::Write;
                let mut buf = alloc::string::String::new();
                let _ = write!(&mut buf, "  {} --- {}", cmd.name, cmd.description);
                serial_write_line_blocking(&buf);
            }
        }
        return;
    }

    // Try to handle as a busybox command first
    let parts: alloc::vec::Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
    if !parts.is_empty() {
        // Try WASM BusyBox for simple no-arg commands if initialized
        #[cfg(not(target_arch = "x86_64"))]
        if busybox::wasm_loader::is_initialized() {
            let cmd = parts[0].as_str();
            let args: alloc::vec::Vec<&str> = parts.iter().skip(1).map(|s| s.as_str()).collect();
            if let Ok(true) = busybox::wasm_loader::call_busybox(cmd, &args) {
                return;
            }
        }

        if let Some(impl_fn) = commands::get_command_impl(&parts[0]) {
            let mut ctx = commands::CommandContext::new(parts);
            match impl_fn.execute(&mut ctx) {
                Ok(output) => {
                    if !output.is_empty() {
                        #[cfg(not(target_arch = "x86_64"))]
                        {
                            tracing::info!(target: "shell", "{}", output.trim_end());
                        }
                        #[cfg(target_arch = "x86_64")]
                        {
                            if output.ends_with('\n') {
                                // already terminated
                                serial_write_str_blocking(&output);
                            } else {
                                serial_write_line_blocking(&output);
                            }
                        }
                    }
                    return;
                }
                Err(e) => {
                    #[cfg(not(target_arch = "x86_64"))]
                    {
                        tracing::error!(target: "shell", "{}: {}", ctx.args[0], e);
                    }
                    #[cfg(target_arch = "x86_64")]
                    {
                        use core::fmt::Write;
                        let mut buf = alloc::string::String::new();
                        let _ = write!(&mut buf, "{}: {}", ctx.args[0], e);
                        serial_write_line_blocking(&buf);
                    }
                    return;
                }
            }
        }
    }

    match handle_command(Context::new(line), COMMANDS) {
        Ok(_) => {}
        Err(error) => tracing::error!(target: "shell", "error: {error}"),
    }
}

const PANIC: Command = Command::new("panic")
    .with_usage("<MESSAGE>")
    .with_help("cause a kernel panic with the given message. use with caution.")
    .with_fn(|line| {
        panic!("{}", line.current);
    });

const FAULT: Command = Command::new("fault")
    .with_help("cause a CPU fault (null pointer dereference). use with caution.")
    .with_fn(|_| {
        // Safety: This actually *is* unsafe and *is* causing problematic behaviour, but that is exactly what
        // we want here!
        unsafe {
            #[expect(clippy::zero_ptr, reason = "we actually want to cause a fault here")]
            (0x0 as *const u8).read_volatile();
        }
        Ok(())
    });

const VERSION: Command = Command::new("version")
    .with_help("print verbose build and version info.")
    .with_fn(|_| {
        tracing::info!("k23 v{}", env!("CARGO_PKG_VERSION"));
        let git_branch = option_env!("VERGEN_GIT_BRANCH").unwrap_or("unknown");
        let git_sha = option_env!("VERGEN_GIT_SHA").unwrap_or("unknown");
        tracing::info!(build.version = %format!(
            "{}-{}.{}",
            env!("CARGO_PKG_VERSION"),
            git_branch,
            git_sha
        ));
        tracing::info!(build.timestamp = %env!("VERGEN_BUILD_TIMESTAMP"));
        tracing::info!(build.opt_level = %env!("VERGEN_CARGO_OPT_LEVEL"));
        tracing::info!(build.target = %env!("VERGEN_CARGO_TARGET_TRIPLE"));
        let git_commit_ts = option_env!("VERGEN_GIT_COMMIT_TIMESTAMP").unwrap_or("unknown");
        tracing::info!(commit.sha = %git_sha);
        tracing::info!(commit.branch = %git_branch);
        tracing::info!(commit.date = %git_commit_ts);
        tracing::info!(rustc.version = %env!("VERGEN_RUSTC_SEMVER"));
        tracing::info!(rustc.channel = %env!("VERGEN_RUSTC_CHANNEL"));

        Ok(())
    });

const SHUTDOWN: Command = Command::new("shutdown")
    .with_help("exit the kernel and shutdown the machine.")
    .with_fn(|_| {
        tracing::info!("Bye, Bye!");

        global().executor.close();

        Ok(())
    });

#[cfg(target_arch = "x86_64")]
const BOOT: Command = Command::new("boot")
    .with_help("continue full kernel boot from the early console.")
    .with_fn(|_| {
        // Signal the early console loop to exit and continue normal boot
        crate::request_continue_boot();
        #[cfg(target_arch = "x86_64")]
        unsafe { super::serial_out(b'\r'); super::serial_out(b'\n'); }
        Ok(())
    });

#[cfg(not(target_arch = "x86_64"))]
const BOOT: Command = Command::new("boot")
    .with_help("not available on this architecture")
    .with_fn(|_| Ok(()));

#[derive(Debug)]
pub struct Command<'cmd> {
    name: &'cmd str,
    help: &'cmd str,
    usage: &'cmd str,
    run: fn(Context<'_>) -> CmdResult<'_>,
}

pub type CmdResult<'a> = Result<(), Error<'a>>;

#[derive(Debug)]
pub struct Error<'a> {
    line: &'a str,
    kind: ErrorKind<'a>,
}

#[derive(Debug)]
enum ErrorKind<'a> {
    UnknownCommand(&'a [Command<'a>]),
    InvalidArguments {
        help: &'a str,
        arg: &'a str,
        flag: Option<&'a str>,
    },
    FlagRequired {
        flags: &'a [&'a str],
    },
    Other(&'static str),
}

#[derive(Copy, Clone)]
pub struct Context<'cmd> {
    line: &'cmd str,
    current: &'cmd str,
}

fn print_help(parent_cmd: &str, commands: &[Command]) {
    let parent_cmd_pad = if parent_cmd.is_empty() { "" } else { " " };
    for command in commands {
        tracing::info!(target: "shell", "  {parent_cmd}{parent_cmd_pad}{command}");
    }
    tracing::info!(target: "shell", "  {parent_cmd}{parent_cmd_pad}help --- prints this help message");
}

fn handle_command<'cmd>(ctx: Context<'cmd>, commands: &'cmd [Command]) -> CmdResult<'cmd> {
    let chunk = ctx.current.trim();
    for cmd in commands {
        if let Some(current) = chunk.strip_prefix(cmd.name) {
            let current = current.trim();

            return panic_unwind2::catch_unwind(|| cmd.run(Context { current, ..ctx })).unwrap_or(
                {
                    Err(Error {
                        line: cmd.name,
                        kind: ErrorKind::Other("command failed"),
                    })
                },
            );
        }
    }

    Err(ctx.unknown_command(commands))
}

// === impl Command ===

impl<'cmd> Command<'cmd> {
    #[must_use]
    pub const fn new(name: &'cmd str) -> Self {
        #[cold]
        fn invalid_command(_ctx: Context<'_>) -> CmdResult<'_> {
            panic!("command is missing run function, this is a bug");
        }

        Self {
            name,
            help: "",
            usage: "",
            run: invalid_command,
        }
    }

    #[must_use]
    pub const fn with_help(self, help: &'cmd str) -> Self {
        Self { help, ..self }
    }

    #[must_use]
    pub const fn with_usage(self, usage: &'cmd str) -> Self {
        Self { usage, ..self }
    }

    #[must_use]
    pub const fn with_fn(self, run: fn(Context<'_>) -> CmdResult<'_>) -> Self {
        Self { run, ..self }
    }

    pub fn run<'ctx>(&'cmd self, ctx: Context<'ctx>) -> CmdResult<'ctx>
    where
        'cmd: 'ctx,
    {
        let current = ctx.current.trim();

        if current == "help" {
            let name = ctx.line.strip_suffix(" help").unwrap_or("<???BUG???>");
            tracing::info!(target: "shell", "{name}");

            return Ok(());
        }

        (self.run)(ctx)
    }
}

impl fmt::Display for Command<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            run: _func,
            name,
            help,
            usage,
        } = self;

        write!(
            f,
            "{name}{usage_pad}{usage} --- {help}",
            usage_pad = if !usage.is_empty() { " " } else { "" },
        )
    }
}

// === impl Error ===

impl fmt::Display for Error<'_> {
    fn fmt(&self, mut f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn command_names<'cmd>(
            cmds: &'cmd [Command<'cmd>],
        ) -> impl Iterator<Item = &'cmd str> + 'cmd {
            cmds.iter()
                .map(|Command { name, .. }| *name)
                .chain(core::iter::once("help"))
        }

        fn fmt_flag_names(f: &mut fmt::Formatter<'_>, flags: &[&str]) -> fmt::Result {
            let mut names = flags.iter();
            if let Some(name) = names.next() {
                f.write_str(name)?;
                for name in names {
                    write!(f, "|{name}")?;
                }
            }
            Ok(())
        }

        let Self { line, kind } = self;
        match kind {
            ErrorKind::UnknownCommand(commands) => {
                write!(f, "unknown command {line:?}, expected one of: [")?;
                comma_delimited(&mut f, command_names(commands))?;
                f.write_char(']')?;
            }
            ErrorKind::InvalidArguments { help, arg, flag } => {
                f.write_str("invalid argument")?;
                if let Some(flag) = flag {
                    write!(f, " {flag}")?;
                }
                write!(f, " {arg:?}: {help}")?;
            }
            ErrorKind::FlagRequired { flags } => {
                write!(f, "the '{line}' command requires the ")?;
                fmt_flag_names(f, flags)?;
                write!(f, " flag")?;
            }
            ErrorKind::Other(msg) => write!(f, "could not execute {line:?}: {msg}")?,
        }

        Ok(())
    }
}

impl core::error::Error for Error<'_> {}

fn comma_delimited<F: fmt::Display>(
    mut writer: impl Write,
    values: impl IntoIterator<Item = F>,
) -> fmt::Result {
    let mut values = values.into_iter();
    if let Some(value) = values.next() {
        write!(writer, "{value}")?;
        for value in values {
            write!(writer, ", {value}")?;
        }
    }

    Ok(())
}

// === impl Context ===

impl<'cmd> Context<'cmd> {
    pub const fn new(line: &'cmd str) -> Self {
        Self {
            line,
            current: line,
        }
    }

    pub fn command(&self) -> &'cmd str {
        self.current.trim()
    }

    fn unknown_command(&self, commands: &'cmd [Command]) -> Error<'cmd> {
        Error {
            line: self.line,
            kind: ErrorKind::UnknownCommand(commands),
        }
    }

    pub fn invalid_argument(&self, help: &'static str) -> Error<'cmd> {
        Error {
            line: self.line,
            kind: ErrorKind::InvalidArguments {
                arg: self.current,
                flag: None,
                help,
            },
        }
    }

    pub fn invalid_argument_named(&self, name: &'static str, help: &'static str) -> Error<'cmd> {
        Error {
            line: self.line,
            kind: ErrorKind::InvalidArguments {
                arg: self.current,
                flag: Some(name),
                help,
            },
        }
    }

    pub fn other_error(&self, msg: &'static str) -> Error<'cmd> {
        Error {
            line: self.line,
            kind: ErrorKind::Other(msg),
        }
    }

    pub fn parse_bool_flag(&mut self, flag: &str) -> bool {
        if let Some(rest) = self.command().trim().strip_prefix(flag) {
            self.current = rest.trim();
            true
        } else {
            false
        }
    }

    pub fn parse_optional_u32_hex_or_dec(
        &mut self,
        name: &'static str,
    ) -> Result<Option<u32>, Error<'cmd>> {
        let (chunk, rest) = match self.command().split_once(" ") {
            Some((chunk, rest)) => (chunk.trim(), rest),
            None => (self.command(), ""),
        };

        if chunk.is_empty() {
            return Ok(None);
        }

        let val = if let Some(hex_num) = chunk.strip_prefix("0x") {
            u32::from_str_radix(hex_num.trim(), 16).map_err(|_| Error {
                line: self.line,
                kind: ErrorKind::InvalidArguments {
                    arg: chunk,
                    flag: Some(name),
                    help: "expected a 32-bit hex number",
                },
            })?
        } else {
            u32::from_str(chunk).map_err(|_| Error {
                line: self.line,
                kind: ErrorKind::InvalidArguments {
                    arg: chunk,
                    flag: Some(name),
                    help: "expected a 32-bit decimal number",
                },
            })?
        };

        self.current = rest;
        Ok(Some(val))
    }

    pub fn parse_u32_hex_or_dec(&mut self, name: &'static str) -> Result<u32, Error<'cmd>> {
        self.parse_optional_u32_hex_or_dec(name).and_then(|val| {
            val.ok_or_else(|| self.invalid_argument_named(name, "expected a number"))
        })
    }

    pub fn parse_optional_flag<T>(
        &mut self,
        names: &'static [&'static str],
    ) -> Result<Option<T>, Error<'cmd>>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        for name in names {
            if let Some(rest) = self.command().strip_prefix(name) {
                let (chunk, rest) = match rest.trim().split_once(" ") {
                    Some((chunk, rest)) => (chunk.trim(), rest),
                    None => (rest, ""),
                };

                if chunk.is_empty() {
                    return Err(Error {
                        line: self.line,
                        kind: ErrorKind::InvalidArguments {
                            arg: chunk,
                            flag: Some(name),
                            help: "expected a value",
                        },
                    });
                }

                match chunk.parse() {
                    Ok(val) => {
                        self.current = rest;
                        return Ok(Some(val));
                    }
                    Err(e) => {
                        tracing::warn!(target: "shell", "invalid value {chunk:?} for flag {name}: {e}");
                        return Err(Error {
                            line: self.line,
                            kind: ErrorKind::InvalidArguments {
                                arg: chunk,
                                flag: Some(name),
                                help: "invalid value",
                            },
                        });
                    }
                }
            }
        }

        Ok(None)
    }

    pub fn parse_required_flag<T>(
        &mut self,
        names: &'static [&'static str],
    ) -> Result<T, Error<'cmd>>
    where
        T: FromStr,
        T::Err: fmt::Display,
    {
        self.parse_optional_flag(names).and_then(|val| {
            val.ok_or(Error {
                line: self.line,
                kind: ErrorKind::FlagRequired { flags: names },
            })
        })
    }
}
