// Copyright 2025 bubblepipe
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! PS/2 keyboard driver for x86_64

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const PS2_DATA_PORT: u16 = 0x60;
const PS2_STATUS_PORT: u16 = 0x64;

// Ring buffer for keyboard input
const KEYBOARD_BUFFER_SIZE: usize = 256;
static KEYBOARD_BUFFER: [AtomicU8; KEYBOARD_BUFFER_SIZE] =
    [const { AtomicU8::new(0) }; KEYBOARD_BUFFER_SIZE];
static KEYBOARD_READ_POS: AtomicUsize = AtomicUsize::new(0);
static KEYBOARD_WRITE_POS: AtomicUsize = AtomicUsize::new(0);

/// US QWERTY scancode set 1 to ASCII mapping (make codes only)
pub fn scancode_to_ascii(scancode: u8, shifted: bool) -> Option<char> {
    if shifted {
        match scancode {
            0x02 => Some('!'),
            0x03 => Some('@'),
            0x04 => Some('#'),
            0x05 => Some('$'),
            0x06 => Some('%'),
            0x07 => Some('^'),
            0x08 => Some('&'),
            0x09 => Some('*'),
            0x0A => Some('('),
            0x0B => Some(')'),
            0x0C => Some('_'),
            0x0D => Some('+'),
            0x10 => Some('Q'),
            0x11 => Some('W'),
            0x12 => Some('E'),
            0x13 => Some('R'),
            0x14 => Some('T'),
            0x15 => Some('Y'),
            0x16 => Some('U'),
            0x17 => Some('I'),
            0x18 => Some('O'),
            0x19 => Some('P'),
            0x1A => Some('{'),
            0x1B => Some('}'),
            0x1E => Some('A'),
            0x1F => Some('S'),
            0x20 => Some('D'),
            0x21 => Some('F'),
            0x22 => Some('G'),
            0x23 => Some('H'),
            0x24 => Some('J'),
            0x25 => Some('K'),
            0x26 => Some('L'),
            0x27 => Some(':'),
            0x28 => Some('"'),
            0x2B => Some('|'),
            0x2C => Some('Z'),
            0x2D => Some('X'),
            0x2E => Some('C'),
            0x2F => Some('V'),
            0x30 => Some('B'),
            0x31 => Some('N'),
            0x32 => Some('M'),
            0x33 => Some('<'),
            0x34 => Some('>'),
            0x35 => Some('?'),
            0x39 => Some(' '),
            _ => None,
        }
    } else {
        match scancode {
            0x02 => Some('1'),
            0x03 => Some('2'),
            0x04 => Some('3'),
            0x05 => Some('4'),
            0x06 => Some('5'),
            0x07 => Some('6'),
            0x08 => Some('7'),
            0x09 => Some('8'),
            0x0A => Some('9'),
            0x0B => Some('0'),
            0x0C => Some('-'),
            0x0D => Some('='),
            0x0E => Some('\x08'), // Backspace
            0x10 => Some('q'),
            0x11 => Some('w'),
            0x12 => Some('e'),
            0x13 => Some('r'),
            0x14 => Some('t'),
            0x15 => Some('y'),
            0x16 => Some('u'),
            0x17 => Some('i'),
            0x18 => Some('o'),
            0x19 => Some('p'),
            0x1A => Some('['),
            0x1B => Some(']'),
            0x1C => Some('\n'), // Enter
            0x1E => Some('a'),
            0x1F => Some('s'),
            0x20 => Some('d'),
            0x21 => Some('f'),
            0x22 => Some('g'),
            0x23 => Some('h'),
            0x24 => Some('j'),
            0x25 => Some('k'),
            0x26 => Some('l'),
            0x27 => Some(';'),
            0x28 => Some('\''),
            0x29 => Some('`'),
            0x2B => Some('\\'),
            0x2C => Some('z'),
            0x2D => Some('x'),
            0x2E => Some('c'),
            0x2F => Some('v'),
            0x30 => Some('b'),
            0x31 => Some('n'),
            0x32 => Some('m'),
            0x33 => Some(','),
            0x34 => Some('.'),
            0x35 => Some('/'),
            0x39 => Some(' '),
            _ => None,
        }
    }
}

/// Check if a scancode is a shift key press
pub fn is_shift_pressed(scancode: u8) -> bool {
    scancode == 0x2A || scancode == 0x36  // Left or right shift
}

/// Check if a scancode is a shift key release
pub fn is_shift_released(scancode: u8) -> bool {
    scancode == 0xAA || scancode == 0xB6  // Left or right shift release
}

/// Try to read a scancode from the PS/2 keyboard
pub fn try_read_scancode() -> Option<u8> {
    unsafe {
        // Check if data is available
        let status: u8;
        core::arch::asm!(
            "in al, dx",
            out("al") status,
            in("dx") PS2_STATUS_PORT,
            options(nomem, preserves_flags)
        );

        // Bit 0 = output buffer full (data available)
        if (status & 0x01) != 0 {
            // Read the scancode
            let scancode: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") scancode,
                in("dx") PS2_DATA_PORT,
                options(nomem, preserves_flags)
            );
            Some(scancode)
        } else {
            None
        }
    }
}

/// Called from interrupt handler or polling loop
pub fn on_keyboard_scancode(scancode: u8) {
    let write_pos = KEYBOARD_WRITE_POS.load(Ordering::Acquire);
    let read_pos = KEYBOARD_READ_POS.load(Ordering::Acquire);
    let next_write = (write_pos + 1) % KEYBOARD_BUFFER_SIZE;

    // Check if buffer is full
    if next_write != read_pos {
        KEYBOARD_BUFFER[write_pos].store(scancode, Ordering::Release);
        KEYBOARD_WRITE_POS.store(next_write, Ordering::Release);
    }
}

/// Try to read a scancode from the buffer
pub fn try_read_from_buffer() -> Option<u8> {
    let read_pos = KEYBOARD_READ_POS.load(Ordering::Acquire);
    let write_pos = KEYBOARD_WRITE_POS.load(Ordering::Acquire);

    if read_pos == write_pos {
        None
    } else {
        let scancode = KEYBOARD_BUFFER[read_pos].load(Ordering::Acquire);
        let next_read = (read_pos + 1) % KEYBOARD_BUFFER_SIZE;
        KEYBOARD_READ_POS.store(next_read, Ordering::Release);
        Some(scancode)
    }
}
