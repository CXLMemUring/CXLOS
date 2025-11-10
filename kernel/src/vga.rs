// Copyright 2025 bubblepipe
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! VGA text mode driver for x86_64

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

const VGA_BUFFER: usize = 0xB8000;
const VGA_WIDTH: usize = 80;
const VGA_HEIGHT: usize = 25;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

static COLUMN: AtomicUsize = AtomicUsize::new(0);
static ROW: AtomicUsize = AtomicUsize::new(0);

pub struct Writer {
    color_code: ColorCode,
}

impl Writer {
    pub fn new() -> Self {
        Writer {
            color_code: ColorCode::new(Color::LightGray, Color::Black),
        }
    }

    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => self.new_line(),
            b'\r' => {
                COLUMN.store(0, Ordering::SeqCst);
            }
            byte => {
                let row = ROW.load(Ordering::SeqCst);
                let col = COLUMN.load(Ordering::SeqCst);

                if col >= VGA_WIDTH {
                    self.new_line();
                }

                let row = ROW.load(Ordering::SeqCst);
                let col = COLUMN.load(Ordering::SeqCst);

                let offset = row * VGA_WIDTH + col;
                let buffer = VGA_BUFFER as *mut ScreenChar;

                unsafe {
                    buffer.add(offset).write_volatile(ScreenChar {
                        ascii_character: byte,
                        color_code: self.color_code,
                    });
                }

                COLUMN.store(col + 1, Ordering::SeqCst);
            }
        }
    }

    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            match byte {
                // Printable ASCII or newline
                0x20..=0x7e | b'\n' | b'\r' => self.write_byte(byte),
                // Not part of printable ASCII range
                _ => self.write_byte(0xfe), // ■
            }
        }
    }

    fn new_line(&mut self) {
        let row = ROW.load(Ordering::SeqCst);

        if row >= VGA_HEIGHT - 1 {
            // Scroll up
            self.scroll_up();
        } else {
            ROW.store(row + 1, Ordering::SeqCst);
        }

        COLUMN.store(0, Ordering::SeqCst);
    }

    fn scroll_up(&mut self) {
        let buffer = VGA_BUFFER as *mut ScreenChar;

        // Move all lines up by one
        unsafe {
            for row in 1..VGA_HEIGHT {
                for col in 0..VGA_WIDTH {
                    let src = buffer.add(row * VGA_WIDTH + col);
                    let dst = buffer.add((row - 1) * VGA_WIDTH + col);
                    dst.write_volatile(src.read_volatile());
                }
            }
        }

        // Clear the last line
        let last_row = VGA_HEIGHT - 1;
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };

        unsafe {
            for col in 0..VGA_WIDTH {
                buffer
                    .add(last_row * VGA_WIDTH + col)
                    .write_volatile(blank);
            }
        }

        ROW.store(last_row, Ordering::SeqCst);
    }

    pub fn clear_screen(&mut self) {
        let buffer = VGA_BUFFER as *mut ScreenChar;
        let blank = ScreenChar {
            ascii_character: b' ',
            color_code: self.color_code,
        };

        unsafe {
            for i in 0..(VGA_WIDTH * VGA_HEIGHT) {
                buffer.add(i).write_volatile(blank);
            }
        }

        COLUMN.store(0, Ordering::SeqCst);
        ROW.store(0, Ordering::SeqCst);
    }

    pub fn backspace(&mut self) {
        let col = COLUMN.load(Ordering::SeqCst);
        if col > 0 {
            COLUMN.store(col - 1, Ordering::SeqCst);

            let row = ROW.load(Ordering::SeqCst);
            let col = COLUMN.load(Ordering::SeqCst);
            let offset = row * VGA_WIDTH + col;
            let buffer = VGA_BUFFER as *mut ScreenChar;

            unsafe {
                buffer.add(offset).write_volatile(ScreenChar {
                    ascii_character: b' ',
                    color_code: self.color_code,
                });
            }
        }
    }
}

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

pub fn init() {
    let mut writer = Writer::new();
    writer.clear_screen();
}

pub fn write_byte(byte: u8) {
    let mut writer = Writer::new();
    writer.write_byte(byte);
}

pub fn write_string(s: &str) {
    let mut writer = Writer::new();
    writer.write_string(s);
}
