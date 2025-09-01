// Copyright 2025 bubblepipe
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![no_std]
#![cfg_attr(feature = "nightly", feature(naked_functions))]

// Only build module contents on x86_64 targets. This crate is a workspace
// member and will be compiled on other hosts (e.g., aarch64) during workspace
// checks, so guard the x86-specific code behind target cfgs.

#[cfg(target_arch = "x86_64")]
pub mod error;
#[cfg(target_arch = "x86_64")]
pub mod interrupt;
#[cfg(target_arch = "x86_64")]
pub mod io;
// pub mod register;
#[cfg(target_arch = "x86_64")]
pub mod serial;
#[cfg(target_arch = "x86_64")]
pub mod trap;

#[cfg(target_arch = "x86_64")]
pub use error::Error;
#[cfg(target_arch = "x86_64")]
pub use interrupt::{disable as interrupt_disable, enable as interrupt_enable};
#[cfg(target_arch = "x86_64")]
pub use trap::{Exception, Interrupt, Trap};
