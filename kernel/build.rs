// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::env;

use vergen::{BuildBuilder, CargoBuilder, Emitter, RustcBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For x86_64, compile the assembly entry point
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("x86_64") {
        println!("cargo:rerun-if-changed=src/arch/x86_64/entry.s");
        cc::Build::new()
            .file("src/arch/x86_64/entry.s")
            .compile("entry");
        // Ensure the linker uses the assembly `_start` symbol as the entry point.
        // Pass `-e _start` directly to the gnu-lld linker.
        println!("cargo:rustc-link-arg=-e");
        println!("cargo:rustc-link-arg=_start");
    }

    let build = BuildBuilder::default().build_timestamp(true).build()?;
    let cargo = CargoBuilder::default()
        .target_triple(true)
        .opt_level(true)
        .build()?;
    let rustc = RustcBuilder::default().semver(true).channel(true).build()?;

    Emitter::new()
        .add_instructions(&build)?
        .add_instructions(&cargo)?
        // Git metadata intentionally omitted to avoid libgit2 dependency in constrained builds
        .add_instructions(&rustc)?
        .emit()?;

    Ok(())
}
