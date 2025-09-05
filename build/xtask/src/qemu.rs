// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::path::Path;
use std::process::{Command, Stdio};

use clap::Parser;

use crate::profile::{Architecture, Profile};
use crate::util::KillOnDrop;

#[derive(Debug, Parser)]
pub struct QemuOptions {
    /// Listen for GDB connections and wait for a debugger to attach.
    #[clap(long, short)]
    pub wait_for_debugger: bool,
    /// The TCP port to listen for debug connections on.
    #[clap(long, default_value = "1234")]
    pub gdb_port: u16,
    /// Extra arguments passed to QEMU.
    #[clap(raw = true)]
    pub qemu_args: Vec<String>,
}

pub fn spawn(
    qemu: &QemuOptions,
    profile: Profile,
    image: &Path,
    inherit_stdio: bool,
    additional_args: &[String],
) -> crate::Result<KillOnDrop> {
    let mut cmd = match profile.arch {
        Architecture::Riscv64 => {
            let mut cmd = Command::new("qemu-system-riscv64");
            cmd.args([
                "-machine",
                "virt",
                "-cpu",
                "rv64",
                "-m",
                "256M",
                "-d",
                "guest_errors",
                "-display",
                "none",
                "-serial",
                "mon:stdio",
                "-semihosting-config",
                "enable=on,target=native",
                "-smp",
                "cpus=8",
                "-object",
                "memory-backend-ram,size=128M,id=m0",
                "-object",
                "memory-backend-ram,size=128M,id=m1",
                "-numa",
                "node,cpus=0-3,nodeid=0,memdev=m0",
                "-numa",
                "node,cpus=4-7,nodeid=1,memdev=m1",
                "-numa",
                "dist,src=0,dst=1,val=20",
                "-monitor",
                "unix:qemu-monitor-socket,server,nowait",
                "-kernel",
                image.to_str().unwrap(), // target/riscv64gc-unknown-none-elf/debug/loader
            ]);
            cmd
        }
        Architecture::X86_64 => {
            let mut cmd = Command::new("/storage/qemu/build/qemu-system-x86_64");
            // println!("{}", image.to_str().unwrap());
            cmd.args([
                "--enable-kvm",
                "-cpu",
                "host",
                "-serial",
                "mon:stdio",
                "-no-shutdown",
                "-no-reboot",
                "-M", "q35,cxl=on", "-m", "4G", "-smp", "4",
                "-device", "pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1",
                "-device", "cxl-rp,port=0,bus=cxl.1,id=root_port13,chassis=0,slot=0",
                "-device", "cxl-rp,port=1,bus=cxl.1,id=root_port14,chassis=0,slot=1",
                "-device", "cxl-type3,bus=root_port13,persistent-memdev=cxl-mem1,lsa=cxl-lsa1,id=cxl-pmem0,sn=0x1",
                "-device", "cxl-type1,bus=root_port14,size=256M,cache-size=64M",
                "-device", "virtio-cxl-accel-pci,bus=pcie.0",
              "-object","memory-backend-file,id=cxl-mem1,share=on,mem-path=/tmp/cxltest1.raw,size=256M",
              "-object","memory-backend-file,id=cxl-lsa1,share=on,mem-path=/tmp/lsa1.raw,size=256M",
              "-M", "cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G",
              "-nographic",
                "-kernel",
                image.to_str().unwrap(), // target/x86_64-unknown-none/debug/loader
            ]);
            cmd
        }
    };

    cmd.args(&qemu.qemu_args);
    cmd.args(additional_args);

    if qemu.wait_for_debugger {
        cmd.arg("-S")
            .arg("-gdb")
            .arg(format!("tcp::{}", qemu.gdb_port));
    }

    if inherit_stdio {
        cmd.stderr(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stdin(Stdio::inherit());
    } else {
        cmd.stderr(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stdin(Stdio::null());
    }

    Ok(KillOnDrop(
        cmd.spawn().expect("Failed to spawn qemu. Is it installed?"),
    ))
}
