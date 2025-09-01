use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use spin::Mutex;

use crate::fs;
use crate::wasm::func::host::Caller;
use crate::wasm::linker::Linker;

// Very small skeleton FD table for WASM host calls.
// For now we keep only read-only snapshots backed by VFS path + cursor.
#[derive(Debug)]
struct HostFile {
    path: String,
    cursor: usize,
}

static NEXT_FD: AtomicI32 = AtomicI32::new(3); // 0,1,2 reserved
static FD_TABLE: Mutex<Vec<(i32, HostFile)>> = Mutex::new(Vec::new());

fn alloc_fd() -> i32 {
    NEXT_FD.fetch_add(1, Ordering::Relaxed)
}

fn fd_lookup_mut(fd: i32) -> Option<spin::MutexGuard<'static, Vec<(i32, HostFile)>>> {
    if fd < 0 { return None; }
    let guard = FD_TABLE.lock();
    // leave actual search to users; we return guard so callers can search/mutate
    Some(guard)
}

pub fn define_host_fs<T>(linker: &mut Linker<T>) -> crate::Result<()> {
    // print(ptr, len)
    linker.func_wrap("host", "print", |_caller: Caller<'_, T>, (ptr,len)| {
        tracing::info!(target: "wasm", "host.print(ptr={:#x}, len={})", ptr, len);
        0i32
    })?;

    // get_time() -> i64 (nanos since boot; stubbed)
    linker.func_wrap("host", "get_time", |_caller: Caller<'_, T>, ()| {
        0i64
    })?;

    // get_memory_info(ptr) -> i32 (stub)
    linker.func_wrap("host", "get_memory_info", |_caller: Caller<'_, T>, (_ptr: i32)| {
        0i32
    })?;

    // fs_list(path_ptr, buf_ptr, buf_len) -> i32 (bytes written) [skeleton]
    linker.func_wrap(
        "host",
        "fs_list",
        |_caller: Caller<'_, T>, (_path_ptr: i32, _buf_ptr: i32, _buf_len: i32)| {
            // TODO: Access guest memory and write directory listing.
            // For now, return 0 to indicate empty or error.
            0i32
        },
    )?;

    // fs_open(path_ptr, flags) -> i32 fd [skeleton]
    linker.func_wrap("host", "fs_open", |_caller: Caller<'_, T>, (_path_ptr: i32, _flags: i32)| {
        // TODO: read path from guest memory; for now, always fail ENOENT
        -2i32
    })?;

    // fs_close(fd) -> i32
    linker.func_wrap("host", "fs_close", |_caller: Caller<'_, T>, (fd: i32)| {
        if let Some(mut table) = fd_lookup_mut(fd) {
            if let Some(pos) = table.iter().position(|(f, _)| *f == fd) {
                table.remove(pos);
                return 0i32;
            }
        }
        -1i32
    })?;

    // fs_read(fd, buf_ptr, len) -> i32 bytes [skeleton]
    linker.func_wrap(
        "host",
        "fs_read",
        |_caller: Caller<'_, T>, (_fd: i32, _buf_ptr: i32, _len: i32)| {
            // TODO: copy data from VFS file content into guest memory
            -1i32
        },
    )?;

    // fs_write(fd, buf_ptr, len) -> i32 bytes [skeleton]
    linker.func_wrap(
        "host",
        "fs_write",
        |_caller: Caller<'_, T>, (_fd: i32, _buf_ptr: i32, _len: i32)| {
            // TODO: write guest buffer into VFS file
            -1i32
        },
    )?;

    // fs_stat(path_ptr, out_ptr) -> i32 [skeleton]
    linker.func_wrap(
        "host",
        "fs_stat",
        |_caller: Caller<'_, T>, (_path_ptr: i32, _out_ptr: i32)| {
            // TODO: fill out struct at out_ptr using VFS.stat
            -1i32
        },
    )?;

    Ok(())
}

