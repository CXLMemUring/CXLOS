use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::min;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, Ordering};

use spin::Mutex;

use crate::fs;
use crate::wasm::func::host::Caller;
use crate::wasm::indices::MemoryIndex;
use crate::wasm::linker::Linker;
use crate::wasm::vm::VMMemoryDefinition;

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
    if fd < 0 {
        return None;
    }
    let guard = FD_TABLE.lock();
    // leave actual search to users; we return guard so callers can search/mutate
    Some(guard)
}

pub fn define_host_fs<T>(linker: &mut Linker<T>) -> crate::Result<()> {
    // print(ptr, len)
    linker.func_wrap(
        "host",
        "print",
        |mut caller: Caller<'_, T>, ptr: i32, len: i32| -> i32 {
            if let Some(mem) = first_memory(&mut caller) {
                let base = unsafe { (*mem.as_ptr()).base.as_ptr() } as *const u8;
                let size = unsafe { (*mem.as_ptr()).current_length(Ordering::Relaxed) };
                let off = ptr as usize;
                let len = len as usize;
                if off <= size && len <= size - off {
                    let slice = unsafe { core::slice::from_raw_parts(base.add(off), len) };
                    if let Ok(s) = core::str::from_utf8(slice) {
                        tracing::info!(target: "wasm", "{}", s);
                        return 0i32;
                    } else {
                        tracing::info!(target: "wasm", "<{} bytes binary>", slice.len());
                        return 0i32;
                    }
                }
            }
            -1i32
        },
    )?;

    // get_time() -> i64 (nanos since boot; stubbed)
    linker.func_wrap("host", "get_time", |_caller: Caller<'_, T>| 0i64)?;

    // get_memory_info(ptr) -> i32 (stub)
    linker.func_wrap(
        "host",
        "get_memory_info",
        |_caller: Caller<'_, T>, _ptr: i32| 0i32,
    )?;

    // fs_list(path_ptr, buf_ptr, buf_len) -> i32 (bytes written)
    linker.func_wrap(
        "host",
        "fs_list",
        |mut caller: Caller<'_, T>, path_ptr: i32, buf_ptr: i32, buf_len: i32| {
            let Some(mem) = first_memory(&mut caller) else {
                return -1;
            };
            let (base, size) = unsafe {
                let m = &*mem.as_ptr();
                (
                    m.base.as_ptr() as *mut u8,
                    m.current_length(Ordering::Relaxed),
                )
            };
            let path = read_cstr(base, size, path_ptr as usize);
            let path = match path {
                Some(p) => p,
                None => return -1,
            };
            let listing = fs::with_vfs(|vfs| vfs.list_dir(&path))
                .ok_or(())
                .and_then(|r| r.map_err(|_| ()));
            let mut out = String::new();
            match listing {
                Ok(entries) => {
                    for (i, e) in entries.iter().enumerate() {
                        if i > 0 {
                            out.push('\n');
                        }
                        out.push_str(e);
                    }
                    out.push('\n');
                }
                Err(_) => return -1,
            }
            let out_bytes = out.as_bytes();
            let off = buf_ptr as usize;
            let cap = buf_len as usize;
            if off > size {
                return -1;
            }
            let max = min(cap, size - off);
            let n = min(max, out_bytes.len());
            unsafe { core::ptr::copy_nonoverlapping(out_bytes.as_ptr(), base.add(off), n) };
            n as i32
        },
    )?;

    // fs_open(path_ptr, flags) -> i32 fd
    linker.func_wrap(
        "host",
        "fs_open",
        |mut caller: Caller<'_, T>, path_ptr:i32, _flags:i32| {
            let Some(mem) = first_memory(&mut caller) else {
                return -1;
            };
            let (base, size) = unsafe {
                let m = &*mem.as_ptr();
                (
                    m.base.as_ptr() as *mut u8,
                    m.current_length(Ordering::Relaxed),
                )
            };
            let Some(path) = read_cstr(base, size, path_ptr as usize) else {
                return -1;
            };
            if !fs::with_vfs(|vfs| vfs.exists(&path)).unwrap_or(false) {
                return -2;
            }
            let fd = alloc_fd();
            FD_TABLE.lock().push((fd, HostFile { path, cursor: 0 }));
            fd
        },
    )?;

    // fs_close(fd) -> i32
    linker.func_wrap(
        "host",
        "fs_close",
        |_caller: Caller<'_, T>, fd: i32| {
            if let Some(mut table) = fd_lookup_mut(fd) {
                if let Some(pos) = table.iter().position(|(f, _)| *f == fd) {
                    table.remove(pos);
                    return 0i32;
                }
            }
            -1i32
        },
    )?;

    // fs_read(fd, buf_ptr, len) -> i32 bytes
    linker.func_wrap(
        "host",
        "fs_read",
        |mut caller: Caller<'_, T>, fd:i32, buf_ptr:i32, len:i32| {
            let Some(mut table) = fd_lookup_mut(fd) else {
                return -1;
            };
            let idx = match table.iter().position(|(f, _)| *f == fd) {
                Some(i) => i,
                None => return -1,
            };
            let file = &mut table[idx].1;
            let content = match fs::with_vfs(|vfs| vfs.read_file(&file.path)) {
                Some(Ok(c)) => c,
                _ => return -1,
            };
            if file.cursor >= content.len() {
                return 0;
            }
            let Some(mem) = first_memory(&mut caller) else {
                return -1;
            };
            let (base, size) = unsafe {
                let m = &*mem.as_ptr();
                (
                    m.base.as_ptr() as *mut u8,
                    m.current_length(Ordering::Relaxed),
                )
            };
            let off = buf_ptr as usize;
            let cap = len as usize;
            if off > size {
                return -1;
            }
            let max = min(cap, size - off);
            let remain = content.len() - file.cursor;
            let n = min(max, remain);
            unsafe {
                core::ptr::copy_nonoverlapping(content[file.cursor..].as_ptr(), base.add(off), n)
            };
            file.cursor += n;
            n as i32
        },
    )?;

    // fs_write(fd, buf_ptr, len) -> i32 bytes
    linker.func_wrap(
        "host",
        "fs_write",
        |mut caller: Caller<'_, T>, fd:i32, buf_ptr:i32, len:  i32| {
            let Some(mut table) = fd_lookup_mut(fd) else {
                return -1;
            };
            let idx = match table.iter().position(|(f, _)| *f == fd) {
                Some(i) => i,
                None => return -1,
            };
            let file = &mut table[idx].1;
            let Some(mem) = first_memory(&mut caller) else {
                return -1;
            };
            let (base, size) = unsafe {
                let m = &*mem.as_ptr();
                (
                    m.base.as_ptr() as *mut u8,
                    m.current_length(Ordering::Relaxed),
                )
            };
            let off = buf_ptr as usize;
            let n = len as usize;
            if off > size || n > size - off {
                return -1;
            }
            let src = unsafe { core::slice::from_raw_parts(base.add(off), n) };
            let mut content = match fs::with_vfs(|vfs| vfs.read_file(&file.path)) {
                Some(Ok(c)) => c,
                _ => Vec::new(),
            };
            let end_pos = file.cursor.saturating_add(n);
            if end_pos > content.len() {
                content.resize(end_pos, 0);
            }
            content[file.cursor..file.cursor + n].copy_from_slice(src);
            let write_res = fs::with_vfs_mut(|vfs| vfs.write_file(&file.path, &content))
                .ok_or(())
                .and_then(|r| r.map_err(|_| ()));
            if write_res.is_err() {
                return -1;
            }
            file.cursor += n;
            n as i32
        },
    )?;

    // fs_stat(path_ptr, out_ptr) -> i32
    linker.func_wrap(
        "host",
        "fs_stat",
        |mut caller: Caller<'_, T>, path_ptr:i32, out_ptr:i32| {
            let Some(mem) = first_memory(&mut caller) else {
                return -1;
            };
            let (base, size) = unsafe {
                let m = &*mem.as_ptr();
                (
                    m.base.as_ptr() as *mut u8,
                    m.current_length(Ordering::Relaxed),
                )
            };
            let Some(path) = read_cstr(base, size, path_ptr as usize) else {
                return -1;
            };
            let stat = match fs::with_vfs(|vfs| vfs.stat(&path)) {
                Some(Ok(s)) => s,
                _ => return -1,
            };
            let file_type = match stat.file_type {
                fs::FileType::Regular => 1u32,
                fs::FileType::Directory => 2u32,
                fs::FileType::Device => 3u32,
                fs::FileType::Link => 4u32,
            };
            let mode = stat.mode as u32;
            let size_u32 = (stat.size as u64).min(u32::MAX as u64) as u32;
            let mut buf = [0u8; 16];
            buf[0..4].copy_from_slice(&size_u32.to_le_bytes());
            buf[4..8].copy_from_slice(&file_type.to_le_bytes());
            buf[8..12].copy_from_slice(&mode.to_le_bytes());
            buf[12..16].copy_from_slice(&(0u32).to_le_bytes());
            let dest_off = out_ptr as usize;
            if dest_off > size || 16 > size - dest_off {
                return -1;
            }
            unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), base.add(dest_off), 16) };
            0i32
        },
    )?;

    Ok(())
}

fn first_memory<'a, T>(caller: &mut Caller<'a, T>) -> Option<NonNull<VMMemoryDefinition>> {
    let mem = caller
        .instance_mut()
        .get_exported_memory(MemoryIndex::from_u32(0));
    Some(mem.definition)
}

fn read_cstr(base: *mut u8, size: usize, offset: usize) -> Option<String> {
    if offset >= size {
        return None;
    }
    let mut i = offset;
    let mut bytes = Vec::new();
    while i < size {
        let b = unsafe { *base.add(i) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        i += 1;
        if bytes.len() > 4096 {
            break;
        }
    }
    String::from_utf8(bytes).ok()
}
