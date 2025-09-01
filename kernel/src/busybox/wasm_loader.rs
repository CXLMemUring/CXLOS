use alloc::string::String;

use alloc::string::ToString;
use spin::{Mutex, OnceLock};
use wasmparser::Validator;

use crate::wasm::{Engine, Module, Store, Val};
use crate::wasm::linker::Linker;
use crate::wasm::Memory;

struct BusyboxWasm {
    store: Store<()>,
    instance: crate::wasm::Instance,
}

static BUSYBOX_WASM: OnceLock<Mutex<BusyboxWasm>> = OnceLock::new();

/// Try to instantiate the BusyBox WASM module and return whether it succeeded.
/// Always enabled by default; expects a prebuilt `wasm_busybox.wasm` to be present.
pub fn try_init_wasm_busybox() -> crate::Result<bool> {
    // Embed the compiled WASM if present.
    // To produce this file, run: `wat2wasm kernel/src/busybox/wasm_busybox.wat -o kernel/src/busybox/wasm_busybox.wasm`
    // and build with `--features wasm_busybox`.
    const WASM_BYTES: &[u8] = include_bytes!("wasm_busybox.wasm");

    let engine = Engine::default();
    let mut store: Store<()> = Store::new(&engine, crate::wasm::default_instance_allocator(), ());
    let mut validator = Validator::new();

    let module = Module::from_bytes(&engine, &mut validator, WASM_BYTES)?;
    let mut linker = Linker::<()>::new(&engine);

    // Define host FS functions under module name "host"
    crate::wasm::host_fs::define_host_fs(&mut linker)?;

    // Instantiate
    let mut const_eval = crate::wasm::ConstExprEvaluator::default();
    let instance = linker.instantiate(&mut store, &mut const_eval, &module)?;

    let _ = BUSYBOX_WASM.set(Mutex::new(BusyboxWasm { store, instance }));
    Ok(true)
}

pub fn is_initialized() -> bool {
    BUSYBOX_WASM.get().is_some()
}

/// Call an exported command with no argv (argc=1, argv=0). Suitable for
/// commands like pwd/uname/date/whoami/free and ls (defaults to "/").
pub fn call_export_noargs(name: &str) -> crate::Result<bool> {
    let Some(lock) = BUSYBOX_WASM.get() else { return Ok(false) };
    let mut bb = lock.lock();
    if let Some(func) = bb.instance.get_func(&mut *bb.store, name) {
        let ty = func.ty(&*bb.store);
    let mut results_buf: alloc::vec::Vec<Val> = alloc::vec::Vec::with_capacity(ty.results().len());
    results_buf.resize(ty.results().len(), Val::I32(0));
    func.call(&mut *bb.store, &[Val::I32(1), Val::I32(0)], &mut results_buf)?;
        return Ok(true);
    }
    Ok(false)
}

/// Call an exported command with string arguments (argv[0] = name; argv[1..] = args)
pub fn call_export_args(name: &str, args: &[&str]) -> crate::Result<bool> {
    let Some(lock) = BUSYBOX_WASM.get() else { return Ok(false) };
    let mut bb = lock.lock();

    // Find exported function
    let Some(func) = bb.instance.get_func(&mut *bb.store, name) else { return Ok(false) };

    // Get default memory export
    let Some(mem) = bb.instance.get_memory(&mut *bb.store, "memory") else { return Ok(false) };

    // Allocate a simple scratch region near offset 0x2000
    // Layout: strings then argv array of i32 pointers
    let mut offset: usize = 0x3000;
    let mut ptrs: alloc::vec::Vec<i32> = alloc::vec::Vec::new();

    // argv[0] = command name
    let mut all_args: alloc::vec::Vec<&str> = alloc::vec::Vec::with_capacity(args.len() + 1);
    all_args.push(name);
    all_args.extend_from_slice(args);

    // Write strings with NUL terminator
    for s in &all_args {
        let bytes = s.as_bytes();
        let ok = unsafe { mem.write(&*bb.store, offset, bytes) };
        if !ok { return Ok(false); }
        let ok = unsafe { mem.write(&*bb.store, offset + bytes.len(), &[0]) };
        if !ok { return Ok(false); }
        ptrs.push(offset as i32);
        offset += bytes.len() + 1;
    }

    // Align argv array to 4 bytes
    offset = (offset + 3) & !3;
    let argv_ptr = offset as i32;
    // Write pointer array
    for p in &ptrs {
        let le = p.to_le_bytes();
        let ok = unsafe { mem.write(&*bb.store, offset, &le) };
        if !ok { return Ok(false); }
        offset += 4;
    }

    let argc = all_args.len() as i32;
    let ty = func.ty(&*bb.store);
    let mut results_buf: alloc::vec::Vec<Val> = alloc::vec::Vec::with_capacity(ty.results().len());
    results_buf.resize(ty.results().len(), Val::I32(0));
    func.call(&mut *bb.store, &[Val::I32(argc), Val::I32(argv_ptr)], &mut results_buf)?;
    Ok(true)
}

fn cmd_index(name: &str) -> Option<i32> {
    match name {
        "echo" => Some(0),
        "ls" => Some(1),
        "cat" => Some(2),
        "pwd" => Some(3),
        "uname" => Some(4),
        "free" => Some(5),
        "date" => Some(6),
        "whoami" => Some(7),
        _ => None,
    }
}

/// Preferred route: call busybox_main(argc, argv, cmd_index). Falls back to per-export if absent.
pub fn call_busybox(name: &str, args: &[&str]) -> crate::Result<bool> {
    let Some(lock) = BUSYBOX_WASM.get() else { return Ok(false) };
    let mut bb = lock.lock();

    if let Some(main) = bb.instance.get_func(&mut *bb.store, "busybox_main") {
        // build argv as in call_export_args
        let Some(mem) = bb.instance.get_memory(&mut *bb.store, "memory") else { return Ok(false) };
        let mut offset: usize = 0x3000;
        let mut ptrs: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
        let mut all_args: alloc::vec::Vec<&str> = alloc::vec::Vec::with_capacity(args.len() + 1);
        all_args.push(name);
        all_args.extend_from_slice(args);
        for s in &all_args {
            let bytes = s.as_bytes();
            let ok = unsafe { mem.write(&*bb.store, offset, bytes) };
            if !ok { return Ok(false); }
            let ok = unsafe { mem.write(&*bb.store, offset + bytes.len(), &[0]) };
            if !ok { return Ok(false); }
            ptrs.push(offset as i32);
            offset += bytes.len() + 1;
        }
        offset = (offset + 3) & !3; // align
        let argv_ptr = offset as i32;
        for p in &ptrs { let le = p.to_le_bytes(); if unsafe { !mem.write(&*bb.store, offset, &le) } { return Ok(false); } offset += 4; }
        let argc = all_args.len() as i32;
        let cmd = cmd_index(name).unwrap_or(-1);
        if cmd >= 0 {
            let ty = main.ty(&*bb.store);
            let mut results_buf: alloc::vec::Vec<Val> = alloc::vec::Vec::with_capacity(ty.results().len());
            results_buf.resize(ty.results().len(), Val::I32(0));
            main.call(&mut *bb.store, &[Val::I32(argc), Val::I32(argv_ptr), Val::I32(cmd)], &mut results_buf)?;
            return Ok(true);
        }
    }
    // fallback
    if args.is_empty() { call_export_noargs(name) } else { call_export_args(name, args) }
}
