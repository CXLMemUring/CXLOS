use alloc::string::String;

use alloc::string::ToString;
use spin::{Mutex, OnceLock};
use wasmparser::Validator;

use crate::wasm::{Engine, Module, Store, Val};
use crate::wasm::linker::Linker;

struct BusyboxWasm {
    store: Store<()>,
    instance: crate::wasm::Instance,
}

static BUSYBOX_WASM: OnceLock<Mutex<BusyboxWasm>> = OnceLock::new();

/// Try to instantiate the BusyBox WASM module and return whether it succeeded.
///
/// This is gated behind the `wasm_busybox` feature because embedding the WASM
/// bytes requires prebuilding `wasm_busybox.wasm` from the provided WAT.
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
    let mut const_eval = crate::wasm::ConstExprEvaluator::new(&engine);
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
        results_buf.resize(ty.results().len(), Val::i32(0));
        func.call(&mut *bb.store, &[Val::i32(1), Val::i32(0)], &mut results_buf)?;
        return Ok(true);
    }
    Ok(false)
}
