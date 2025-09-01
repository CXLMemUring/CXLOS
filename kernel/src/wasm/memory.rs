// Copyright 2025 Jonas Kruckenberg
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::wasm::store::{StoreOpaque, Stored};
use crate::wasm::types::MemoryType;
use crate::wasm::vm::{ExportedMemory, VMMemoryImport, VmPtr};
use core::sync::atomic::Ordering;

#[derive(Clone, Copy, Debug)]
pub struct Memory(Stored<ExportedMemory>);

impl Memory {
    pub fn ty(self, store: &StoreOpaque) -> MemoryType {
        let export = &store[self.0];
        MemoryType::from_wasm_memory(&export.memory)
    }

    pub(super) fn from_exported_memory(store: &mut StoreOpaque, export: ExportedMemory) -> Self {
        let stored = store.add_memory(export);
        Self(stored)
    }
    pub(super) fn as_vmmemory_import(self, store: &mut StoreOpaque) -> VMMemoryImport {
        let export = &store[self.0];
        VMMemoryImport {
            from: VmPtr::from(export.definition),
            vmctx: VmPtr::from(export.vmctx),
            index: export.index,
        }
    }

    /// Unsafe: returns the base pointer and current length of the linear memory.
    /// The caller must ensure pointer arithmetic and bounds are valid.
    pub unsafe fn raw_parts(&self, store: &StoreOpaque) -> (*mut u8, usize) {
        let export = &store[self.0];
        let def = export.definition.as_ptr();
        // Safety: caller upholds memory validity for the lifetime of use
        unsafe {
            ((*def).base.as_ptr(), (*def).current_length(Ordering::Relaxed))
        }
    }

    /// Unsafe: write `data` to memory at `offset` if it fits, returning true on success.
    pub unsafe fn write(&self, store: &StoreOpaque, offset: usize, data: &[u8]) -> bool {
        let (base, len) = unsafe { self.raw_parts(store) };
        if offset > len || data.len() > len - offset {
            return false;
        }
        // Safety: bounds checked above
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), base.add(offset), data.len()) };
        true
    }
}
