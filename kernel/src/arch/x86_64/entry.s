.global _start
.extern _rust_start

.section .text
_start:
    # Raw serial 'R' on COM1
    mov $0x3F8, %dx
    mov $0x52, %al
    out %al, %dx
    # The loader passes:
    # rdi = cpuid
    # rsi = boot_info  
    # rdx = boot_ticks
    
    # Ensure stack is 16-byte aligned before call
    # The call instruction will push 8 bytes, so we need stack to be 8-byte misaligned here
    andq $-16, %rsp
    subq $8, %rsp
    
    # Just pass them through to Rust
    call _rust_start
    # Should never return
    ud2
