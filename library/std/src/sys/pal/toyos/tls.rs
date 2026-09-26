/// DTV-based TLS access for shared libraries.
///
/// Called by shared library code when accessing `#[thread_local]` variables of
/// a module whose TLS block is found through the dynamic thread vector (DTV).
///
/// DTV layout:
///   [0x00] generation: u64
///   [0x08] len: u64
///   [0x10] entries[0]: u64 (module_id=1)
///   [0x18] entries[1]: u64 (module_id=2)
///   ...
///
/// Entry value is the base address of that module's TLS block,
/// or DTV_UNALLOCATED (!0) if not yet allocated.
///
/// x86-64 (TLS variant II, GD/LD model): the linker preserves
/// `call __tls_get_addr` in .so files and emits R_X86_64_DTPMOD64/DTPOFF64 GOT
/// slot pairs. At load time, the kernel fills:
///   GOT[0] = module_id (DTV index, 1-based)
///   GOT[1] = offset within module's TLS segment
///
/// TCB layout (at fs_base / TP):
///   fs:[0x00] = self_ptr
///   fs:[0x08] = dtv_ptr
///
/// __tls_get_addr receives a pointer to TlsIndex {module_id, offset} in %rdi,
/// returns the address of the TLS variable in %rax.
///
/// AArch64 (TLS variant I, TLSDESC): the linker emits R_AARCH64_TLSDESC for a
/// descriptor pair in the GOT, and the loader fills:
///   desc[0] = __toyos_tlsdesc_dynamic
///   desc[1] = module_id << 32 | offset within module's TLS segment
///
/// TCB layout (at TPIDR_EL0 / TP):
///   [TP+0x00] = dtv_ptr
///   [TP+0x08] = reserved
/// followed by the executable's TLS block at TP + align_up(16, p_align).
///
/// __toyos_tlsdesc_dynamic receives the descriptor's address in x0 and returns
/// the variable's offset from TP in x0, preserving every other register.

/// Slow path: the DTV entry is unallocated or out of range.
/// Calls SYS_TLS_ALLOC_BLOCK to allocate the TLS block on demand.
#[inline(never)]
unsafe extern "C" fn __tls_get_addr_slow(module_id: u64, offset: u64) -> *mut u8 {
    // The caller's ABI is an address and there is nobody to return an error
    // to: a refusal added to `offset` is a pointer near the top of the address
    // space that the caller would then dereference.
    match toyos_abi::syscall::tls_alloc_block(module_id) {
        Ok(block) => core::ptr::without_provenance_mut((block + offset) as usize),
        Err(_) => rtabort!("no TLS block for a dlopen'd module"),
    }
}

/// Fast path: naked asm reads DTV directly from fs:[8], checks bounds and allocation,
/// falls through to slow path only when needed.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn __tls_get_addr(ti: *const [u64; 2]) -> *mut u8 {
    core::arch::naked_asm!(
        // ti is in %rdi: [module_id, offset]
        "mov rsi, [rdi + 8]",   // rsi = offset
        "mov rdi, [rdi]",       // rdi = module_id

        // module_id == 0 guard (shouldn't happen, but be safe)
        "test rdi, rdi",
        "jz 2f",

        // Load DTV pointer from TCB: fs:[8]
        "mov rax, fs:[8]",

        // Bounds check: module_id <= dtv[1] (len)
        "cmp rdi, [rax + 8]",
        "ja 2f",

        // Load DTV entry: dtv[2 + (module_id - 1)]
        "lea rcx, [rdi - 1]",
        "mov rax, [rax + rcx * 8 + 16]",

        // Check for DTV_UNALLOCATED (!0)
        "cmp rax, -1",
        "je 2f",

        // Fast path: return entry + offset
        "add rax, rsi",
        "ret",

        // Slow path
        "2:",
        "jmp {slow}",
        slow = sym __tls_get_addr_slow,
    );
}

/// Fast path: naked asm reads DTV directly from [TP], checks bounds and allocation,
/// and calls the slow path only when needed, saving every register the
/// descriptor call does not clobber.
#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn __toyos_tlsdesc_dynamic(desc: *const [u64; 2]) -> isize {
    core::arch::naked_asm!(
        "stp x1, x2, [sp, #-32]!",
        "stp x3, x4, [sp, #16]",
        "ldr x0, [x0, #8]",
        "lsr x1, x0, #32",          // x1 = module_id
        "and x0, x0, #0xffffffff",  // x0 = offset
        "mrs x2, tpidr_el0",
        "ldr x3, [x2]",             // x3 = DTV

        // module_id == 0 guard (shouldn't happen, but be safe)
        "cbz x1, 2f",

        // Bounds check: module_id <= dtv[1] (len)
        "ldr x4, [x3, #8]",
        "cmp x1, x4",
        "b.hi 2f",

        // Load DTV entry: dtv[2 + (module_id - 1)]
        "add x4, x3, x1, lsl #3",
        "ldr x4, [x4, #8]",

        // Check for DTV_UNALLOCATED (!0)
        "cmn x4, #1",
        "b.eq 2f",

        // Fast path: return entry + offset - TP
        "add x0, x4, x0",
        "sub x0, x0, x2",
        "ldp x3, x4, [sp, #16]",
        "ldp x1, x2, [sp], #32",
        "ret",

        // Slow path: everything a call may clobber is saved around it.
        "2:",
        "sub sp, sp, #640",
        "stp x5, x6, [sp, #0]",
        "stp x7, x8, [sp, #16]",
        "stp x9, x10, [sp, #32]",
        "stp x11, x12, [sp, #48]",
        "stp x13, x14, [sp, #64]",
        "stp x15, x16, [sp, #80]",
        "stp x17, x18, [sp, #96]",
        "stp x29, x30, [sp, #112]",
        "add x29, sp, #112",
        "stp q0, q1, [sp, #128]",
        "stp q2, q3, [sp, #160]",
        "stp q4, q5, [sp, #192]",
        "stp q6, q7, [sp, #224]",
        "stp q8, q9, [sp, #256]",
        "stp q10, q11, [sp, #288]",
        "stp q12, q13, [sp, #320]",
        "stp q14, q15, [sp, #352]",
        "stp q16, q17, [sp, #384]",
        "stp q18, q19, [sp, #416]",
        "stp q20, q21, [sp, #448]",
        "stp q22, q23, [sp, #480]",
        "stp q24, q25, [sp, #512]",
        "stp q26, q27, [sp, #544]",
        "stp q28, q29, [sp, #576]",
        "stp q30, q31, [sp, #608]",
        "mov x2, x0",
        "mov x0, x1",
        "mov x1, x2",
        "bl {slow}",
        "mrs x1, tpidr_el0",
        "sub x0, x0, x1",
        "ldp q0, q1, [sp, #128]",
        "ldp q2, q3, [sp, #160]",
        "ldp q4, q5, [sp, #192]",
        "ldp q6, q7, [sp, #224]",
        "ldp q8, q9, [sp, #256]",
        "ldp q10, q11, [sp, #288]",
        "ldp q12, q13, [sp, #320]",
        "ldp q14, q15, [sp, #352]",
        "ldp q16, q17, [sp, #384]",
        "ldp q18, q19, [sp, #416]",
        "ldp q20, q21, [sp, #448]",
        "ldp q22, q23, [sp, #480]",
        "ldp q24, q25, [sp, #512]",
        "ldp q26, q27, [sp, #544]",
        "ldp q28, q29, [sp, #576]",
        "ldp q30, q31, [sp, #608]",
        "ldp x5, x6, [sp, #0]",
        "ldp x7, x8, [sp, #16]",
        "ldp x9, x10, [sp, #32]",
        "ldp x11, x12, [sp, #48]",
        "ldp x13, x14, [sp, #64]",
        "ldp x15, x16, [sp, #80]",
        "ldp x17, x18, [sp, #96]",
        "ldp x29, x30, [sp, #112]",
        "add sp, sp, #640",
        "ldp x3, x4, [sp, #16]",
        "ldp x1, x2, [sp], #32",
        "ret",
        slow = sym __tls_get_addr_slow,
    );
}
