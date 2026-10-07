// GNU as port of rclocal_thunks.asm (32 naked ordinal forwarders with
// return-address hijack for post-call logging) + abort-catcher entries.
    .intel_syntax noprefix
    .text

    .extern _g_ord
    .extern _g_a1
    .extern _g_a2
    .extern _g_a3
    .extern _g_a4
    .extern _g_ret
    .extern _g_orig_ret
    .extern _g_fn
    .extern _log_pre_c
    .extern _log_post_c

// ---- post-call handler: thunk replaces caller's ret addr with this ----
    .globl _post_handler
_post_handler:
    pusha
    mov [_g_ret], eax
    call _log_post_c
    popa
    push [_g_orig_ret]
    ret

// ---- 32 ordinal forwarders (convention transparent) ----
.macro THUNK N
    .globl _f\N
_f\N:
    push ebp
    mov ebp, esp
    mov dword ptr [_g_ord], \N
    mov eax, [ebp+8]
    mov [_g_a1], eax
    mov eax, [ebp+12]
    mov [_g_a2], eax
    mov eax, [ebp+16]
    mov [_g_a3], eax
    mov eax, [ebp+20]
    mov [_g_a4], eax
    call _log_pre_c
    mov eax, [ebp+4]
    mov [_g_orig_ret], eax
    lea eax, [_post_handler]
    mov [ebp+4], eax
    mov esp, ebp
    pop ebp
    mov eax, dword ptr [_g_fn + 4*\N]
    jmp eax
.endm

THUNK 1
THUNK 2
THUNK 3
THUNK 4
THUNK 5
THUNK 6
THUNK 7
THUNK 8
THUNK 9
THUNK 10
THUNK 11
THUNK 12
THUNK 13
THUNK 14
THUNK 15
THUNK 16
THUNK 17
THUNK 18
THUNK 19
THUNK 20
THUNK 21
THUNK 22
THUNK 23
THUNK 24
THUNK 25
THUNK 26
THUNK 27
THUNK 28
THUNK 29
THUNK 30
THUNK 31
THUNK 32

// ---- abort-catcher hook entries ----
    .extern _g_hit_id
    .extern _g_hit_ret
    .extern _g_hit_arg1
    .extern _g_hit_arg2
    .extern _g_hit_arg3
    .extern _g_hit_arg4
    .extern _g_hit_esp
    .extern _g_hit_ebp
    .extern _g_resume
    .extern _stack_report
    .extern _unhook_and_target

.macro HOOKENTRY NAME, ID
    .globl \NAME
\NAME:
    mov dword ptr [_g_hit_id], \ID
    jmp _hook_common
.endm

HOOKENTRY _hook_h_abort,    0
HOOKENTRY _hook_h_purecall, 1
HOOKENTRY _hook_h_assert,   2
HOOKENTRY _hook_h_wassert,  3
HOOKENTRY _hook_h_exitproc, 4
HOOKENTRY _hook_h_termproc, 5
HOOKENTRY _hook_h_msgboxa,  6
HOOKENTRY _hook_h_msgboxw,  7

// entered via 5-byte JMP patch on the hooked function's first bytes:
// stack is exactly as the original caller left it ([esp] = ret addr).
_hook_common:
    mov eax, [esp]
    mov [_g_hit_ret], eax
    mov eax, [esp+4]
    mov [_g_hit_arg1], eax
    mov eax, [esp+8]
    mov [_g_hit_arg2], eax
    mov eax, [esp+12]
    mov [_g_hit_arg3], eax
    mov eax, [esp+16]
    mov [_g_hit_arg4], eax
    mov [_g_hit_esp], esp
    mov [_g_hit_ebp], ebp
    pusha
    call _stack_report
    call _unhook_and_target
    mov [_g_resume], eax
    popa
    jmp dword ptr [_g_resume]

// ---- GetAdaptersInfo compatibility hook entry ----
// entered via 5-byte JMP patch on iphlpapi!GetAdaptersInfo; stdcall args
// pass straight through to the C implementation.
    .extern _my_GetAdaptersInfo@8
    .globl _hook_h_gai
_hook_h_gai:
    jmp _my_GetAdaptersInfo@8

// ---- Direct3DCreate9 / cursor hook entries ----
    .extern _my_Direct3DCreate9@4
    .globl _hook_h_d3dcreate9
_hook_h_d3dcreate9:
    jmp _my_Direct3DCreate9@4

    .extern _my_Direct3DCreate9Ex@8
    .globl _hook_h_d3dcreate9ex
_hook_h_d3dcreate9ex:
    jmp _my_Direct3DCreate9Ex@8

    .extern _my_ShowCursor@4
    .globl _hook_h_showcursor
_hook_h_showcursor:
    jmp _my_ShowCursor@4

    .extern _my_SetCursor@4
    .globl _hook_h_setcursor
_hook_h_setcursor:
    jmp _my_SetCursor@4

    .extern _my_DirectSoundCreate8@12
    .globl _hook_h_ds8create
_hook_h_ds8create:
    jmp _my_DirectSoundCreate8@12
