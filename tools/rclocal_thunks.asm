.386
.model flat, c

EXTERN g_ord:DWORD, g_a1:DWORD, g_a2:DWORD, g_a3:DWORD, g_a4:DWORD, g_ret:DWORD, g_orig_ret:DWORD
EXTERN g_fn:DWORD
EXTERN log_pre_c:PROC, log_post_c:PROC

PUBLIC post_handler
PUBLIC f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12, f13, f14, f15, f16
PUBLIC f17, f18, f19, f20, f21, f22, f23, f24, f25, f26, f27, f28, f29, f30, f31, f32

.code

post_handler PROC
    pushad
    mov [g_ret], eax
    call log_post_c
    popad
    push [g_orig_ret]
    ret
post_handler ENDP

THUNK MACRO N
f&N PROC
    push ebp
    mov ebp, esp
    mov [g_ord], N
    mov eax, [ebp+8]
    mov [g_a1], eax
    mov eax, [ebp+0Ch]
    mov [g_a2], eax
    mov eax, [ebp+10h]
    mov [g_a3], eax
    mov eax, [ebp+14h]
    mov [g_a4], eax
    call log_pre_c
    mov eax, [ebp+4]
    mov [g_orig_ret], eax
    lea eax, post_handler
    mov [ebp+4], eax
    mov esp, ebp
    pop ebp
    mov eax, [g_fn + 4*N]
    jmp eax
f&N ENDP
ENDM

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

END
