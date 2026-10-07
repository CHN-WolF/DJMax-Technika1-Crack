.386
.model flat, c

EXTERN g_fn:DWORD
EXTERN apply_patches:PROC

PUBLIC lf1, lf2, lf3, lf4, lf5, lf6, lf7, lf8, lf9, lf10, lf11, lf12, lf13, lf14, lf15, lf16
PUBLIC lf17, lf18, lf19, lf20, lf21, lf22, lf23, lf24, lf25, lf26, lf27, lf28, lf29, lf30, lf31, lf32

.code

EXTERN g_log_ord:PROC

THUNK MACRO N
lf&N PROC
    call apply_patches
    push N
    call g_log_ord
    pop eax
    mov eax, [g_fn + 4*N]
    test eax, eax
    jz fail&N
    jmp eax
fail&N:
    xor eax, eax
    ret
lf&N ENDP
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
