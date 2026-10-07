// unphook_dr3.c — 3 debug-register watches in client_unpacked2.exe:
//   Dr0 write-watch  0xFB115AC  (relocated error-code global - observed writer)
//   Dr1 write-watch  0xFAE7C98  (second error-code global - mini-fail routine)
//   Dr2 exec-watch   0xFAF12E7  (the mini-fail routine entry - find its caller)
// First hit of each logs full context + stack; lets us order the events.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

#define WA0 0xFB115AC
#define WA1 0xFAE7C98
#define XA2 0xFB23671   // the write instruction `mov [eax],edx` - fires pre-write
#define XA3 0xFB16F34   // caller return point - its block is still live then
#define DR7_VAL (0x1 | 0x4 | 0x10 | 0x40 | (1<<16) | (3<<18) | (1<<20) | (3<<22))

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook_dr3.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}
static int mem_ok(const void* p, DWORD n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return 1;
}

static void dump_hit(PEXCEPTION_POINTERS p, const char* what) {
    CONTEXT* c = p->ContextRecord;
    lg("!!!! %s\n", what);
    lg("  eip=%08x eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x\n",
       c->Eip, c->Eax, c->Ebx, c->Ecx, c->Edx, c->Esi, c->Edi, c->Ebp, c->Esp);
    if (mem_ok((void*)WA0, 4)) lg("  [fb115ac]=%08x", *(DWORD*)WA0);
    if (mem_ok((void*)WA1, 4)) lg("  [fae7c98]=%08x", *(DWORD*)WA1);
    lg("\n");
    // code before/around eip
    if (mem_ok((void*)(c->Eip - 24), 48)) {
        lg("  code@%08x:", c->Eip - 24);
        for (int i = 0; i < 48; i++) lg(" %02x", ((BYTE*)(c->Eip - 24))[i]);
        lg("\n");
    }
    // stack scan: image pointers (return addresses tell the call chain)
    DWORD sp = c->Esp & ~3;
    int found = 0;
    for (DWORD q = sp; q < sp + 0x300 && found < 24; q += 4) {
        if (!mem_ok((void*)q, 4)) break;
        DWORD v = *(DWORD*)q;
        if (v >= 0x401000 && v < 0xFF17000) { lg("  stk[%08x] = %08x\n", q, v); found++; }
    }
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS p) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    DWORD d6 = p->ContextRecord->Dr6;
    if (d6 & 1) dump_hit(p, "WRITE to FB115AC (reporter global)");
    if (d6 & 2) dump_hit(p, "WRITE to FAE7C98 (mini-fail global)");
    if (d6 & 8) dump_hit(p, "EXEC caller-return 0xFB16F34 - dumping caller block");
    if (d6 & 4) {
        dump_hit(p, "EXEC writer instr 0xFB23671 - dumping caller block");
        // the caller block (around return 0xfb16f34) is decrypted RIGHT NOW -
        // grab it before it self-wipes
        FILE* f = fopen("unphook_dr3_caller.bin", "wb");
        if (f) {
            DWORD base = 0xfb16000;
            for (DWORD a = base; a < base + 0x2000; a += 4) {
                DWORD v = mem_ok((void*)a, 4) ? *(DWORD*)a : 0;
                fwrite(&v, 1, 4, f);
            }
            fclose(f);
            lg("  caller block dumped to unphook_dr3_caller.bin\n");
        }
    }
    if (d6 & 8) {
        FILE* f = fopen("unphook_dr3_caller_ret.bin", "wb");
        if (f) {
            DWORD base = 0xfb16000;
            for (DWORD a = base; a < base + 0x2000; a += 4) {
                DWORD v = mem_ok((void*)a, 4) ? *(DWORD*)a : 0;
                fwrite(&v, 1, 4, f);
            }
            fclose(f);
            lg("  caller block (at ret) dumped to unphook_dr3_caller_ret.bin\n");
        }
    }
    // clear the Dr hit bits by rewriting Dr7 is automatic per-hit; just continue
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD g_self;
static void arm_all(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == g_self) continue;
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, te.th32ThreadID);
        if (!ht) continue;
        SuspendThread(ht);
        CONTEXT c; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(ht, &c)) {
            if (c.Dr0 != WA0 || (c.Dr7 & 0x15) != 0x15) {
                c.Dr0 = WA0; c.Dr1 = WA1; c.Dr2 = XA2; c.Dr3 = XA3;
                c.Dr7 |= DR7_VAL;
                SetThreadContext(ht, &c);
            }
        }
        ResumeThread(ht);
        CloseHandle(ht);
    }
}

static DWORD WINAPI helper(LPVOID) {
    g_self = GetCurrentThreadId();
    lg("unphook_dr3: helper running\n");
    for (int i = 0; i < 200; i++) { arm_all(); Sleep(100); }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("unphook_dr3: === attach ===\n");
        AddVectoredExceptionHandler(1, veh);
        CreateThread(0, 0, helper, 0, 0, 0);
    }
    return TRUE;
}
