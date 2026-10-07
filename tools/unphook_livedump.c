// unphook_livedump.c — exec-bp on the error-code writer instruction; at the hit, copy
// the live caller/writer neighborhood into an in-DLL static buffer and print
// its address; an external tool then reads it raw (no file IO in VEH context).
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

#define XA2 0xFB23671   // writer instruction `mov [eax],edx` (fires pre-exec)
#define CAP_LO 0xFA8C000
#define CAP_HI 0xFB25000
// L2 exec (RW=00 LEN=00)
#define DR7_VAL (0x10)

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook_livedump.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
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

static BYTE g_cap[CAP_HI - CAP_LO];   // captured live bytes land here
static volatile DWORD g_done;

static LONG CALLBACK veh(PEXCEPTION_POINTERS p) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if (!(p->ContextRecord->Dr6 & 4)) return EXCEPTION_CONTINUE_SEARCH;
    if (g_done) return EXCEPTION_CONTINUE_EXECUTION;
    g_done = 1;
    CONTEXT* c = p->ContextRecord;
    lg("unphook_livedump: EXEC writer hit, eip=%08x eax=%08x ecx=%08x edx=%08x ebx=%08x esi=%08x edi=%08x ebp=%08x esp=%08x\n",
       c->Eip, c->Eax, c->Ecx, c->Edx, c->Ebx, c->Esi, c->Edi, c->Ebp, c->Esp);
    // copy the neighborhood NOW (caller block is mid-call -> not yet wiped)
    DWORD n = 0;
    for (DWORD a = CAP_LO; a < CAP_HI; a += 4) {
        DWORD v = mem_ok((void*)a, 4) ? *(DWORD*)a : 0xDEADBEEF;
        *(DWORD*)(g_cap + (a - CAP_LO)) = v;
        n++;
    }
    lg("unphook_livedump: captured %08x..%08x into DLL buf %08x (%lu dwords)\n",
       CAP_LO, CAP_HI, (DWORD)g_cap, n);
    // also: stack raw copy for offline chain analysis
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
            if (c.Dr2 != XA2 || !(c.Dr7 & 0x10)) {
                c.Dr2 = XA2; c.Dr7 |= DR7_VAL;
                SetThreadContext(ht, &c);
            }
        }
        ResumeThread(ht);
        CloseHandle(ht);
    }
}

static DWORD WINAPI helper(LPVOID) {
    g_self = GetCurrentThreadId();
    lg("unphook_livedump: helper running, exec watch at %08x\n", XA2);
    for (int i = 0; i < 200; i++) { arm_all(); Sleep(100); }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("unphook_livedump: === attach ===\n");
        AddVectoredExceptionHandler(1, veh);
        CreateThread(0, 0, helper, 0, 0, 0);
    }
    return TRUE;
}
