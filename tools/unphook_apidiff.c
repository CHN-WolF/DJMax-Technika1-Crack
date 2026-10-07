// unphook_apidiff.c — differential API-resolution tracer for the shell runtime init.
// Hooks kernel32!LoadLibraryA/W, GetProcAddress, GetModuleHandleA/W and
// ntdll!LdrLoadDll; logs (tick, args, retval) for every call. Plus the
// error-global write watchpoint (0xFB115AC). Run on healthy and rebuilt,
// diff the logs -> the divergence IS the failing resource.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

#define WATCH_ADDR 0xFB115AC
#define DR7_WATCH  (1 | (1 << 16) | (3 << 18))

static FILE* g_lf;
static DWORD g_t0;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook_apidiff.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
    if (!g_lf) return;
    if (!g_t0) g_t0 = GetTickCount();
    fprintf(g_lf, "[%6lu] ", (unsigned long)(GetTickCount() - g_t0));
    va_list ap; va_start(ap, fmt); vfprintf(g_lf, fmt, ap); va_end(ap);
}
static int mem_ok(const void* p, DWORD n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void*)p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return 1;
}
static void cstrA(DWORD p, char* out, int n) {
    out[0] = 0;
    if (!p || !mem_ok((void*)p, 1)) return;
    for (int i = 0; i < n - 1; i++) {
        if (!mem_ok((void*)(p + i), 1)) break;
        out[i] = ((char*)p)[i];
        if (!out[i]) return;
    }
    out[n - 1] = 0;
}
static void cstrW(DWORD p, char* out, int n) {
    out[0] = 0;
    if (!p || !mem_ok((void*)p, 2)) return;
    WCHAR* w = (WCHAR*)p;
    for (int i = 0; i < n - 1; i++) {
        if (!mem_ok((void*)(p + i * 2), 2)) break;
        WCHAR c = w[i];
        if (!c) break;
        out[i] = c < 128 ? (char)c : '?';
    }
    out[n - 1] = 0;
}

typedef struct { const char* fn; void* repl; BYTE tramp[16]; int ok; } HK;
static int hook_one(HMODULE m, HK* h) {
    BYTE* p = (BYTE*)GetProcAddress(m, h->fn);
    if (!p) { lg("hk: %s missing\n", h->fn); return 0; }
    if (mem_ok(p, 6) && p[0] == 0xFF && p[1] == 0x25) {
        DWORD slot;
        memcpy(&slot, p + 2, 4);
        if (mem_ok((void*)slot, 4)) {
            DWORD real;
            memcpy(&real, (void*)slot, 4);
            if (mem_ok((void*)real, 5)) { lg("hk: %s thunk %p -> %08x\n", h->fn, p, real); p = (BYTE*)real; }
        }
    }
    if (mem_ok(p, 5) && p[0] == 0xE9) {
        DWORD rel;
        memcpy(&rel, p + 1, 4);
        BYTE* real = p + 5 + rel;
        if (mem_ok(real, 5)) { lg("hk: %s fwd %p -> %08x\n", h->fn, p, (DWORD)real); p = real; }
    }
    if (!mem_ok(p, 5)) return 0;
    int safe = 0;
    if (p[0] == 0x8B && p[1] == 0xFF) safe = 1;
    else if (p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC) safe = 1;
    else if (p[0] == 0xB8) safe = 1;
    else if (p[0] == 0x6A) safe = 1;
    if (!safe) { lg("hk: %s @%08x unsafe prologue - SKIP\n", h->fn, (DWORD)p); return 0; }
    DWORD old;
    memcpy(h->tramp, p, 5);
    h->tramp[5] = 0xE9;
    DWORD rel = (DWORD)(p + 5) - (DWORD)(h->tramp + 10);
    memcpy(h->tramp + 6, &rel, 4);
    if (!VirtualProtect(h->tramp, 16, PAGE_EXECUTE_READWRITE, &old)) return 0;
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) return 0;
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)h->repl - (DWORD)(p + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(p, jb, 5);
    VirtualProtect(p, 5, old, &old);
    h->ok = 1;
    lg("hk: %s hooked @%08x\n", h->fn, (DWORD)p);
    return 1;
}

typedef HMODULE (WINAPI *LLA)(LPCSTR);
typedef HMODULE (WINAPI *LLW)(LPCWSTR);
typedef FARPROC (WINAPI *GPA)(HMODULE, LPCSTR);
typedef HMODULE (WINAPI *GMHA)(LPCSTR);
typedef HMODULE (WINAPI *GMHW)(LPCWSTR);
typedef LONG (WINAPI *LLD)(void*, DWORD*, void*, void*);  // LdrLoadDll

static HK h_lla, h_llw, h_gpa, h_gmha, h_gmhw, h_lld;

static HMODULE WINAPI my_LLA(LPCSTR n) {
    HMODULE r = ((LLA)h_lla.tramp)(n);
    char b[160]; cstrA((DWORD)n, b, sizeof(b));
    lg("LLA(\"%s\") -> %p\n", b, r);
    return r;
}
static HMODULE WINAPI my_LLW(LPCWSTR n) {
    HMODULE r = ((LLW)h_llw.tramp)(n);
    char b[160]; cstrW((DWORD)n, b, sizeof(b));
    lg("LLW(L\"%s\") -> %p\n", b, r);
    return r;
}
static FARPROC WINAPI my_GPA(HMODULE m, LPCSTR n) {
    FARPROC r = ((GPA)h_gpa.tramp)(m, n);
    char b[160];
    if ((DWORD)n < 0x10000) sprintf(b, "#%lu", (unsigned long)(DWORD)n);
    else cstrA((DWORD)n, b, sizeof(b));
    lg("GPA(%p,\"%s\") -> %p%s\n", m, b, r, r ? "" : "  <-- NULL!");
    return r;
}
static HMODULE WINAPI my_GMHA(LPCSTR n) {
    HMODULE r = ((GMHA)h_gmha.tramp)(n);
    char b[160]; cstrA((DWORD)n, b, sizeof(b));
    lg("GMHA(\"%s\") -> %p\n", b, r);
    return r;
}
static HMODULE WINAPI my_GMHW(LPCWSTR n) {
    HMODULE r = ((GMHW)h_gmhw.tramp)(n);
    char b[160]; cstrW((DWORD)n, b, sizeof(b));
    lg("GMHW(L\"%s\") -> %p\n", b, r);
    return r;
}
static LONG WINAPI my_LLD(void* path, DWORD* flags, void* name, void* outmod) {
    LONG r = ((LLD)h_lld.tramp)(path, flags, name, outmod);
    // name is UNICODE_STRING ptr
    char b[160]; b[0] = 0;
    if (mem_ok(name, 4)) {
        DWORD buf = *(DWORD*)((BYTE*)name + 4);
        cstrW(buf, b, sizeof(b));
    }
    lg("LdrLoadDll(\"%s\") -> %08x\n", b, r);
    return r;
}

static LONG CALLBACK veh(PEXCEPTION_POINTERS p) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if (!(p->ContextRecord->Dr6 & 1)) return EXCEPTION_CONTINUE_SEARCH;
    DWORD val = 0;
    if (mem_ok((void*)WATCH_ADDR, 4)) val = *(DWORD*)WATCH_ADDR;
    lg("!!!! ERROR CODE WRITE = %08x at eip=%08x\n", val, p->ContextRecord->Eip);
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
            if (c.Dr0 != WATCH_ADDR || !(c.Dr7 & 1)) {
                c.Dr0 = WATCH_ADDR; c.Dr7 |= DR7_WATCH;
                SetThreadContext(ht, &c);
            }
        }
        ResumeThread(ht);
        CloseHandle(ht);
    }
}

static DWORD WINAPI helper(LPVOID) {
    g_self = GetCurrentThreadId();
    lg("unphook_apidiff: helper running\n");
    AddVectoredExceptionHandler(1, veh);
    for (int i = 0; i < 200; i++) { arm_all(); Sleep(100); }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("unphook_apidiff: === attach ===\n");
        HMODULE k = GetModuleHandleA("kernel32.dll");
        HMODULE n = GetModuleHandleA("ntdll.dll");
        h_lla.fn = "LoadLibraryA";  h_lla.repl = my_LLA;  hook_one(k, &h_lla);
        h_llw.fn = "LoadLibraryW";  h_llw.repl = my_LLW;  hook_one(k, &h_llw);
        h_gpa.fn = "GetProcAddress"; h_gpa.repl = my_GPA; hook_one(k, &h_gpa);
        h_gmha.fn = "GetModuleHandleA"; h_gmha.repl = my_GMHA; hook_one(k, &h_gmha);
        h_gmhw.fn = "GetModuleHandleW"; h_gmhw.repl = my_GMHW; hook_one(k, &h_gmhw);
        h_lld.fn = "LdrLoadDll"; h_lld.repl = my_LLD; hook_one(n, &h_lld);
        CreateThread(0, 0, helper, 0, 0, 0);
    }
    return TRUE;
}
