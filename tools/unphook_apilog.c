// unphook_apilog.c — injected into client_unpacked2.exe: figure out WHY the shell
// runtime check fails. Hooks kernel32 file/module APIs (CreateFileA/W,
// ReadFile, GetFileSize, GetModuleFileNameA/W, GetModuleHandleA/W) and logs
// every call (+ result), to answer: does the shell read its OWN file
// (self CRC check) or is it pure runtime-state?
// Also keeps the error-global write watchpoint to correlate timing.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

#define WATCH_ADDR 0xFB115AC
#define DR7_WATCH  (1 | (1 << 16) | (3 << 18))

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook_apilog.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
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

// ---- generic 5-byte jmp hook with trampoline ----
typedef struct { const char* fn; void* repl; BYTE tramp[16]; void* orig5; int ok; } HK;
static int hook_one(HMODULE m, HK* h) {
    BYTE* p = (BYTE*)GetProcAddress(m, h->fn);
    if (!p) { lg("hk: %s missing\n", h->fn); return 0; }
    // follow FF 25 (jmp [import]) forwarding thunks to the real body
    if (mem_ok(p, 6) && p[0] == 0xFF && p[1] == 0x25) {
        DWORD slot;
        memcpy(&slot, p + 2, 4);
        if (mem_ok((void*)slot, 4)) {
            DWORD real;
            memcpy(&real, (void*)slot, 4);
            if (mem_ok((void*)real, 5)) { lg("hk: %s thunk %p -> %08x\n", h->fn, p, real); p = (BYTE*)real; }
        }
    }
    // follow E9 (jmp rel32) forwarders to the real body
    if (mem_ok(p, 5) && p[0] == 0xE9) {
        DWORD rel;
        memcpy(&rel, p + 1, 4);
        BYTE* real = p + 5 + rel;
        if (mem_ok(real, 5)) { lg("hk: %s fwd %p -> %08x\n", h->fn, p, (DWORD)real); p = real; }
    }
    // only relocate safe 5-byte prologues: 8B FF 55 8B EC (hotpatch) / 55 8B EC
    // variants starting with B8 (mov eax,imm). Anything with relative control
    // flow in the first 5 bytes (E8/E9/EB/70-7F/0F 8x) would break the tramp.
    if (!mem_ok(p, 5)) return 0;
    BYTE b0 = p[0];
    int safe = 0;
    if (b0 == 0x8B && p[1] == 0xFF) safe = 1;                 // mov edi,edi
    else if (b0 == 0x55 && p[1] == 0x8B && p[2] == 0xEC) safe = 1;  // push ebp; mov ebp,esp
    else if (b0 == 0xB8) safe = 1;                            // mov eax, imm32
    else if (b0 == 0x6A) safe = 1;                            // push imm8 (some stubs)
    if (!safe) {
        lg("hk: %s @%08x unsafe prologue %02x %02x %02x %02x %02x - SKIP\n",
           h->fn, (DWORD)p, p[0], p[1], p[2], p[3], p[4]);
        return 0;
    }
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
    h->orig5 = p;
    h->ok = 1;
    lg("hk: %s hooked @%08x\n", h->fn, (DWORD)p);
    return 1;
}

typedef HANDLE (WINAPI *CFA)(LPCSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CFW)(LPCWSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *RF)(HANDLE, void*, DWORD, DWORD*, void*);
typedef DWORD (WINAPI *GFS)(HANDLE, DWORD*);
typedef DWORD (WINAPI *GMFA)(void*, LPSTR, DWORD);
typedef HMODULE (WINAPI *GMHA)(LPCSTR);
typedef HMODULE (WINAPI *GMHW)(LPCWSTR);

static HK h_cfa, h_cfw, h_rf, h_gfs, h_gmfa, h_gmha, h_gmhw;

static HANDLE WINAPI my_CreateFileA(LPCSTR fn, DWORD a, DWORD s, void* sa, DWORD d, DWORD fl, HANDLE t) {
    char b[200]; cstrA((DWORD)fn, b, sizeof(b));
    HANDLE r = ((CFA)h_cfa.tramp)(fn, a, s, sa, d, fl, t);
    lg("CFA(\"%s\") -> %p\n", b, r);
    return r;
}
static HANDLE WINAPI my_CreateFileW(LPCWSTR fn, DWORD a, DWORD s, void* sa, DWORD d, DWORD fl, HANDLE t) {
    char b[200]; int i = 0;
    if (fn && mem_ok((void*)fn, 2))
        for (; i < 199; i++) { WCHAR c = fn[i]; if (!c) break; b[i] = c < 128 ? (char)c : '?'; }
    b[i] = 0;
    HANDLE r = ((CFW)h_cfw.tramp)(fn, a, s, sa, d, fl, t);
    lg("CFW(\"%s\") -> %p\n", b, r);
    return r;
}
static BOOL WINAPI my_ReadFile(HANDLE h, void* b, DWORD n, DWORD* rd, void* ov) {
    // resolve unknown handles to filenames once (the shell opens its own exe via
    // direct NtCreateFile, invisible to our kernel32 hooks)
    static struct { HANDLE h; char name[200]; int done; } seen[32];
    static int nseen;
    int i;
    for (i = 0; i < nseen; i++) if (seen[i].h == h) break;
    if (i == nseen && nseen < 32) {
        seen[i].h = h; seen[i].done = 1; seen[i].name[0] = 0; nseen++;
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        typedef LONG (WINAPI *NQO)(HANDLE, UINT, PVOID, ULONG, PULONG);
        static NQO fn;
        if (!fn && nt) fn = (NQO)GetProcAddress(nt, "NtQueryObject");
        if (fn) {
            BYTE buf[1024];
            ULONG rl = 0;
            typedef struct { WORD len, maxlen; WCHAR* buf; } USTR;
            if (fn(h, 1, buf, sizeof(buf), &rl) >= 0) {  // ObjectNameInformation = 1
                USTR* us = (USTR*)buf;
                if (us->buf && us->len) {
                    WCHAR* w = us->buf;
                    int m = us->len / 2; if (m > 190) m = 190;
                    int j;
                    for (j = 0; j < m; j++) seen[i].name[j] = w[j] < 128 ? (char)w[j] : '?';
                    seen[i].name[j] = 0;
                }
            }
        }
        if (seen[i].name[0]) lg("RF: handle %p == \"%s\"\n", h, seen[i].name);
    }
    BOOL r = ((RF)h_rf.tramp)(h, b, n, rd, ov);
    lg("RF(h=%p n=%lu) -> %d\n", h, n, r);
    return r;
}
static DWORD WINAPI my_GetFileSize(HANDLE h, DWORD* hi) {
    DWORD r = ((GFS)h_gfs.tramp)(h, hi);
    lg("GFS(h=%p) -> %lu\n", h, r);
    return r;
}
static DWORD WINAPI my_GetModuleFileNameA(void* m, LPSTR b, DWORD n) {
    DWORD r = ((GMFA)h_gmfa.tramp)(m, b, n);
    char bb[200]; cstrA((DWORD)b, bb, sizeof(bb));
    lg("GMFA(mod=%p) -> \"%s\"\n", m, bb);
    return r;
}
static HMODULE WINAPI my_GetModuleHandleA(LPCSTR m) {
    char b[120]; cstrA((DWORD)m, b, sizeof(b));
    HMODULE r = ((GMHA)h_gmha.tramp)(m);
    lg("GMHA(\"%s\") -> %p\n", b, r);
    return r;
}
static HMODULE WINAPI my_GetModuleHandleW(LPCWSTR m) {
    HMODULE r = ((GMHW)h_gmhw.tramp)(m);
    lg("GMHW(...) -> %p\n", r);
    return r;
}

// ---- error-global watchpoint (same as unphook) ----
static LONG CALLBACK veh(PEXCEPTION_POINTERS p) {
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;
    if (!(p->ContextRecord->Dr6 & 1)) return EXCEPTION_CONTINUE_SEARCH;
    DWORD val = 0;
    if (mem_ok((void*)WATCH_ADDR, 4)) val = *(DWORD*)WATCH_ADDR;
    lg("!!!! ERROR CODE WRITE: [0x%08x] = %08x at eip=%08x\n", WATCH_ADDR, val, p->ContextRecord->Eip);
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

static void suspend_others(void);
static void resume_others(void);

#define MAXSUSP 128
static HANDLE g_susp[MAXSUSP];
static int g_nsusp;
static void suspend_others(void) {
    g_nsusp = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId(), self = GetCurrentThreadId();
    for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
        HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
        if (ht && g_nsusp < MAXSUSP) { SuspendThread(ht); g_susp[g_nsusp++] = ht; }
        else if (ht) CloseHandle(ht);
    }
    CloseHandle(snap);
}
static void resume_others(void) {
    for (int i = 0; i < g_nsusp; i++) { ResumeThread(g_susp[i]); CloseHandle(g_susp[i]); }
    g_nsusp = 0;
}

static void install(void) {
    HMODULE k = GetModuleHandleA("kernel32.dll");
    if (!k) { lg("no kernel32 yet\n"); return; }
    suspend_others();
    h_cfa.fn = "CreateFileA";   h_cfa.repl = my_CreateFileA;   hook_one(k, &h_cfa);
    h_cfw.fn = "CreateFileW";   h_cfw.repl = my_CreateFileW;   hook_one(k, &h_cfw);
    h_rf.fn  = "ReadFile";      h_rf.repl  = my_ReadFile;      hook_one(k, &h_rf);
    h_gfs.fn = "GetFileSize";   h_gfs.repl = my_GetFileSize;   hook_one(k, &h_gfs);
    h_gmfa.fn= "GetModuleFileNameA"; h_gmfa.repl = my_GetModuleFileNameA; hook_one(k, &h_gmfa);
    h_gmha.fn= "GetModuleHandleA";   h_gmha.repl = my_GetModuleHandleA;   hook_one(k, &h_gmha);
    h_gmhw.fn= "GetModuleHandleW";   h_gmhw.repl = my_GetModuleHandleW;   hook_one(k, &h_gmhw);
    resume_others();
}

static DWORD WINAPI helper(LPVOID) {
    g_self = GetCurrentThreadId();
    lg("unphook_apilog: helper running\n");
    AddVectoredExceptionHandler(1, veh);
    for (int i = 0; i < 200; i++) { arm_all(); Sleep(100); }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("unphook_apilog: === attach ===\n");
        install();
        CreateThread(0, 0, helper, 0, 0, 0);
    }
    return TRUE;
}
