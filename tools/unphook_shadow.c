// unphook_shadow.c — injected into client_unpacked2.exe: defeat the shell's file
// self-check by content redirection. The shell opens its own exe via direct
// NtCreateFile but reads it with kernel32!ReadFile (observed: ~4200 x 1KB
// reads before error 10). We mark the exe handle (NtQueryObject name match),
// then serve every read from a shadow handle on the ORIGINAL client.exe,
// mirroring position. If the file check passes, the shell should run on.
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdarg.h>

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook_shadow.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
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
    h->ok = 1;
    lg("hk: %s hooked @%08x\n", h->fn, (DWORD)p);
    return 1;
}

typedef BOOL (WINAPI *RF)(HANDLE, void*, DWORD, DWORD*, void*);
typedef DWORD (WINAPI *SFP)(HANDLE, LONG, LONG*, DWORD);
typedef BOOL (WINAPI *SFPE)(HANDLE, LARGE_INTEGER, LARGE_INTEGER*, DWORD);
typedef DWORD (WINAPI *GFS)(HANDLE, DWORD*);
typedef BOOL (WINAPI *GFSE)(HANDLE, LARGE_INTEGER*);
typedef HANDLE (WINAPI *CFA)(LPCSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *CFW)(LPCWSTR, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);

static HK h_rf, h_sfp, h_sfpe, h_gfs, h_gfse, h_cfa, h_cfw;

// ---- exe-handle shadow redirect ----
static HANDLE g_exeh;      // the shell's handle on its own (rebuilt) exe
static HANDLE g_shadow;    // our handle on the ORIGINAL client.exe
static LONG g_shadow_pos;  // mirrored position
static char g_selfname[MAX_PATH];

static int is_exe_handle(HANDLE h) {
    if (h == g_exeh) return 1;
    return 0;
}
static void name_of_handle(HANDLE h, char* out, int n) {
    out[0] = 0;
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    typedef LONG (WINAPI *NQO)(HANDLE, UINT, PVOID, ULONG, PULONG);
    static NQO fn;
    if (!fn && nt) fn = (NQO)GetProcAddress(nt, "NtQueryObject");
    if (!fn) return;
    BYTE buf[1024]; ULONG rl = 0;
    typedef struct { WORD len, maxlen; WCHAR* buf; } USTR;
    if (fn(h, 1, buf, sizeof(buf), &rl) < 0) return;
    USTR* us = (USTR*)buf;
    if (!us->buf || !us->len) return;
    int m = us->len / 2; if (m > n - 1) m = n - 1;
    for (int i = 0; i < m; i++) out[i] = us->buf[i] < 128 ? (char)us->buf[i] : '?';
    out[m] = 0;
}
static void maybe_mark(HANDLE h) {
    if (g_exeh || !h || h == INVALID_HANDLE_VALUE) return;
    char nm[260];
    name_of_handle(h, nm, sizeof(nm));
    if (!nm[0]) return;
    // match if the opened file's tail == our running exe's filename tail
    const char* tail = strrchr(g_selfname, '\\');
    tail = tail ? tail + 1 : g_selfname;
    if (strstr(nm, tail)) {
        g_exeh = h;
        char fn2[MAX_PATH];
        GetModuleFileNameA(NULL, fn2, MAX_PATH);
        char dir[MAX_PATH]; strcpy(dir, fn2);
        char* p = strrchr(dir, '\\'); if (p) *p = 0;
        // original exe: game root client.exe. our exe is in crack_work\dump,
        // so go two levels up from our own dir.
        strcat(dir, "\\..\\..\\client.exe");
        g_shadow = CreateFileA(dir, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
        lg("exe handle marked %p (\"%s\"), shadow=%p on %s\n", h, nm, g_shadow, dir);
    }
}

static BOOL WINAPI my_ReadFile(HANDLE h, void* b, DWORD n, DWORD* rd, void* ov) {
    if (h != g_exeh) maybe_mark(h);
    if (h == g_exeh && g_shadow && g_shadow != INVALID_HANDLE_VALUE) {
        DWORD realread = 0;
        BOOL r = ((RF)h_rf.tramp)(h, b, n, rd, ov);   // keep the real handle's position honest
        if (r && rd) realread = *rd;
        // serve original bytes at the mirrored position
        DWORD got = 0;
        LARGE_INTEGER li; li.QuadPart = g_shadow_pos;
        SetFilePointer(g_shadow, li.LowPart, &li.HighPart, FILE_BEGIN);
        ReadFile(g_shadow, b, realread, &got, NULL);
        g_shadow_pos += realread;
        if (rd) *rd = got;
        lg("RF(exe n=%lu) -> orig %lu bytes @%lu\n", n, got, g_shadow_pos - realread);
        return r;
    }
    BOOL r = ((RF)h_rf.tramp)(h, b, n, rd, ov);
    return r;
}

static DWORD WINAPI my_SetFilePointer(HANDLE h, LONG d, LONG* hi, DWORD m) {
    DWORD r = ((SFP)h_sfp.tramp)(h, d, hi, m);
    if (h == g_exeh && g_shadow) {
        LONG nh = hi ? *hi : 0;
        DWORD np = SetFilePointer(g_shadow, d, &nh, m);
        g_shadow_pos = np;
        lg("SFP(exe d=%ld m=%lu) -> %lu (mirror %lu)\n", d, m, r, np);
    }
    return r;
}
static BOOL WINAPI my_SetFilePointerEx(HANDLE h, LARGE_INTEGER d, LARGE_INTEGER* out, DWORD m) {
    BOOL r = ((SFPE)h_sfpe.tramp)(h, d, out, m);
    if (h == g_exeh && g_shadow) {
        LARGE_INTEGER nd; nd.QuadPart = d.QuadPart;
        SetFilePointerEx(g_shadow, nd, NULL, m);
        g_shadow_pos = (LONG)(out ? out->QuadPart : 0);
        lg("SFPE(exe d=%lld m=%lu)\n", d.QuadPart, m);
    }
    return r;
}
static DWORD WINAPI my_GetFileSize(HANDLE h, DWORD* hi) {
    DWORD r = ((GFS)h_gfs.tramp)(h, hi);
    if (h == g_exeh) lg("GFS(exe) -> %lu\n", r);
    return r;
}
static BOOL WINAPI my_GetFileSizeEx(HANDLE h, LARGE_INTEGER* o) {
    BOOL r = ((GFSE)h_gfse.tramp)(h, o);
    if (h == g_exeh && o) lg("GFSEx(exe) -> %lld\n", o->QuadPart);
    return r;
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
static HANDLE WINAPI my_CreateFileA(LPCSTR fn, DWORD a, DWORD s, void* sa, DWORD d, DWORD fl, HANDLE t) {
    char b[200]; cstrA((DWORD)fn, b, sizeof(b));
    HANDLE r = ((CFA)h_cfa.tramp)(fn, a, s, sa, d, fl, t);
    lg("CFA(\"%s\") -> %p\n", b, r);
    maybe_mark(r);
    return r;
}
static HANDLE WINAPI my_CreateFileW(LPCWSTR fn, DWORD a, DWORD s, void* sa, DWORD d, DWORD fl, HANDLE t) {
    char b[200]; cstrW((DWORD)fn, b, sizeof(b));
    HANDLE r = ((CFW)h_cfw.tramp)(fn, a, s, sa, d, fl, t);
    lg("CFW(\"%s\") -> %p\n", b, r);
    maybe_mark(r);
    return r;
}

// ---- error-global watchpoint (correlation) ----
#define WATCH_ADDR 0xFB115AC
#define DR7_WATCH  (1 | (1 << 16) | (3 << 18))
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

static DWORD WINAPI helper(LPVOID) {
    g_self = GetCurrentThreadId();
    lg("unphook_shadow: helper running\n");
    AddVectoredExceptionHandler(1, veh);
    for (int i = 0; i < 200; i++) { arm_all(); Sleep(100); }
    return 0;
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

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        GetModuleFileNameA(NULL, g_selfname, MAX_PATH);
        lg("unphook_shadow: === attach === self=%s\n", g_selfname);
        HMODULE k = GetModuleHandleA("kernel32.dll");
        suspend_others();
        h_rf.fn = "ReadFile";          h_rf.repl = my_ReadFile;          hook_one(k, &h_rf);
        h_sfp.fn = "SetFilePointer";   h_sfp.repl = my_SetFilePointer;   hook_one(k, &h_sfp);
        h_sfpe.fn = "SetFilePointerEx"; h_sfpe.repl = my_SetFilePointerEx; hook_one(k, &h_sfpe);
        h_gfs.fn = "GetFileSize";      h_gfs.repl = my_GetFileSize;      hook_one(k, &h_gfs);
        h_gfse.fn = "GetFileSizeEx";   h_gfse.repl = my_GetFileSizeEx;   hook_one(k, &h_gfse);
        h_cfa.fn = "CreateFileA";      h_cfa.repl = my_CreateFileA;      hook_one(k, &h_cfa);
        h_cfw.fn = "CreateFileW";      h_cfw.repl = my_CreateFileW;      hook_one(k, &h_cfw);
        resume_others();
        CreateThread(0, 0, helper, 0, 0, 0);
    }
    return TRUE;
}
