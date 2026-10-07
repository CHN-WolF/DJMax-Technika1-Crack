// unphook_ntredir.c — NtCreateFile-level redirect of the shell's self-read to the
// ORIGINAL client.exe. The shell opens its own exe via direct NtCreateFile
// (invisible to kernel32 hooks). If the name matches our running exe, we create
// the original file instead -> every subsequent read (any API level) returns
// original bytes. Tests whether error 10 is a file-content expectation.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

static FILE* g_lf;
static void lg(const char* fmt, ...) {
    if (!g_lf) { g_lf = fopen("unphook_ntredir.log", "a"); if (g_lf) setvbuf(g_lf, 0, _IONBF, 0); }
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

// minimal native struct layouts (32-bit)
typedef struct { WORD Length, MaximumLength; WCHAR* Buffer; } USTR32;
typedef struct { DWORD Length; HANDLE RootDirectory; USTR32* ObjectName; DWORD Attributes; void* SD; void* SQS; } OA32;

typedef LONG (WINAPI *NCF)(HANDLE*, DWORD, OA32*, void*, void*, DWORD, DWORD, DWORD, DWORD, void*, DWORD);

static BYTE g_tramp_ncf[16];
static WCHAR g_origpath[MAX_PATH];   // L"\??\G:\...\client.exe"
static WCHAR g_selftail[64];         // L"client_unpacked2.exe"
static int g_redirected;

static LONG WINAPI my_NtCreateFile(HANDLE* fh, DWORD acc, OA32* oa, void* iosb, void* alloc,
                                   DWORD fattr, DWORD share, DWORD disp, DWORD copts, void* ea, DWORD ealen) {
    OA32 oa2;
    USTR32 name2;
    WCHAR* origbuf = NULL;
    if (oa && mem_ok(oa, sizeof(OA32)) && oa->ObjectName && mem_ok(oa->ObjectName, 8)) {
        USTR32* nm = oa->ObjectName;
        if (nm->Buffer && mem_ok(nm->Buffer, nm->Length)) {
            // ascii-ify tail for matching
            char a[260]; int m = nm->Length / 2; if (m > 250) m = 250;
            int j;
            for (j = 0; j < m; j++) { WCHAR c = nm->Buffer[j]; a[j] = c < 128 ? (char)c : '?'; }
            a[j] = 0;
            // does it end with our exe name?
            char selfA[64]; int sl = 0;
            for (int i = 0; g_selftail[i]; i++) selfA[sl++] = (char)g_selftail[i];
            selfA[sl] = 0;
            int hit = 0;
            if (sl > 4) {
                int al = strlen(a);
                if (al >= sl && !strnicmp(a + al - sl, selfA, sl)) hit = 1;
            }
            if (hit) {
                lg("NtCreateFile SELF-EXE \"%s\" -> redirecting to original\n", a);
                oa2 = *oa;
                name2 = *nm;
                name2.Buffer = g_origpath;
                name2.Length = wcslen(g_origpath) * 2;
                name2.MaximumLength = name2.Length + 2;
                oa2.ObjectName = &name2;
                LONG r = ((NCF)g_tramp_ncf)(fh, acc, &oa2, iosb, alloc, fattr, share, disp, copts, ea, ealen);
                lg("  redirected NtCreateFile -> %08x fh=%p\n", r, fh ? *fh : 0);
                g_redirected++;
                return r;
            } else {
                lg("NtCreateFile \"%s\"\n", a);
            }
        }
    }
    return ((NCF)g_tramp_ncf)(fh, acc, oa, iosb, alloc, fattr, share, disp, copts, ea, ealen);
}

static int hook_ncf(void) {
    HMODULE n = GetModuleHandleA("ntdll.dll");
    if (!n) return 0;
    BYTE* p = (BYTE*)GetProcAddress(n, "NtCreateFile");
    if (!p || !mem_ok(p, 5)) return 0;
    // syscall stub: B8 xx xx 00 00 (mov eax, sysnum) expected
    lg("unphook_ntredir: NtCreateFile @%08x bytes %02x %02x %02x %02x %02x\n",
       (DWORD)p, p[0], p[1], p[2], p[3], p[4]);
    DWORD old;
    memcpy(g_tramp_ncf, p, 5);
    g_tramp_ncf[5] = 0xE9;
    DWORD rel = (DWORD)(p + 5) - (DWORD)(g_tramp_ncf + 10);
    memcpy(g_tramp_ncf + 6, &rel, 4);
    if (!VirtualProtect(g_tramp_ncf, 16, PAGE_EXECUTE_READWRITE, &old)) return 0;
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) return 0;
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)my_NtCreateFile - (DWORD)(p + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(p, jb, 5);
    VirtualProtect(p, 5, old, &old);
    lg("unphook_ntredir: NtCreateFile hooked\n");
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        lg("unphook_ntredir: === attach ===\n");
        // self exe tail
        char self[MAX_PATH];
        GetModuleFileNameA(NULL, self, MAX_PATH);
        const char* tail = strrchr(self, '\\');
        tail = tail ? tail + 1 : self;
        int n = strlen(tail);
        for (int i = 0; i < n; i++) g_selftail[i] = (WCHAR)tail[i];
        g_selftail[n] = 0;
        // original path: strip \crack_work\dump\<selfname>, append \client.exe
        char dir[MAX_PATH]; strcpy(dir, self);
        char* p = strstr(dir, "\\crack_work\\dump\\");
        if (p) *p = 0; else { char* q = strrchr(dir, '\\'); if (q) *q = 0; }
        char origA[MAX_PATH];
        _snprintf(origA, MAX_PATH, "\\??\\%s\\client.exe", dir);
        int m = strlen(origA);
        for (int i = 0; i < m; i++) g_origpath[i] = (WCHAR)(BYTE)origA[i];
        g_origpath[m] = 0;
        lg("unphook_ntredir: self tail=%S orig=%S\n", g_selftail, g_origpath);
        hook_ncf();
    }
    return TRUE;
}
