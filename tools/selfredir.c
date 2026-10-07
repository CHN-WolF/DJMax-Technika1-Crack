// selfredir.c — the final unpack-enabler DLL. Hook ntdll!NtCreateFile; when the
// shell opens its OWN exe (the rebuilt client_unpacked*.exe), create the
// ORIGINAL client.exe (game root) instead and return that handle. The shell's
// self-read then yields the protected original's bytes -> its file-content
// expectation holds -> no "Error loading program" (error 10).
//
// Must be loaded before the Themida stub runs: inject at CREATE_SUSPENDED time
// (run_unpacked.exe does this). NOTE: putting this DLL in the rebuilt exe's
// import table was tried (2026-10-06) and does NOT work — the Windows loader
// walks the exe's 3 system-DLL descriptors but never loads the added one
// (corrupted-name tests on descriptor #1 vs #4 prove it), and the mini-IAT
// slots turn out to be resolved by the shell at runtime, not by the loader.
#include <windows.h>
#include <stdio.h>

// minimal native layouts (32-bit)
typedef struct { WORD Length, MaximumLength; WCHAR* Buffer; } USTR32;
typedef struct { DWORD Length; HANDLE RootDirectory; USTR32* ObjectName; DWORD Attributes; void* SD; void* SQS; } OA32;
typedef LONG (WINAPI *NCF)(HANDLE*, DWORD, OA32*, void*, void*, DWORD, DWORD, DWORD, DWORD, void*, DWORD);

static BYTE g_tramp[16];
static WCHAR g_origpath[MAX_PATH];   // L"\??\<gameroot>\client.exe"
static WCHAR g_selftail[64];         // our exe's filename

// exported so client_unpacked.exe can statically import this DLL (loader then
// runs DllMain before the exe's TLS callbacks = before the Themida stub).
__declspec(dllexport) int selfredir_ping(void) { return 1; }

static LONG WINAPI my_NtCreateFile(HANDLE* fh, DWORD acc, OA32* oa, void* iosb, void* alloc,
                                   DWORD fattr, DWORD share, DWORD disp, DWORD copts, void* ea, DWORD ealen) {
    if (oa && oa->ObjectName) {
        OA32 oa2;
        USTR32 name2;
        USTR32* nm = oa->ObjectName;
        if (nm->Buffer && nm->Length >= 2) {
            // tail-match against our own exe name (wide, case-insensitive)
            int n = nm->Length / 2;
            int sl = 0; while (g_selftail[sl]) sl++;
            if (sl > 4 && n >= sl) {
                WCHAR* tail = nm->Buffer + (n - sl);
                int hit = 1;
                for (int i = 0; i < sl; i++) {
                    WCHAR a = tail[i], b = g_selftail[i];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { hit = 0; break; }
                }
                if (hit) {
                    oa2 = *oa;
                    name2 = *nm;
                    name2.Buffer = g_origpath;
                    name2.Length = wcslen(g_origpath) * 2;
                    name2.MaximumLength = name2.Length + 2;
                    oa2.ObjectName = &name2;
                    return ((NCF)g_tramp)(fh, acc, &oa2, iosb, alloc, fattr, share, disp, copts, ea, ealen);
                }
            }
        }
    }
    return ((NCF)g_tramp)(fh, acc, oa, iosb, alloc, fattr, share, disp, copts, ea, ealen);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        char self[MAX_PATH];
        GetModuleFileNameA(NULL, self, MAX_PATH);
        const char* tail = strrchr(self, '\\');
        tail = tail ? tail + 1 : self;
        int n = strlen(tail);
        for (int i = 0; i < n; i++) g_selftail[i] = (WCHAR)(BYTE)tail[i];
        g_selftail[n] = 0;
        char dir[MAX_PATH]; strcpy(dir, self);
        char* p = strstr(dir, "\\crack_work\\dump\\");
        if (p) *p = 0; else { char* q = strrchr(dir, '\\'); if (q) *q = 0; }
        char origA[MAX_PATH];
        _snprintf(origA, MAX_PATH, "\\??\\%s\\client.exe", dir);
        int m = strlen(origA);
        for (int i = 0; i < m; i++) g_origpath[i] = (WCHAR)(BYTE)origA[i];
        g_origpath[m] = 0;

        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (!nt) return TRUE;
        BYTE* p2 = (BYTE*)GetProcAddress(nt, "NtCreateFile");
        if (!p2) return TRUE;
        DWORD old;
        memcpy(g_tramp, p2, 5);
        g_tramp[5] = 0xE9;
        DWORD rel = (DWORD)(p2 + 5) - (DWORD)(g_tramp + 10);
        memcpy(g_tramp + 6, &rel, 4);
        if (!VirtualProtect(g_tramp, 16, PAGE_EXECUTE_READWRITE, &old)) return TRUE;
        if (!VirtualProtect(p2, 5, PAGE_EXECUTE_READWRITE, &old)) return TRUE;
        BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
        rel = (DWORD)my_NtCreateFile - (DWORD)(p2 + 5);
        memcpy(jb + 1, &rel, 4);
        memcpy(p2, jb, 5);
        VirtualProtect(p2, 5, old, &old);
    }
    return TRUE;
}
