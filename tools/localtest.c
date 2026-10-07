// localtest: run official RC_GrandLocal through the game's call sequence while
// logging every registry key / file / dll it touches (IAT hook on the loaded module).
#include <windows.h>
#include <stdio.h>
#include <string.h>

static FILE* lf;
static HMODULE g_official;
static void lg(const char* fmt, ...) {
    if (!lf) { lf = fopen("lt3.txt", "w"); if (lf) setvbuf(lf, 0, _IONBF, 0); }
    if (!lf) return;
    va_list ap; va_start(ap, fmt); vfprintf(lf, fmt, ap); va_end(ap);
}

typedef LSTATUS (WINAPI *tRegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *tRegOpenKeyA)(HKEY, LPCSTR, PHKEY);
typedef LSTATUS (WINAPI *tRegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS (WINAPI *tRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LSTATUS (WINAPI *tRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LSTATUS (WINAPI *tRegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LSTATUS (WINAPI *tRegEnumValueA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef HANDLE (WINAPI *tCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *tCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HMODULE (WINAPI *tLoadLibraryA)(LPCSTR);
typedef HMODULE (WINAPI *tLoadLibraryW)(LPCWSTR);

static tRegOpenKeyExA oRegOpenKeyExA; static tRegOpenKeyA oRegOpenKeyA;
static tRegQueryValueExA oRegQueryValueExA; static tRegCreateKeyExA oRegCreateKeyExA;
static tRegSetValueExA oRegSetValueExA; static tRegEnumKeyExA oRegEnumKeyExA; static tRegEnumValueA oRegEnumValueA;
static tCreateFileA oCreateFileA; static tCreateFileW oCreateFileW;
static tLoadLibraryA oLoadLibraryA; static tLoadLibraryW oLoadLibraryW;

static const char* hk(HKEY k) {
    if (k == HKEY_LOCAL_MACHINE) return "HKLM";
    if (k == HKEY_CURRENT_USER) return "HKCU";
    if (k == HKEY_CLASSES_ROOT) return "HKCR";
    if (k == HKEY_USERS) return "HKU";
    return "HK?";
}

static LSTATUS WINAPI hRegOpenKeyExA(HKEY k, LPCSTR s, DWORD o, REGSAM a, PHKEY r) {
    lg("RegOpenKeyExA %s\\%s\n", hk(k), s ? s : "(null)");
    return oRegOpenKeyExA(k, s, o, a, r);
}
static LSTATUS WINAPI hRegOpenKeyA(HKEY k, LPCSTR s, PHKEY r) {
    lg("RegOpenKeyA %s\\%s\n", hk(k), s ? s : "(null)");
    return oRegOpenKeyA(k, s, r);
}
static LSTATUS WINAPI hRegQueryValueExA(HKEY k, LPCSTR s, LPDWORD r1, LPDWORD t, LPBYTE d, LPDWORD n) {
    lg("RegQueryValueExA [%08x]\\%s\n", (DWORD)k, s ? s : "(null)");
    return oRegQueryValueExA(k, s, r1, t, d, n);
}
static LSTATUS WINAPI hRegCreateKeyExA(HKEY k, LPCSTR s, DWORD o, LPSTR c, DWORD e, REGSAM a, LPSECURITY_ATTRIBUTES p, PHKEY r, LPDWORD w) {
    lg("RegCreateKeyExA %s\\%s\n", hk(k), s ? s : "(null)");
    return oRegCreateKeyExA(k, s, o, c, e, a, p, r, w);
}
static LSTATUS WINAPI hRegSetValueExA(HKEY k, LPCSTR s, DWORD r1, DWORD t, const BYTE* d, DWORD n) {
    lg("RegSetValueExA [%08x]\\%s type=%u size=%u\n", (DWORD)k, s ? s : "(null)", t, n);
    return oRegSetValueExA(k, s, r1, t, d, n);
}
static LSTATUS WINAPI hRegEnumKeyExA(HKEY k, DWORD i, LPSTR n, LPDWORD c, LPDWORD r1, LPSTR cn, LPDWORD cc, PFILETIME t) {
    lg("RegEnumKeyExA [%08x] idx=%u\n", (DWORD)k, i);
    return oRegEnumKeyExA(k, i, n, c, r1, cn, cc, t);
}
static LSTATUS WINAPI hRegEnumValueA(HKEY k, DWORD i, LPSTR n, LPDWORD c, LPDWORD r1, LPDWORD t, LPBYTE d, LPDWORD s) {
    lg("RegEnumValueA [%08x] idx=%u\n", (DWORD)k, i);
    return oRegEnumValueA(k, i, n, c, r1, t, d, s);
}
static HANDLE WINAPI hCreateFileA(LPCSTR s, DWORD a, DWORD sh, LPSECURITY_ATTRIBUTES p, DWORD d, DWORD f, HANDLE t) {
    lg("CreateFileA %s\n", s ? s : "(null)");
    return oCreateFileA(s, a, sh, p, d, f, t);
}
static HANDLE WINAPI hCreateFileW(LPCWSTR s, DWORD a, DWORD sh, LPSECURITY_ATTRIBUTES p, DWORD d, DWORD f, HANDLE t) {
    lg("CreateFileW %S\n", s ? s : L"(null)");
    return oCreateFileW(s, a, sh, p, d, f, t);
}
static HMODULE WINAPI hLoadLibraryA(LPCSTR s) {
    lg("LoadLibraryA %s\n", s ? s : "(null)");
    return oLoadLibraryA(s);
}
static HMODULE WINAPI hLoadLibraryW(LPCWSTR s) {
    lg("LoadLibraryW %S\n", s ? s : L"(null)");
    return oLoadLibraryW(s);
}

static PIMAGE_IMPORT_DESCRIPTOR get_imports(HMODULE m) {
    PIMAGE_DOS_HEADER dosh = (PIMAGE_DOS_HEADER)m;
    PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)((BYTE*)m + dosh->e_lfanew);
    DWORD rva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD sz = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    (void)sz;
    return rva ? (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)m + rva) : 0;
}

static void hook_iat(HMODULE target) {
    PIMAGE_IMPORT_DESCRIPTOR imp = get_imports(target);
    if (!imp) return;
    for (; imp->Name; imp++) {
        PIMAGE_THUNK_DATA t = (PIMAGE_THUNK_DATA)((BYTE*)target + imp->FirstThunk);
        PIMAGE_THUNK_DATA o = (PIMAGE_THUNK_DATA)((BYTE*)target + imp->OriginalFirstThunk);
        const char* dll = (const char*)((BYTE*)target + imp->Name);
        for (; t->u1.Function; t++, o++) {
            if (!(o->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                const char* fn = (const char*)((BYTE*)target + o->u1.AddressOfData + 2);
                void* mine = 0; void** slot = (void**)&t->u1.Function;
                #define H(name, my) if (!strcmp(fn, #name)) { mine = (void*)my; }
                H(RegOpenKeyExA, hRegOpenKeyExA) else H(RegOpenKeyA, hRegOpenKeyA)
                else H(RegQueryValueExA, hRegQueryValueExA) else H(RegCreateKeyExA, hRegCreateKeyExA)
                else H(RegSetValueExA, hRegSetValueExA) else H(RegEnumKeyExA, hRegEnumKeyExA)
                else H(RegEnumValueA, hRegEnumValueA) else H(CreateFileA, hCreateFileA)
                else H(CreateFileW, hCreateFileW) else H(LoadLibraryA, hLoadLibraryA)
                else H(LoadLibraryW, hLoadLibraryW)
                if (mine) {
                    DWORD old;
                    VirtualProtect(slot, 4, PAGE_EXECUTE_READWRITE, &old);
                    void* orig = *slot;
                    *slot = mine;
                    VirtualProtect(slot, 4, old, &old);
                    if (!oRegOpenKeyExA && !strcmp(fn, "RegOpenKeyExA")) oRegOpenKeyExA = (tRegOpenKeyExA)orig;
                    if (!oRegOpenKeyA && !strcmp(fn, "RegOpenKeyA")) oRegOpenKeyA = (tRegOpenKeyA)orig;
                    if (!oRegQueryValueExA && !strcmp(fn, "RegQueryValueExA")) oRegQueryValueExA = (tRegQueryValueExA)orig;
                    if (!oRegCreateKeyExA && !strcmp(fn, "RegCreateKeyExA")) oRegCreateKeyExA = (tRegCreateKeyExA)orig;
                    if (!oRegSetValueExA && !strcmp(fn, "RegSetValueExA")) oRegSetValueExA = (tRegSetValueExA)orig;
                    if (!oRegEnumKeyExA && !strcmp(fn, "RegEnumKeyExA")) oRegEnumKeyExA = (tRegEnumKeyExA)orig;
                    if (!oRegEnumValueA && !strcmp(fn, "RegEnumValueA")) oRegEnumValueA = (tRegEnumValueA)orig;
                    if (!oCreateFileA && !strcmp(fn, "CreateFileA")) oCreateFileA = (tCreateFileA)orig;
                    if (!oCreateFileW && !strcmp(fn, "CreateFileW")) oCreateFileW = (tCreateFileW)orig;
                    if (!oLoadLibraryA && !strcmp(fn, "LoadLibraryA")) oLoadLibraryA = (tLoadLibraryA)orig;
                    if (!oLoadLibraryW && !strcmp(fn, "LoadLibraryW")) oLoadLibraryW = (tLoadLibraryW)orig;
                }
            }
        }
    }
}

typedef int (WINAPI *t4)(DWORD, DWORD, DWORD, DWORD);
static t4 f(int n) { return (t4)GetProcAddress(g_official, (LPCSTR)n); }

int main() {
    lf = fopen("lt3.txt", "w"); setvbuf(lf, 0, _IONBF, 0);
    lg("=== localtest start ===\n");
    g_official = LoadLibraryA("RC_GrandLocalReal.dll");
    lg("official=%p err=%lu\n", g_official, GetLastError());
    if (!g_official) return 1;
    hook_iat(g_official);
    lg("IAT hooked\n");

    char name[] = "RC_GrandLocal.dll";
    static BYTE seed[512], o5[512], o23[512], o21[512], a[512], b[512];
    // 游戏固定挑战(来自 rclog2_realdog_full.txt round1)
    static const BYTE challenge[32] = {0x7e,0x29,0xd5,0x17,0xfb,0x11,0x49,0xc4,0xfd,0x4f,0xf8,0x95,0x41,0xc9,0xc2,0xda,0xf9,0x07,0x49};
    memcpy(seed, challenge, 32);
    memset(o5, 0, sizeof(o5));
    int r5 = f(5)((DWORD)seed, (DWORD)o5, (DWORD)name, 0xb8);
    lg("ord5 -> %d out16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", r5,
        o5[0],o5[1],o5[2],o5[3],o5[4],o5[5],o5[6],o5[7],o5[8],o5[9],o5[10],o5[11],o5[12],o5[13],o5[14],o5[15]);
    memset(o23, 0, sizeof(o23));
    int r23 = f(23)(0x10, (DWORD)o23, (DWORD)name, 0xb8);
    lg("ord23 -> %d out16=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", r23,
        o23[0],o23[1],o23[2],o23[3],o23[4],o23[5],o23[6],o23[7],o23[8],o23[9],o23[10],o23[11],o23[12],o23[13],o23[14],o23[15]);
    memset(o21, 0, sizeof(o21));
    int r21 = f(21)((DWORD)o21, 1, (DWORD)name, 0xb8);
    lg("ord21 -> %d\n", r21);
    // ord28 各形态
    memset(a, 0, sizeof(a)); memset(b, 0, sizeof(b));
    int r28a = f(28)((DWORD)a, (DWORD)b, (DWORD)b, 0x2560);
    lg("ord28(v0) -> %d a=%02x%02x%02x%02x%02x%02x%02x%02x\n", r28a, a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
    memset(a, 0, sizeof(a));
    int r28b = f(28)((DWORD)a, 1, (DWORD)b, 0x2d9f3fa8);
    lg("ord28(v1) -> %d a=%02x%02x%02x%02x%02x%02x%02x%02x\n", r28b, a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
    memset(a, 0, sizeof(a));
    int r28c = f(28)((DWORD)a, 2, (DWORD)b, 0x2560);
    lg("ord28(v2) -> %d a=%02x%02x%02x%02x%02x%02x%02x%02x\n", r28c, a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
    lg("=== done ===\n");
    return 0;
}
