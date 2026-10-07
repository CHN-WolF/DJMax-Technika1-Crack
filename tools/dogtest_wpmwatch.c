// dogtest_wpmwatch.c — chained dog-call platform with a WriteProcessMemory watch (wpmlog.txt).
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

static FILE* g_log;
static void* g_wpm = 0;
static BYTE g_origWPM[5], g_jmpWPM[5];
static void* g_llw = 0;
static BYTE g_origLLW[5], g_jmpLLW[5];

static BOOL (WINAPI *RealWPM)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = 0;
static HMODULE (WINAPI *RealLLW)(LPCWSTR) = 0;

static const char* modname(DWORD addr) {
    static char buf[128];
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    strcpy(buf, "?");
    if (snap != INVALID_HANDLE_VALUE && Module32First(snap, &me)) {
        do {
            DWORD base = (DWORD)me.modBaseAddr;
            if (addr >= base && addr < base + me.modBaseSize) {
                sprintf(buf, "%s+0x%x", me.szModule, addr - base);
                break;
            }
        } while (Module32Next(snap, &me));
    }
    if (snap != INVALID_HANDLE_VALUE) CloseHandle(snap);
    return buf;
}

static void setjmp(BYTE* jmp, void* from, void* to) {
    jmp[0] = 0xE9;
    *(DWORD*)(jmp + 1) = (DWORD)to - (DWORD)from - 5;
}

static BOOL WINAPI WPM_proxy(HANDLE h, LPCVOID base, LPVOID buf, SIZE_T sz, SIZE_T* wr) {
    fprintf(g_log, "WPM target=%08x (%s) size=%u bytes=", (DWORD)base, modname((DWORD)base), sz);
    __try {
        for (SIZE_T i = 0; i < sz && i < 48; i++) fprintf(g_log, "%02x", ((BYTE*)buf)[i]);
    } __except(1) { fprintf(g_log, "<unreadable>"); }
    fprintf(g_log, "\n");
    fflush(g_log);
    DWORD old;
    VirtualProtect(g_wpm, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_wpm, g_origWPM, 5);
    BOOL ret = RealWPM(h, base, buf, sz, wr);
    memcpy(g_wpm, g_jmpWPM, 5);
    VirtualProtect(g_wpm, 5, old, &old);
    return ret;
}

static HMODULE WINAPI LLW_proxy(LPCWSTR name) {
    HMODULE r = RealLLW(name);
    fprintf(g_log, "LoadLibraryW(%S) = %p\n", name ? name : L"(null)", r);
    fflush(g_log);
    return r;
}

static void hook(void* api, void* proxy, BYTE* saved, BYTE* jmp) {
    DWORD old;
    VirtualProtect(api, 5, PAGE_EXECUTE_READWRITE, &old);
    memcpy(saved, api, 5);
    setjmp(jmp, api, proxy);
    memcpy(api, jmp, 5);
    VirtualProtect(api, 5, old, &old);
}

typedef int (WINAPI *tOpen)(DWORD, DWORD, DWORD);

int main(int argc, char** argv) {
    g_log = fopen("wpmlog.txt", "w");
    setvbuf(g_log, 0, _IONBF, 0);
    HMODULE k = GetModuleHandleA("kernel32.dll");
    g_wpm = GetProcAddress(k, "WriteProcessMemory");
    g_llw = GetProcAddress(k, "LoadLibraryW");
    RealWPM = (BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*))g_wpm;
    RealLLW = (HMODULE(WINAPI*)(LPCWSTR))g_llw;
    hook(g_wpm, WPM_proxy, g_origWPM, g_jmpWPM);
    hook(g_llw, LLW_proxy, g_origLLW, g_jmpLLW);
    fprintf(g_log, "hooks installed\n");

    const char* dll = argc > 1 ? argv[1] : "RCGrandDogW32.dll";
    HMODULE h = LoadLibraryA(dll);
    fprintf(g_log, "LoadLibrary(%s)=%p err=%lu\n", dll, h, GetLastError());
    tOpen o = (tOpen)GetProcAddress(h, "rc_OpenDog");
    char a2[64]; memset(a2, 0, sizeof(a2)); memcpy(a2, "GrandDog", 8);
    DWORD a3[8] = {0, 0x651a1ae3, 2, 0};
    int r = o(1, (DWORD)a2, (DWORD)a3);
    fprintf(g_log, "rc_OpenDog -> %d (0x%x)\n", r, r);
    fclose(g_log);
    printf("done, see wpmlog.txt\n");
    return 0;
}
