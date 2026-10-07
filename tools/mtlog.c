// mtlog.dll — log PTFF MT19937 genrand outputs (keystream) from the game.
// Hooks only 0x5d6f80 (genrand_int32, thiscall, returns eax).
#include <windows.h>
#include <stdio.h>

typedef unsigned int u32;
static FILE* g_log;
static u32 g_ctr;

typedef u32 (WINAPI *GENF)(void);
static BYTE g_tramp[16];

__declspec(dllexport) u32 WINAPI my_gen(void) {
    u32 r = ((GENF)g_tramp)();
    if (g_log) { fprintf(g_log, "gen %u %08x\n", g_ctr, r); fflush(g_log); }
    g_ctr++;
    return r;
}

static void install(void* addr, void* detour) {
    DWORD old;
    memcpy(g_tramp, addr, 5);
    g_tramp[5] = 0xE9;
    DWORD rel = (DWORD)((BYTE*)addr + 5) - (DWORD)(g_tramp + 10);
    memcpy(g_tramp + 6, &rel, 4);
    VirtualProtect(g_tramp, 16, PAGE_EXECUTE_READWRITE, &old);
    VirtualProtect(addr, 5, PAGE_EXECUTE_READWRITE, &old);
    BYTE jb[5] = { 0xE9, 0, 0, 0, 0 };
    rel = (DWORD)detour - (DWORD)((BYTE*)addr + 5);
    memcpy(jb + 1, &rel, 4);
    memcpy(addr, jb, 5);
    VirtualProtect(addr, 5, old, &old);
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r) {
    if (why == DLL_PROCESS_ATTACH) {
        CreateDirectoryA("tpkdump_out", NULL);
        g_log = fopen("tpkdump_out\\mtlog.txt", "w");
        install((void*)0x5d6f80, my_gen);
        if (g_log) { fprintf(g_log, "mtlog loaded\n"); fflush(g_log); }
    }
    return TRUE;
}
