// dogtest_imgsnap.c — chained dog-call platform with module image snapshot diff.
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef int (WINAPI *tOpen)(DWORD, DWORD, DWORD);

typedef struct { char name[64]; DWORD base; DWORD size; } ModInfo;
static ModInfo g_mods[64];
static int g_nmods;

static void snapmods() {
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    g_nmods = 0;
    if (s != INVALID_HANDLE_VALUE && Module32First(s, &me)) {
        do {
            const char* n = me.szModule;
            if (strstr(n, "RC") || strstr(n, "Client") || strstr(n, "client")) {
                strcpy(g_mods[g_nmods].name, n);
                g_mods[g_nmods].base = (DWORD)me.modBaseAddr;
                g_mods[g_nmods].size = me.modBaseSize;
                if (++g_nmods >= 64) break;
            }
        } while (Module32Next(s, &me));
    }
    if (s != INVALID_HANDLE_VALUE) CloseHandle(s);
}

static void dump(const char* tag) {
    char fn[256];
    for (int i = 0; i < g_nmods; i++) {
        sprintf(fn, "%s_%08x_%s.bin", tag, g_mods[i].base, g_mods[i].name);
        for (char* p = fn; *p; p++) if (*p == '.' || *p == ' ') *p = '_';
        FILE* f = fopen(fn, "wb");
        if (f) { fwrite((void*)g_mods[i].base, 1, g_mods[i].size, f); fclose(f); }
        printf("dumped %s (%08x, %x)\n", fn, g_mods[i].base, g_mods[i].size);
    }
}

int main(int argc, char** argv) {
    const char* dll = argc > 1 ? argv[1] : "RCGrandDogW32.dll";
    HMODULE h = LoadLibraryA(dll);
    printf("LoadLibrary(%s)=%p err=%lu\n", dll, h, GetLastError());
    if (!h) return 1;
    snapmods();
    dump("before");
    tOpen o = (tOpen)GetProcAddress(h, "rc_OpenDog");
    char a2[64]; memset(a2, 0, sizeof(a2)); memcpy(a2, "GrandDog", 8);
    DWORD a3[8] = {0, 0x651a1ae3, 2, 0};
    int r = o(1, (DWORD)a2, (DWORD)a3);
    printf("rc_OpenDog -> %d (0x%x)\n", r, r);
    snapmods();
    dump("after");
    printf("now diff before_* vs after_*\n");
    return 0;
}
