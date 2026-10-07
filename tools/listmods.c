#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: listmods <pid>\n"); return 2; }
    DWORD pid = atoi(argv[1]);
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (s == INVALID_HANDLE_VALUE) { printf("snap err %lu\n", GetLastError()); return 1; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    if (Module32First(s, &me)) do {
        if (strstr(me.szModule, "RC") || strstr(me.szModule, "client"))
            printf("%08x %08x %s\n", (DWORD)me.modBaseAddr, me.modBaseSize, me.szExePath);
    } while (Module32Next(s, &me));
    CloseHandle(s);
    return 0;
}
