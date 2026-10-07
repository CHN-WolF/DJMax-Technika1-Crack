// checkhook.c — inspect a 32-bit target process: list modules, check whether
// selfredir.dll is loaded and whether ntdll!NtCreateFile is hooked (E9 jmp).
// Works because all 32-bit processes share the same WOW64 ntdll base per boot.
// usage: checkhook <pid>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: checkhook <pid>\n"); return 1; }
    DWORD pid = atoi(argv[1]);
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (s == INVALID_HANDLE_VALUE) { printf("snapshot fail %lu\n", GetLastError()); return 1; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    int has_self = 0;
    if (Module32First(s, &me)) do {
        printf("%08x %s\n", (DWORD)(DWORD_PTR)me.modBaseAddr, me.szModule);
        if (strstr(me.szModule, "selfredir")) has_self = 1;
    } while (Module32Next(s, &me));
    CloseHandle(s);

    BYTE* ncf = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateFile");
    HANDLE h = OpenProcess(PROCESS_VM_READ, 0, pid);
    BYTE buf[8] = {0}; SIZE_T r = 0;
    if (h && ReadProcessMemory(h, ncf, buf, 8, &r)) {
        printf("NtCreateFile bytes:"); for (int i = 0; i < 8; i++) printf(" %02x", buf[i]); printf("\n");
    } else printf("read fail %lu\n", GetLastError());
    printf("selfredir %s, NtCreateFile %s\n", has_self ? "LOADED" : "ABSENT",
           buf[0] == 0xE9 ? "HOOKED" : "clean");
    return 0;
}
