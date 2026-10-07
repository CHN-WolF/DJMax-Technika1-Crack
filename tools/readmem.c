// readmem.c — read DWORDs from another process
// usage: readmem <pid> <addr_hex> <count>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 3) { printf("usage: readmem <pid> <addr_hex> [count]\n"); return 1; }
    DWORD pid = strtoul(argv[1], 0, 10);
    DWORD addr = strtoul(argv[2], 0, 16);
    int count = argc > 3 ? atoi(argv[3]) : 8;
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
    if (!h) { printf("OpenProcess fail %lu\n", GetLastError()); return 1; }
    for (int i = 0; i < count; i++) {
        DWORD v = 0; SIZE_T n = 0;
        if (!ReadProcessMemory(h, (void*)(addr + i * 4), &v, 4, &n) || n != 4) {
            printf("%08lx: <unreadable>\n", addr + i * 4);
        } else {
            printf("%08lx: %08lx\n", addr + i * 4, v);
        }
    }
    CloseHandle(h);
    return 0;
}
