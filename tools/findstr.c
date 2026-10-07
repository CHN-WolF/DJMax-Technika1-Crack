// findstr.c — find ASCII string occurrences in a process's committed memory
// usage: findstr <pid> <string>
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    DWORD pid = atoi(argv[1]);
    const char* needle = argv[2];
    int nl = strlen(needle);
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if (!h) { printf("open fail %lu\n", GetLastError()); return 1; }
    DWORD addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    int hits = 0;
    while (addr < 0x7fff0000) {
        if (!VirtualQueryEx(h, (void*)addr, &mbi, sizeof(mbi))) break;
        addr = (DWORD)mbi.BaseAddress + mbi.RegionSize;
        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) continue;
        unsigned char* b = malloc(mbi.RegionSize);
        SIZE_T got;
        if (ReadProcessMemory(h, mbi.BaseAddress, b, mbi.RegionSize, &got)) {
            for (SIZE_T i = 0; i + nl <= got; i++)
                if (!memcmp(b + i, needle, nl)) {
                    printf("%08x\n", (DWORD)mbi.BaseAddress + (DWORD)i);
                    if (++hits > 20) { free(b); return 0; }
                }
        }
        free(b);
    }
    printf("hits=%d\n", hits);
    return 0;
}
