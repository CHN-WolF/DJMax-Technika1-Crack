// dumpreg.c — dump raw bytes from another process to a file.
// usage: dumpreg <pid> <addr_hex> <size_hex> <outfile>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv) {
    if (argc < 5) { printf("usage: dumpreg <pid> <addr> <size> <out>\n"); return 1; }
    DWORD pid = strtoul(argv[1], 0, 10);
    DWORD addr = strtoul(argv[2], 0, 16);
    DWORD size = strtoul(argv[3], 0, 16);
    HANDLE h = OpenProcess(PROCESS_VM_READ, 0, pid);
    if (!h) { printf("OpenProcess fail %lu\n", GetLastError()); return 1; }
    FILE* f = fopen(argv[4], "wb");
    if (!f) { printf("open out fail\n"); return 1; }
    static BYTE buf[0x10000];
    DWORD off = 0;
    while (off < size) {
        DWORD chunk = size - off; if (chunk > sizeof(buf)) chunk = sizeof(buf);
        SIZE_T got = 0;
        ReadProcessMemory(h, (void*)(addr + off), buf, chunk, &got);
        fwrite(buf, 1, got, f);
        if (got < chunk) { BYTE z = 0; for (DWORD k = got; k < chunk; k++) fwrite(&z, 1, 1, f); }
        off += chunk;
    }
    fclose(f);
    printf("wrote %lu bytes from %08lx\n", size, addr);
    return 0;
}
