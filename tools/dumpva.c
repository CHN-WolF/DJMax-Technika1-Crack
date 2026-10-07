// dumpva.c — read a VA range from a running process into a file.
// usage: dumpva <pid> <va_hex> <len> <outfile>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 5) { printf("usage: dumpva <pid> <va_hex> <len> <out>\n"); return 1; }
    DWORD pid = strtoul(argv[1], 0, 10);
    DWORD va = strtoul(argv[2], 0, 16);
    long len = atol(argv[3]);
    HANDLE h = OpenProcess(PROCESS_VM_READ, 0, pid);
    if (!h) { printf("open fail %lu\n", GetLastError()); return 1; }
    unsigned char* b = malloc(len);
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, (void*)va, b, len, &got)) { printf("read fail %lu\n", GetLastError()); return 1; }
    FILE* f = fopen(argv[4], "wb");
    fwrite(b, 1, got, f); fclose(f);
    printf("wrote %s (%lu bytes)\n", argv[4], (unsigned long)got);
    return 0;
}
