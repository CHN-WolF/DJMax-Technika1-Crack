// pollva.c — watch a VA range in a running process; dump when content changes.
// usage: pollva <pid> <va_hex> <len> <outprefix>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    DWORD pid = atoi(argv[1]);
    DWORD va = strtoul(argv[2], 0, 16);
    long len = atol(argv[3]);
    const char* pre = argv[4];
    HANDLE h = OpenProcess(PROCESS_VM_READ, 0, pid);
    if (!h) { printf("open fail %lu\n", GetLastError()); return 1; }
    unsigned char* prev = malloc(len);
    unsigned char* cur = malloc(len);
    SIZE_T got;
    if (!ReadProcessMemory(h, (void*)va, prev, len, &got)) { printf("read fail %lu\n", GetLastError()); return 1; }
    printf("watching %08x (%ld bytes), initial snapshot taken\n", va, len);
    int n = 0;
    for (;;) {
        Sleep(500);
        if (!ReadProcessMemory(h, (void*)va, cur, len, &got) || got != len) {
            printf("read fail/gone at %lu\n", GetLastError());
            // buffer freed: stop
            return 1;
        }
        if (memcmp(cur, prev, len)) {
            char path[MAX_PATH];
            _snprintf(path, MAX_PATH, "%s_%d.bin", pre, n++);
            FILE* f = fopen(path, "wb");
            fwrite(cur, 1, len, f); fclose(f);
            printf("CHANGE -> %s\n", path);
            memcpy(prev, cur, len);
        }
    }
}
