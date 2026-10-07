// dumpx.c — extract memory from a full minidump (.dmp) by VA range.
// usage: dumpx <file.dmp> <va_hex> <len>  -> raw bytes to stdout
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct { ULONG32 StreamType; ULONG32 Size; ULONG32 Rva; } STREAM;
typedef struct { ULONG64 Start; ULONG64 Size; } RANGE;

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "usage: dumpx file.dmp va_hex len\n"); return 2; }
    HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (f == INVALID_HANDLE_VALUE) { fprintf(stderr, "open fail %lu\n", GetLastError()); return 1; }
    LARGE_INTEGER fsz; GetFileSizeEx(f, &fsz);
    HANDLE mf = CreateFileMappingA(f, 0, PAGE_READONLY, 0, 0, 0);
    BYTE* base = (BYTE*)MapViewOfFile(mf, FILE_MAP_READ, 0, 0, 0);
    if (!base) { fprintf(stderr, "map fail\n"); return 1; }
    if (*(DWORD*)base != 0x504D444D) { fprintf(stderr, "not MDMP\n"); return 1; }
    ULONG32 nstreams = *(ULONG32*)(base + 8);
    ULONG32 dirrva = *(ULONG32*)(base + 12);
    unsigned long long want = strtoull(argv[2], 0, 16);
    unsigned long len = strtoul(argv[3], 0, 0);
    // find Memory64List (type 9)
    for (ULONG32 i = 0; i < nstreams; i++) {
        STREAM* s = (STREAM*)(base + dirrva + i * 12);
        if (s->StreamType != 9) continue;
        BYTE* p = base + s->Rva;
        ULONG64 nr = *(ULONG64*)p;
        RANGE* ranges = (RANGE*)(p + 16);
        ULONG64 datarva = s->Rva + 16 + nr * 16;
        ULONG64 remain = len;
        ULONG64 va = want;
        for (ULONG64 r = 0; r < nr; r++) {
            ULONG64 rs = ranges[r].Start, re = rs + ranges[r].Size;
            // find data file offset for this range: ranges are laid sequentially after the descriptor block
            // data for range r starts at datarva (computed cumulatively)
        }
        // cumulative walk
        ULONG64 off = datarva;
        for (ULONG64 r = 0; r < nr && remain; r++) {
            ULONG64 rs = ranges[r].Start, sz = ranges[r].Size, re = rs + sz;
            if (va >= rs && va < re) {
                ULONG64 skip = va - rs;
                ULONG64 avail = sz - skip;
                ULONG64 n = avail > remain ? remain : avail;
                fwrite(base + off + skip, 1, (size_t)n, stdout);
                va += n; remain -= n;
            }
            off += sz;
        }
        return 0;
    }
    fprintf(stderr, "no Memory64List\n");
    return 1;
}
