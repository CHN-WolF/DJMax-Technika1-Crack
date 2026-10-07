// scanptr.c — scan a dump file (with known base VA) for DWORD values that look
// like pointers into a target VA range; report histogram + sample locations.
// usage: scanptr <file> <base_va_hex> <lo_hex> <hi_hex>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 5) { printf("usage: scanptr <file> <base_va> <lo> <hi>\n"); return 1; }
    const char* fn = argv[1];
    DWORD base = strtoul(argv[2], 0, 16);
    DWORD lo = strtoul(argv[3], 0, 16);
    DWORD hi = strtoul(argv[4], 0, 16);
    FILE* f = fopen(fn, "rb");
    if (!f) { printf("open fail\n"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);
    int hits = 0;
    int nb = (int)(hi >> 16) + 1;
    DWORD* per64k = calloc(nb, 4);
    for (long i = 0; i + 4 <= sz; i += 4) {
        DWORD v = *(DWORD*)(buf + i);
        if (v >= lo && v < hi) {
            hits++;
            per64k[v >> 16]++;
            if (hits <= 40)
                printf("  [%08x] -> %08x\n", base + (DWORD)i, v);
        }
    }
    printf("total %d pointers into [%08x,%08x)\n", hits, lo, hi);
    printf("hot target 64KB blocks:\n");
    for (int i = 0; i < nb; i++)
        if (per64k[i] >= 4) printf("  %08x..: %d\n", i << 16, per64k[i]);
    free(per64k);
    free(buf);
    return 0;
}
