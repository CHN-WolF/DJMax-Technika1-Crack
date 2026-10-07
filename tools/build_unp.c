// build_unp.c — C port of rebuild.py: client.exe + dumpmem/oepdump image.bin ->
// client_unpacked.exe. Section raw <- live image bytes, plain 3-DLL import
// table at RVA 0xf65004c, EP stays, TLS/reloc/debug cleared, RELOCS_STRIPPED.
// usage: build_unp <client.exe> <image.bin|-> <out.exe>   ("-" = imports/headers only)
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static BYTE* g_data;
static long g_dsz;

// section table model
#define MAXSEC 16
static struct { char name[9]; DWORD vsz, rva, rawsz, rawoff; } g_sec[MAXSEC];
static int g_nsec;
static DWORD g_peoff, g_opt;

static long rva2off(DWORD rva) {
    for (int i = 0; i < g_nsec; i++) {
        DWORD span = g_sec[i].vsz > g_sec[i].rawsz ? g_sec[i].vsz : g_sec[i].rawsz;
        if (rva >= g_sec[i].rva && rva < g_sec[i].rva + span)
            return g_sec[i].rawoff + (rva - g_sec[i].rva);
    }
    return -1;
}

int main(int argc, char** argv) {
    if (argc < 4) { printf("usage: build_unp <client.exe> <image.bin> <out.exe>\n"); return 1; }
    FILE* f = fopen(argv[1], "rb");
    if (!f) { printf("open src fail\n"); return 1; }
    fseek(f, 0, SEEK_END); g_dsz = ftell(f); fseek(f, 0, SEEK_SET);
    g_data = malloc(g_dsz);
    fread(g_data, 1, g_dsz, f); fclose(f);

    f = fopen(argv[2], "rb");
    BYTE* img = NULL; long isz = 0;
    if (f) {
        fseek(f, 0, SEEK_END); isz = ftell(f); fseek(f, 0, SEEK_SET);
        img = malloc(isz);
        fread(img, 1, isz, f); fclose(f);
        printf("image.bin = %ld bytes\n", isz);
    } else {
        printf("no image: imports/headers only\n");  // argv[2] unreadable or "-"
    }
    const DWORD IMGBASE = 0x400000;

    g_peoff = *(DWORD*)(g_data + 0x3c);
    g_nsec = *(WORD*)(g_data + g_peoff + 6);
    WORD optsz = *(WORD*)(g_data + g_peoff + 0x14);
    g_opt = g_peoff + 0x18;
    BYTE* s = g_data + g_opt + optsz;
    for (int i = 0; i < g_nsec; i++, s += 40) {
        memcpy(g_sec[i].name, s, 8); g_sec[i].name[8] = 0;
        g_sec[i].vsz = *(DWORD*)(s + 8);
        g_sec[i].rva = *(DWORD*)(s + 12);
        g_sec[i].rawsz = *(DWORD*)(s + 16);
        g_sec[i].rawoff = *(DWORD*)(s + 20);
    }
    printf("sections=%d EP=%08x\n", g_nsec, *(DWORD*)(g_data + g_opt + 0x28));

    // 1) section raw <- live image bytes (skipped in imports-only mode)
    for (int i = 0; img && i < g_nsec; i++) {
        DWORD va = IMGBASE + g_sec[i].rva;
        DWORD lo = va - IMGBASE;  // offset into image.bin
        if ((long)(lo + g_sec[i].rawsz) <= isz) {
            memcpy(g_data + g_sec[i].rawoff, img + lo, g_sec[i].rawsz);
            printf("sec %-8s <- image [%08x..%08x]\n", g_sec[i].name, va, va + g_sec[i].rawsz);
        } else {
            printf("sec %-8s: beyond image, kept file bytes\n", g_sec[i].name);
        }
    }

    // 2) plain import table at RVA 0xf65004c (3 system DLLs only; the shell
    //    re-resolves these mini-IAT slots at runtime anyway. NOTE: adding a 4th
    //    descriptor for selfredir.dll was tried 2026-10-06 — the loader never
    //    loads it (corrupted-name tests), so standalone-via-import is impossible)
    DWORD IMP = 0xf65004c;
    long off = rva2off(IMP);
    if (off < 0) { printf("import RVA unmappable!\n"); return 1; }
    DWORD base = IMP;
    BYTE* d = g_data + off;

    static const struct { const char* dll; DWORD ft; int napis; const char* apis[6]; } spec[4] = {
        { "ADVAPI32.dll", 0xf650000, 1, { "RegOpenKeyExA" } },
        { "KERNEL32.dll", 0xf650008, 4, { "GetSystemDirectoryA", "LoadLibraryA", "GetModuleHandleA", "GetProcAddress" } },
        { "USER32.dll",   0xf65001c, 1, { "MessageBoxA" } },
    };
    DWORD oft_rva[4];
    DWORD p = 0x50;  // offset within the import dir area
    // OFT arrays
    DWORD oft_ofts[4][6]; int oft_cnt[4];
    for (int i = 0; i < 3; i++) {
        oft_rva[i] = base + p;
        oft_cnt[i] = 0;
        p += (spec[i].napis + 1) * 4;
    }
    // strings
    DWORD strp = 0x80;
    DWORD dllname_rva[4];
    for (int i = 0; i < 3; i++) {
        dllname_rva[i] = base + strp;
        strcpy((char*)d + strp, spec[i].dll);
        strp += strlen(spec[i].dll) + 1;
    }
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < spec[i].napis; j++) {
            // hint/name: 2-byte hint (0) + name
            d[strp] = 0; d[strp + 1] = 0;
            strcpy((char*)d + strp + 2, spec[i].apis[j]);
            oft_ofts[i][j] = base + strp;   // hintname rva
            strp += 2 + strlen(spec[i].apis[j]) + 1;
        }
    }
    // OFT tables
    p = 0x50;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < spec[i].napis; j++) {
            *(DWORD*)(d + p) = oft_ofts[i][j];
            p += 4;
        }
        *(DWORD*)(d + p) = 0; p += 4;
    }
    // descriptors
    for (int i = 0; i < 3; i++) {
        *(DWORD*)(d + i * 20 + 0) = oft_rva[i];
        *(DWORD*)(d + i * 20 + 4) = 0;
        *(DWORD*)(d + i * 20 + 8) = 0;
        *(DWORD*)(d + i * 20 + 12) = dllname_rva[i];
        *(DWORD*)(d + i * 20 + 16) = spec[i].ft;
    }
    memset(d + 3 * 20, 0, 20);
    printf("import table written, end=%08x (dir cap 0x152): %s\n", base + strp,
           strp <= 0x152 ? "fits" : "OVERFLOW!");

    // 3) headers: clear TLS/reloc/debug, set RELOCS_STRIPPED
    DWORD dd = g_opt + 0x60;
    *(DWORD*)(g_data + dd + 9 * 8) = 0; *(DWORD*)(g_data + dd + 9 * 8 + 4) = 0;  // TLS
    *(DWORD*)(g_data + dd + 5 * 8) = 0; *(DWORD*)(g_data + dd + 5 * 8 + 4) = 0;  // reloc
    *(DWORD*)(g_data + dd + 6 * 8) = 0; *(DWORD*)(g_data + dd + 6 * 8 + 4) = 0;  // debug
    WORD chars = *(WORD*)(g_data + g_peoff + 0x16);
    *(WORD*)(g_data + g_peoff + 0x16) = chars | 0x0001;

    f = fopen(argv[3], "wb");
    fwrite(g_data, 1, g_dsz, f);
    fclose(f);
    printf("wrote %s (%ld bytes)\n", argv[3], g_dsz);
    return 0;
}
