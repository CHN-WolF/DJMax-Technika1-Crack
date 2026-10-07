// ttfsize.c — compute real TTF file size from its table directory
// usage: ttfsize <file> <offset>
#include <stdio.h>
#include <stdlib.h>

static unsigned be32(unsigned char* p) { return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    long off = atol(argv[2]);
    fseek(f, off, SEEK_SET);
    unsigned char h[12];
    fread(h, 1, 12, f);
    printf("sfnt=%02x%02x%02x%02x numTables=%u\n", h[0], h[1], h[2], h[3], (h[4] << 8) | h[5]);
    int nt = (h[4] << 8) | h[5];
    unsigned maxend = 0;
    for (int i = 0; i < nt; i++) {
        unsigned char r[16];
        fread(r, 1, 16, f);
        unsigned o = be32(r + 8), l = be32(r + 12);
        printf("  %.4s off=%u len=%u\n", r, o, l);
        if (o + l > maxend) maxend = o + l;
    }
    printf("real ttf size = %u (0x%x)\n", maxend, maxend);
    fclose(f);
    return 0;
}
