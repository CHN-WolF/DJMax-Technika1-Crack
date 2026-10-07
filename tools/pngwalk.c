// pngwalk.c — strict PNG chunk walker with CRC check
// usage: pngwalk <file> [maxchunks]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int crc32b(const unsigned char* s, long n) {
    unsigned int c = 0xFFFFFFFF;
    for (long i = 0; i < n; i++) {
        c ^= s[i];
        for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : c >> 1;
    }
    return c ^ 0xFFFFFFFF;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);
    if (memcmp(b, "\x89PNG\r\n\x1a\n", 8)) { printf("no magic\n"); return 1; }
    long p = 8;
    int maxc = argc > 2 ? atoi(argv[2]) : 30;
    for (int n = 0; n < maxc && p + 12 <= sz; n++) {
        long clen = ((long)b[p] << 24) | (b[p+1] << 16) | (b[p+2] << 8) | b[p+3];
        char type[5]; memcpy(type, b + p + 4, 4); type[4] = 0;
        if (clen < 0 || p + 12 + clen > sz) { printf("@%ld type=%.4s len=%ld OUT-OF-RANGE\n", p, type, clen); break; }
        unsigned int crcok = 0;
        if (clen >= 0) {
            unsigned int comp = crc32b(b + p + 4, 4 + clen);
            unsigned int stored = ((unsigned)b[p+8+clen] << 24) | (b[p+9+clen] << 16) | (b[p+10+clen] << 8) | b[p+11+clen];
            crcok = (comp == stored);
        }
        printf("@%-7ld %-4s len=%-8ld crc=%s\n", p, type, clen, crcok ? "OK" : "BAD");
        if (!memcmp(type, "IEND", 4)) break;
        p += 12 + clen;
    }
    printf("filesize=%ld end=%ld\n", sz, p);
    return 0;
}
