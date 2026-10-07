// hist.c — byte histogram + ascii-run scan of a file region
// usage: hist <file> <off> <len>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    long off = atol(argv[2]), len = atol(argv[3]);
    fseek(f, off, SEEK_SET);
    unsigned char* b = malloc(len);
    fread(b, 1, len, f); fclose(f);
    long h[256] = {0};
    for (long i = 0; i < len; i++) h[b[i]]++;
    // top 12 bytes
    for (int t = 0; t < 12; t++) {
        long mx = -1, mi = 0;
        for (int i = 0; i < 256; i++) if (h[i] > mx) { mx = h[i]; mi = i; }
        if (mx <= 0) break;
        printf("byte %02x : %ld (%.1f%%)\n", (int)mi, mx, 100.0 * mx / len);
        h[mi] = 0;
    }
    // ascii runs >= 6
    long rs = -1;
    for (long i = 0; i <= len; i++) {
        int ok = i < len && b[i] >= 32 && b[i] < 127;
        if (ok && rs < 0) rs = i;
        if (!ok && rs >= 0) {
            if (i - rs >= 6) { printf("ascii @%ld: %.*s\n", rs, (int)(i - rs > 60 ? 60 : i - rs), b + rs); }
            rs = -1;
        }
    }
    return 0;
}
