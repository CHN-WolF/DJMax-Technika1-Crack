// jpgwalk.c — strict JPEG marker walker: SOI, length-delimited segments,
// SOS -> entropy scan (FF00 stuffed, RSTn ok) -> EOI. Reports truncation.
// usage: jpgwalk <file>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);
    if (sz < 4 || b[0] != 0xFF || b[1] != 0xD8) { printf("no SOI\n"); return 1; }
    long p = 2;
    int sos = 0;
    while (p + 1 < sz) {
        if (b[p] != 0xFF) { printf("@%ld: expected FF, got %02x (LOST SYNC)\n", p, b[p]); return 1; }
        unsigned char m = b[p + 1];
        if (m == 0xD9) { printf("@%ld EOI, filesize=%ld end=%ld %s\n", p, sz, p + 2, p + 2 == sz ? "EXACT" : "TRAILING"); return 0; }
        if (m == 0xD8) { p += 2; continue; }
        if (m == 0x00) { printf("@%ld stray FF00 before SOS\n", p); return 1; }
        if (m == 0xDA) {  // SOS
            int len = (b[p+2] << 8) | b[p+3];
            printf("@%ld SOS len=%d\n", p, len);
            p += 2 + len;
            sos = 1;
            break;
        }
        if ((m >= 0xD0 && m <= 0xD7) || m == 0x01) { p += 2; continue; }  // RST/TEM
        if (p + 3 >= sz) { printf("@%ld marker FF%02x truncated\n", p, m); return 1; }
        int len = (b[p+2] << 8) | b[p+3];
        if (len < 2) { printf("@%ld bad seg len %d\n", p, len); return 1; }
        p += 2 + len;
    }
    if (sos) {
        // entropy data: scan for EOI
        for (; p + 1 < sz; p++) {
            if (b[p] == 0xFF && b[p+1] == 0xD9) {
                printf("EOI at %ld, filesize=%ld %s\n", p, sz, p + 2 == sz ? "EXACT" : "TRAILING-extra");
                return 0;
            }
        }
        printf("NO EOI found (truncated at %ld of %ld)\n", p, sz);
        return 1;
    }
    printf("ran out before SOS\n");
    return 1;
}
