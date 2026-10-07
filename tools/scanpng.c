// scanpng.c — break tpk second-layer cipher via PNG known-plaintext.
// Outer layer: 16-byte repeating XOR key starting at file offset 12.
// Second layer model candidates (both 16-byte repeating XOR):
//   "reset": key phase 0 at entry start O
//   "grid":  key phase follows file offset ((O+i-12)&15)
// A PNG entry has fully-known bytes 0..15; check bytes at 24..28 (fixed
// 08 06/02 00 00 00) and 37..40 ("IDAT") must match the same 16-byte key.
// usage: scanpng <file.tpk>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char K16[16] = { 0x72,0x0d,0xe1,0xe4,0xb8,0x47,0x76,0x4a,
                                       0x79,0x7f,0x37,0x1b,0x57,0x9d,0x31,0xdb };
static const unsigned char PNG16[16] = { 0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
                                         0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52 };
// bytes 24..28: bitdepth=8, colortype(2 or 6), comp=0, filter=0, interlace=0
// bytes 37..40: "IDAT"

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* raw = malloc(sz);
    fread(raw, 1, sz, f); fclose(f);
    // strip outer layer
    unsigned char* d = malloc(sz);
    for (long i = 0; i < sz; i++) d[i] = (i < 12) ? raw[i] : raw[i] ^ K16[(i - 12) & 15];

    long hits = 0;
    for (long O = 12; O + 41 < sz; O += 16) {
        if (!memcmp(d + O, PNG16, 16)) { printf("PLAIN-PNG at %ld\n", O); hits++; continue; }
        for (int model = 0; model < 2; model++) {
            unsigned char K[16];
            for (int i = 0; i < 16; i++) {
                int ph = model == 0 ? i : (int)((O + i - 12) & 15);
                K[i] = d[O + i] ^ PNG16[i];
                (void)ph;
            }
            // check bytes 24..28: known-ish (allow colortype 2|6)
            int okc = 0;
            for (int j = 0; j < 5; j++) {
                int pos = 24 + j;
                int ph = model == 0 ? (pos & 15) : (int)((O + pos - 12) & 15);
                unsigned char v = d[O + pos] ^ K[ph];
                if (j == 0 && v == 8) okc++;
                if (j == 1 && (v == 2 || v == 6 || v == 0 || v == 3 || v == 4)) okc++;
                if (j >= 2 && v == 0) okc++;
            }
            int okd = 0;
            for (int j = 0; j < 4; j++) {
                int pos = 37 + j;
                int ph = model == 0 ? (pos & 15) : (int)((O + pos - 12) & 15);
                unsigned char v = d[O + pos] ^ K[ph];
                if (v == "IDAT"[j]) okd++;
            }
            if (okc == 5 && okd == 4) {
                printf("HIT off=%ld model=%s K2=", O, model ? "grid" : "reset");
                for (int i = 0; i < 16; i++) printf("%02x", K[i]);
                printf("\n");
                hits++;
            }
        }
    }
    printf("hits=%ld\n", hits);
    return 0;
}
