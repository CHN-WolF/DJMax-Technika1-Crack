// tryoff.c — test PNG known-plaintext at specific offsets in a tpk.
// Prints derived K2 and check-byte verification for models:
//   reset: cipher2 phase 0 at entry start
//   grid:  cipher2 phase follows (fileoff-12)&15
// usage: tryoff <file.tpk> <off1> [off2 ...]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char K16[16] = { 0x72,0x0d,0xe1,0xe4,0xb8,0x47,0x76,0x4a,
                                       0x79,0x7f,0x37,0x1b,0x57,0x9d,0x31,0xdb };
static const unsigned char PNG16[16] = { 0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,
                                         0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52 };

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* raw = malloc(sz);
    fread(raw, 1, sz, f); fclose(f);

    for (int a = 2; a < argc; a++) {
        long O = atol(argv[a]);
        printf("--- off %ld (0x%lx)\n", O, O);
        // show raw->K16-decrypted first 16 bytes
        printf("  dec16: ");
        for (int i = 0; i < 16; i++) printf("%02x ", raw[O + i] ^ K16[(O + i - 12) & 15]);
        printf("\n");
        for (int model = 0; model < 2; model++) {
            unsigned char K[16];
            for (int i = 0; i < 16; i++)
                K[i] = (raw[O + i] ^ K16[(O + i - 12) & 15]) ^ PNG16[i];
            // verify with IDAT at +37..+40 and fixed bytes at +24..+28
            int ok = 0; char det[64] = {0};
            for (int j = 0; j < 5; j++) {
                int pos = 24 + j;
                int ph = model == 0 ? (pos & 15) : (int)((O + pos - 12) & 15);
                unsigned char v = (raw[O + pos] ^ K16[(O + pos - 12) & 15]) ^ K[ph];
                sprintf(det + strlen(det), "%02x ", v);
                if (j == 0 && v == 8) ok++;
                if (j == 1 && (v == 0 || v == 2 || v == 3 || v == 4 || v == 6)) ok++;
                if (j >= 2 && v == 0) ok++;
            }
            strcat(det, "| ");
            for (int j = 0; j < 4; j++) {
                int pos = 37 + j;
                int ph = model == 0 ? (pos & 15) : (int)((O + pos - 12) & 15);
                unsigned char v = (raw[O + pos] ^ K16[(O + pos - 12) & 15]) ^ K[ph];
                sprintf(det + strlen(det), "%c", (v >= 32 && v < 127) ? v : '.');
                if (v == "IDAT"[j]) ok++;
            }
            printf("  model=%s ok=%d/9  %s\n", model ? "grid" : "reset", ok, det);
        }
    }
    return 0;
}
