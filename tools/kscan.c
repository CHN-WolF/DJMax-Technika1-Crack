// kscan.c — find zero-padding regions in a .tpk: positions where the same
// 16-byte ciphertext block repeats >= 3 consecutive times (block grid phase 12).
// usage: kscan <file>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);
    long runs = 0;
    for (long i = 12; i + 16 * 3 <= sz; i += 16) {
        if (!memcmp(b + i, b + i + 16, 16) && !memcmp(b + i, b + i + 32, 16)) {
            long j = i + 16;
            while (j + 16 <= sz && !memcmp(b + i, b + j, 16)) j += 16;
            printf("pad off=%8ld len=%5ld key=", i, j - i);
            for (int k = 0; k < 16; k++) printf("%02x", b[i + k]);
            printf("\n");
            runs++;
            i = j - 16;
        }
    }
    printf("total pads: %ld\n", runs);
    return 0;
}
