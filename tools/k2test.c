// k2test.c — hypothesis: dec[0..15] or dec[16..31] is a second-layer 16-byte
// key; try XORing data region with each and print snippets.
// usage: k2test <file.dec>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);
    for (int k = 0; k < 2; k++) {
        unsigned char* key = b + k * 16;
        printf("=== key candidate dec[%d..%d]: ", k * 16, k * 16 + 15);
        for (int i = 0; i < 16; i++) printf("%02x", key[i]);
        printf("\n");
        for (long base = 0x80; base <= 0x800; base += 0x80) {
            printf("  @%lx: ", base);
            for (int i = 0; i < 32; i++) {
                unsigned char v = b[base + i] ^ key[(base + i) & 15];
                printf("%c", (v >= 32 && v < 127) ? v : '.');
            }
            printf("  | ");
            for (int i = 0; i < 16; i++) printf("%02x ", b[base + i] ^ key[(base + i) & 15]);
            printf("\n");
        }
    }
    return 0;
}
