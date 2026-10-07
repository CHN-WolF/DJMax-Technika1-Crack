// kvar.c — try simple variants of the 16B key on dec data: rotations, reverse,
// inverted, add/sub deltas; score by "skewness" (max byte frequency).
// usage: kvar <file.dec> <off>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char K16[16] = { 0x72,0x0d,0xe1,0xe4,0xb8,0x47,0x76,0x4a,
                                       0x79,0x7f,0x37,0x1b,0x57,0x9d,0x31,0xdb };

static long score(const unsigned char* b, long n) {
    long h[256] = {0};
    for (long i = 0; i < n; i++) h[b[i]]++;
    long mx = 0;
    for (int i = 0; i < 256; i++) if (h[i] > mx) mx = h[i];
    return mx;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    long off = atol(argv[2]);
    fseek(f, off, SEEK_SET);
    long n = 65536;
    unsigned char* b = malloc(n);
    n = fread(b, 1, n, f); fclose(f);
    unsigned char* w = malloc(n);

    printf("baseline (no xor): maxfreq=%ld\n", score(b, n));
    for (int rot = 0; rot < 16; rot++) {
        for (long i = 0; i < n; i++) w[i] = b[i] ^ K16[(i + rot) & 15];
        long s = score(w, n);
        printf("rot%2d: maxfreq=%ld  first: %02x %02x %02x %02x %c%c%c%c\n", rot, s,
               w[0], w[1], w[2], w[3],
               (w[0]>=32&&w[0]<127)?w[0]:'.', (w[1]>=32&&w[1]<127)?w[1]:'.',
               (w[2]>=32&&w[2]<127)?w[2]:'.', (w[3]>=32&&w[3]<127)?w[3]:'.');
    }
    for (int d = 1; d < 256; d += 1) {
        // K2 = K16 + d (per byte)
        for (long i = 0; i < n; i++) w[i] = b[i] ^ (unsigned char)(K16[i & 15] + d);
        long s = score(w, n);
        if (s > n / 20) printf("add %02x: maxfreq=%ld\n", d, s);
    }
    return 0;
}
