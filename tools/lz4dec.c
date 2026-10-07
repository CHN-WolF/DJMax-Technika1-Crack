// lz4dec.c — LZ4 block decompressor (test): decode <in> from offset, compare with <live>
// usage: lz4dec <decfile> <livefile> <dec_off>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long lz4dec(const unsigned char* in, long insz, unsigned char* out, long outcap) {
    long i = 0, o = 0;
    while (i < insz && o < outcap) {
        unsigned char t = in[i++];
        int litlen = t >> 4;
        if (litlen == 15) { unsigned char e; do { e = in[i++]; litlen += e; } while (e == 255 && i < insz); }
        while (litlen-- > 0 && i < insz && o < outcap) out[o++] = in[i++];
        if (i + 2 > insz) break;
        int off = in[i] | (in[i+1] << 8); i += 2;
        if (off == 0) break;
        int mlen = (t & 15) + 4;
        if ((t & 15) == 15) { unsigned char e; do { e = in[i++]; mlen += e; } while (e == 255 && i < insz); }
        while (mlen-- > 0 && o < outcap) { out[o] = out[o - off]; o++; }
    }
    return o;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    FILE* g = fopen(argv[2], "rb");
    if (!f || !g) return 1;
    fseek(f, 0, SEEK_END); long la = ftell(f); fseek(f, 0, SEEK_SET);
    fseek(g, 0, SEEK_END); long lb = ftell(g); fseek(g, 0, SEEK_SET);
    unsigned char* A = malloc(la); fread(A, 1, la, f); fclose(f);
    unsigned char* B = malloc(lb); fread(B, 1, lb, g); fclose(g);
    long off = atol(argv[3]);
    unsigned char* out = malloc(lb * 4);
    long n = lz4dec(A + off, la - off, out, lb * 4);
    printf("lz4 decoded %ld bytes\n", n);
    long diffs = 0;
    for (long i = 0; i < n && i < lb; i++) if (out[i] != B[i]) { if (++diffs <= 5) printf("diff@%ld: %02x vs %02x\n", i, out[i], B[i]); }
    printf("diffs=%ld (of %ld)\n", diffs, n < lb ? n : lb);
    FILE* o = fopen("/tmp/lz4out.bin", "wb"); fwrite(out, 1, n, o); fclose(o);
    return 0;
}
