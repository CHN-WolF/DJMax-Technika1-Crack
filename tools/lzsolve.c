// lzsolve.c — try LZSS variants on dec stream, compare with live output.
// Variants: flag bit polarity (1=lit / 0=lit), flag bit order (MSB/LSB first),
// match token u16 LE: layout A = off:12|len:4 (len+3), layout B = len:4|off:12.
// usage: lzsolve <dec> <live> <startoff>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char A[1 << 20], B[1 << 20], OUT[1 << 21];

static long lzss(const unsigned char* in, long insz, unsigned char* out, long outcap,
                 int flagIsLit, int msbFirst, int layout, int lenBias) {
    long i = 0, o = 0;
    unsigned int flags = 0; int nbits = 0;
    while (i < insz && o < outcap) {
        if (nbits == 0) { flags = in[i++]; nbits = 8; }
        int bit;
        if (msbFirst) { bit = (flags >> 7) & 1; flags = (flags << 1) & 0xff; }
        else { bit = flags & 1; flags >>= 1; }
        nbits--;
        int isLit = flagIsLit ? bit : !bit;
        if (isLit) {
            if (i >= insz) break;
            out[o++] = in[i++];
        } else {
            if (i + 2 > insz) break;
            unsigned int t = in[i] | (in[i + 1] << 8); i += 2;
            int off, len;
            if (layout == 0) { off = t >> 4; len = (t & 15) + lenBias; }
            else { len = (t >> 12) + lenBias; off = t & 0xFFF; }
            if (off == 0) off = 1;
            while (len-- > 0 && o < outcap) { out[o] = out[o - off]; o++; }
        }
    }
    return o;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    FILE* g = fopen(argv[2], "rb");
    if (!f || !g) return 1;
    long la = fread(A, 1, sizeof A, f); fclose(f);
    long lb = fread(B, 1, sizeof B, g); fclose(g);
    long start = argc > 3 ? atol(argv[3]) : 0;
    for (int fl = 0; fl < 2; fl++)
        for (int msb = 0; msb < 2; msb++)
            for (int lay = 0; lay < 2; lay++)
                for (int bias = 2; bias <= 4; bias++) {
                    long n = lzss(A + start, la - start, OUT, lb * 2, fl, msb, lay, bias);
                    long diffs = 0;
                    for (long i = 0; i < n && i < lb; i++) if (OUT[i] != B[i]) diffs++;
                    printf("flagLit=%d msb=%d lay=%d bias=%d -> out=%ld diffs=%ld %s\n",
                           fl, msb, lay, bias, n, diffs, diffs == 0 ? "*** MATCH ***" : (diffs < n / 10 ? "close" : ""));
                }
    return 0;
}
