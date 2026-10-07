// lzinfer.c — given compressed (dec) and decompressed (live) streams, infer the
// LZ token grammar by recursive explanation: at each input position, try
// literal (byte equal) or a match token of 1-4 bytes whose (dist,len) encodes
// a back-reference in the output. Prints each token's raw bytes + dist/len.
// usage: lzinfer <dec> <live> [maxtokens]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *A, *B;
static long la, lb;

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    FILE* g = fopen(argv[2], "rb");
    if (!f || !g) return 1;
    fseek(f, 0, SEEK_END); la = ftell(f); fseek(f, 0, SEEK_SET);
    fseek(g, 0, SEEK_END); lb = ftell(g); fseek(g, 0, SEEK_SET);
    A = malloc(la); fread(A, 1, la, f); fclose(f);
    B = malloc(lb); fread(B, 1, lb, g); fclose(g);
    int maxt = argc > 3 ? atoi(argv[3]) : 25;

    long i = 0, j = 0;
    int t = 0;
    while (i < la && j < lb && t < maxt) {
        if (A[i] == B[j]) { i++; j++; continue; }
        // find longest backref in B[..j) matching B[j..]
        long bd = 0, bl = 0;
        for (long d = 1; d <= j; d++) {
            long l = 0;
            while (j + l < lb && l < 64 && B[j + l] == B[j - d + l]) l++;
            if (l > bl) { bl = l; bd = d; }
        }
        printf("tok@%ld->out%ld: dec bytes", i, j);
        for (int k = 0; k < 8 && i + k < la; k++) printf(" %02x", A[i + k]);
        printf(" | want len=%ld dist=%ld text=", bl, bd);
        for (int k = 0; k < bl && k < 12; k++) printf("%c", B[j + k] >= 32 && B[j + k] < 127 ? B[j + k] : '.');
        printf("\n");
        t++;
        // advance: find token length by scanning A forward 1..16 for a 5-byte resync
        long jend = j + bl;
        long sync = -1;
        for (long di = 1; di <= 16 && i + di + 5 < la; di++)
            if (jend + 5 < lb && !memcmp(A + i + di, B + jend, 5)) { sync = di; break; }
        if (sync < 0) { printf("  no resync\n"); break; }
        printf("  token_len=%ld\n", sync);
        i += sync; j = jend;
    }
    printf("end: in=%ld/%ld out=%ld/%ld\n", i, la, j, lb);
    return 0;
}
