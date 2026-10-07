// lzdiff.c — analyze dec(compressed) vs live(decompressed) streams:
// walk live; feed from dec; literals match; on mismatch, search back in live
// for the continuation, report (dist,len) and the dec token bytes.
// usage: lzdiff <dec> <live> [skip]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    FILE* g = fopen(argv[2], "rb");
    if (!f || !g) return 1;
    fseek(f, 0, SEEK_END); long la = ftell(f); fseek(f, 0, SEEK_SET);
    fseek(g, 0, SEEK_END); long lb = ftell(g); fseek(g, 0, SEEK_SET);
    unsigned char* A = malloc(la); fread(A, 1, la, f); fclose(f);
    unsigned char* B = malloc(lb); fread(B, 1, lb, g); fclose(g);
    long skip = argc > 3 ? atol(argv[3]) : 0;
    long i = 0, j = 0;
    long matched = 0, tokens = 0;
    while (i < la && j < lb) {
        if (A[i] == B[j]) { i++; j++; matched++; continue; }
        // mismatch: search back in B[..j) for the longest continuation match
        long bestd = 0, bestl = 0;
        for (long d = 1; d <= j && d < 66000; d++) {
            long l = 0;
            while (j + l < lb && l < 64 && B[j + l] == B[j - d + l]) l++;
            if (l > bestl) { bestl = l; bestd = d; }
        }
        // print dec token bytes (up to 8) and what live shows
        printf("div@%ld(live %ld): A=", i, j);
        for (int k = 0; k < 8 && i + k < la; k++) printf("%02x ", A[i + k]);
        printf(" | live wants: ");
        for (int k = 0; k < 16 && j + k < lb; k++) printf("%c", B[j + k] >= 32 && B[j + k] < 127 ? B[j + k] : '.');
        printf(" | best backref dist=%ld len=%ld (copied: ", bestd, bestl);
        for (int k = 0; k < bestl && k < 16; k++) printf("%c", B[j - bestd + k] >= 32 && B[j - bestd + k] < 127 ? B[j - bestd + k] : '.');
        printf(")\n");
        tokens++;
        if (tokens > 40) break;
        // resync: find next point where A[i..]==B[j..]
        long ni = i + 1, nj = j + 1;
        int synced = 0;
        for (long dj = 0; dj < 64 && !synced; dj++)
            for (long di = 0; di < 64; di++)
                if (i + di + 6 < la && j + dj + 6 < lb && !memcmp(A + i + di, B + j + dj, 6)) {
                    i += di; j += dj; synced = 1; break;
                }
        if (!synced) { printf("LOST\n"); break; }
    }
    printf("matched=%ld tokens=%ld endA=%ld endB=%ld\n", matched, tokens, i, j);
    return 0;
}
