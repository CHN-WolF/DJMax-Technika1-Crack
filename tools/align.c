// align.c — assume B == A with insertions: walk both; on mismatch, skip ahead
// in A by 1..32 looking for resync (5 consecutive matches); report skips.
// usage: align <A> <B> [startA startB len]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    FILE* a = fopen(argv[1], "rb");
    FILE* b = fopen(argv[2], "rb");
    if (!a || !b) return 1;
    fseek(a, 0, SEEK_END); long la = ftell(a); fseek(a, 0, SEEK_SET);
    fseek(b, 0, SEEK_END); long lb = ftell(b); fseek(b, 0, SEEK_SET);
    unsigned char* A = malloc(la); fread(A, 1, la, a); fclose(a);
    unsigned char* B = malloc(lb); fread(B, 1, lb, b); fclose(b);
    long i = argc > 3 ? atol(argv[3]) : 0;
    long j = argc > 4 ? atol(argv[4]) : 0;
    long end = argc > 5 ? i + atol(argv[5]) : la;
    long skips = 0, matched = 0;
    long firstprint = 0;
    while (i < la && j < lb && i < end) {
        if (A[i] == B[j]) { i++; j++; matched++; continue; }
        long best = -1;
        for (long k = 1; k <= 32 && i + k + 8 < la; k++)
            if (!memcmp(A + i + k, B + j, 8)) { best = k; break; }
        if (best < 0) {
            // try skipping in B instead
            for (long k = 1; k <= 32 && j + k + 8 < lb; k++)
                if (!memcmp(A + i, B + j + k, 8)) { best = -2 - k; break; }
        }
        if (best > 0) {
            if (skips < 40) printf("skipA@%ld: %ld bytes:", i, best);
            if (skips < 40) { for (long k = 0; k < best; k++) printf(" %02x", A[i + k]); printf("\n"); }
            i += best; skips++;
        } else if (best < -1) {
            long k = -best - 2;
            if (skips < 40) printf("skipB@%ld: %ld bytes:", i, k);
            if (skips < 40) { for (long q = 0; q < k; q++) printf(" %02x", B[j + q]); printf("\n"); }
            j += k; skips++;
        } else {
            if (firstprint < 40) printf("subst A@%ld=%02x B@%ld=%02x\n", i, A[i], j, B[j]);
            firstprint++;
            i++; j++;
        }
    }
    printf("matched=%ld skips=%ld subst=%ld endA=%ld endB=%ld\n", matched, skips, firstprint, i, j);
    return 0;
}
