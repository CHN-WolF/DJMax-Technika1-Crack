// pttrackdiff.c - per-track note-event overlap between two pt files: pttrackdiff <idA> <idB>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

typedef struct { int tick, ins, dur; } Ev;
typedef struct { char name[65]; Ev *evs; int n, cap; } Track;
static int cmpev(const void *a, const void *b){
    const Ev *x = a, *y = b;
    if (x->tick != y->tick) return x->tick - y->tick;
    if (x->ins != y->ins) return x->ins - y->ins;
    return x->dur - y->dur;
}
static int load(const char *id, Track **out){
    char path[512]; snprintf(path, sizeof path, "extracted_pt/%s.pt", id);
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
    if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); return -1; }
    unsigned insCnt = rd16(b+0x16);
    long pos = 0x18 + (long)insCnt * 68;
    Track *ts = calloc(128, sizeof(Track)); int nt = 0;
    while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4) && nt < 128) {
        memcpy(ts[nt].name, b+pos+6, 0x40); ts[nt].name[64] = 0;
        long blockSize = (long)rd32(b+pos+0x4A);
        long cnt = blockSize / 0x10, ep = pos + 0x50, k;
        ts[nt].evs = malloc((cnt+1)*sizeof(Ev));
        for (k = 0; k < cnt; k++, ep += 0x10) {
            if (b[ep+4] != 1) continue;
            const unsigned char *ex = b+ep+5;
            Ev *e = &ts[nt].evs[ts[nt].n++];
            e->tick = (int)rd32(b+ep); e->ins = (int)rd16(ex+3); e->dur = (int)rd16(ex+8);
        }
        qsort(ts[nt].evs, ts[nt].n, sizeof(Ev), cmpev);
        nt++; pos = ep;
    }
    free(b); *out = ts; return nt;
}
int main(int argc, char **argv){
    if (argc < 3) return 1;
    Track *A, *B; int na = load(argv[1], &A), nb = load(argv[2], &B);
    if (na < 0 || nb < 0) { puts("loadfail"); return 1; }
    printf("%s (%d tracks) vs %s (%d tracks)\n", argv[1], na, argv[2], nb);
    int n = na < nb ? na : nb;
    for (int i = 0; i < n; i++) {
        if (!A[i].n && !B[i].n) continue;
        int x = 0, y = 0, inter = 0;
        while (x < A[i].n && y < B[i].n) {
            int c = cmpev(&A[i].evs[x], &B[i].evs[y]);
            if (c < 0) x++; else if (c > 0) y++; else { inter++; x++; y++; }
        }
        int mx = A[i].n > B[i].n ? A[i].n : B[i].n;
        printf("T%02d %-14s %5d vs %-5d overlap %5.1f%%%s\n", i, A[i].name[0]?A[i].name:"-",
               A[i].n, B[i].n, mx ? 100.0*inter/mx : 100.0, 100.0*inter/(mx?mx:1) > 95 ? "" : "  <-- DIFF");
    }
    return 0;
}
