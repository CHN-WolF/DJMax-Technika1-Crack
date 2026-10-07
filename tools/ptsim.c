// ptsim.c - note-stream overlap of PTFF charts (merged from the old ptsim/ptsim2/ptsim_all).
//   ptsim                      batch: all-pairs overlap within each consecutive-id group of extracted_pt
//   ptsim <idA> <idB> [...]    specific file pairs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

typedef struct { int tick, ins, dur; } Ev;
static int cmpev(const void *a, const void *b){
    const Ev *x = a, *y = b;
    if (x->tick != y->tick) return x->tick - y->tick;
    if (x->ins != y->ins) return x->ins - y->ins;
    return x->dur - y->dur;
}
static int load(const char *path, Ev **out){
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
    if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); return -1; }
    unsigned insCnt = rd16(b+0x16);
    long pos = 0x18 + (long)insCnt * 68;
    Ev *evs = malloc(sz/16*sizeof(Ev)+16); int n = 0;
    while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
        long blockSize = (long)rd32(b+pos+0x4A), cnt = blockSize/0x10, ep = pos + 0x50, k;
        for (k = 0; k < cnt; k++, ep += 0x10) {
            if (b[ep+4] != 1) continue;
            const unsigned char *ex = b+ep+5;
            evs[n].tick = (int)rd32(b+ep); evs[n].ins = (int)rd16(ex+3); evs[n].dur = (int)rd16(ex+8); n++;
        }
        pos = ep;
    }
    free(b); qsort(evs, n, sizeof(Ev), cmpev); *out = evs; return n;
}
static double overlap(const Ev *a, int na, const Ev *b, int nb){
    int x = 0, y = 0, inter = 0;
    while (x < na && y < nb) {
        int c = cmpev(&a[x], &b[y]);
        if (c < 0) x++; else if (c > 0) y++; else { inter++; x++; y++; }
    }
    int mx = na > nb ? na : nb;
    return mx ? (double)inter/mx : 0.0;
}
static int cmpstr(const void *a, const void *b){ return strcmp(*(char*const*)a, *(char*const*)b); }

int main(int argc, char **argv){
    if (argc > 1) { // specific pairs
        for (int i = 1; i + 1 < argc; i += 2) {
            char pa[512], pb[512];
            snprintf(pa, sizeof pa, "extracted_pt/%s.pt", argv[i]);
            snprintf(pb, sizeof pb, "extracted_pt/%s.pt", argv[i+1]);
            Ev *a, *b; int na = load(pa, &a), nb = load(pb, &b);
            if (na < 0 || nb < 0) { printf("%s %s LOADFAIL\n", argv[i], argv[i+1]); continue; }
            printf("%s %s %.4f (%d vs %d)\n", argv[i], argv[i+1], overlap(a, na, b, nb), na, nb);
            free(a); free(b);
        }
        return 0;
    }
    // batch mode: all pairs within each consecutive-id group (distance <= 8)
    DIR *d = opendir("extracted_pt");
    if (!d) return 1;
    struct dirent *e; char *names[512]; int nn = 0;
    while ((e = readdir(d)) && nn < 512) if (strstr(e->d_name, ".pt")) names[nn++] = _strdup(e->d_name);
    closedir(d); qsort(names, nn, sizeof(char*), cmpstr);
    static Ev *evs[512]; static int n_[512]; static long long idv[512];
    int m = 0;
    for (int i = 0; i < nn; i++) {
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s", names[i]);
        int r = load(path, &evs[m]); if (r < 0) continue;
        n_[m] = r; idv[m] = _strtoi64(names[i], 0, 10); m++;
    }
    for (int i = 0; i < m; i++) for (int j = i + 1; j < m; j++) {
        long long dlt = idv[j] - idv[i];
        if (dlt > 8 || dlt < -8) continue;
        printf("%lld\t%lld\t%.4f\n", idv[i], idv[j], overlap(evs[i], n_[i], evs[j], n_[j]));
    }
    return 0;
}
