// ptstats.c - per-byte histograms of PTFF v1 event payloads over extracted_pt/*.pt
// Goal: figure out what the bytes DJMax-Editor treats as padding actually contain.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

// per-position value histogram for the 11 extra bytes
static long notePos[11][256];
static long volPos[11][256];
static long tempoPos[11][256];
static long beatPos[11][256];

static void rep(const char *tag, long pos[11][256], long total){
    printf("== %s (total %ld)\n", tag, total);
    for (int i = 0; i < 11; i++) {
        long distinct = 0, top = 0, topv = -1, zero = pos[i][0];
        for (int v = 0; v < 256; v++) {
            if (pos[i][v]) distinct++;
            if (pos[i][v] > top) { top = pos[i][v]; topv = v; }
        }
        printf("  [%2d] distinct=%4ld zero=%6ld top=0x%02lx(%ld)", i, distinct, zero, topv, top);
        if (distinct <= 8 && distinct > 0) {
            printf("  vals:");
            for (int v = 0; v < 256; v++) if (pos[i][v]) printf(" %02x:%ld", v, pos[i][v]);
        }
        printf("\n");
    }
}

int main(void){
    DIR *d = opendir("extracted_pt");
    if (!d) { puts("no extracted_pt"); return 1; }
    struct dirent *e;
    long notes=0, vols=0, tempos=0, beats=0;
    float tmin=1e30f, tmax=-1e30f;
    long beats_u16[8] = {0}; // first few beat values
    int nbv = 0;
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, ".pt")) continue;
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s", e->d_name);
        FILE *f = fopen(path, "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); continue; }
        unsigned insCnt = rd16(b+0x16);
        long pos = 0x18 + (long)insCnt * 68;
        while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
            long blockSize = (long)rd32(b+pos+0x4A);
            long cnt = blockSize / 0x10, ep = pos + 0x50, k;
            for (k = 0; k < cnt; k++, ep += 0x10) {
                int id = b[ep+4];
                const unsigned char *ex = b+ep+5;
                long (*tab)[256] = NULL;
                if (id == 1) { tab = notePos; notes++; }
                else if (id == 2) { tab = volPos; vols++; }
                else if (id == 3) { tab = tempoPos; tempos++;
                    float tv; memcpy(&tv, ex+3, 4);
                    if (tv == tv) { if (tv < tmin) tmin = tv; if (tv > tmax) tmax = tv; }
                }
                else if (id == 4) { tab = beatPos; beats++;
                    if (nbv < 8) beats_u16[nbv++] = rd16(ex+3);
                }
                if (tab) for (int i = 0; i < 11; i++) tab[i][ex[i]]++;
            }
            pos = ep;
        }
        free(b);
    }
    closedir(d);
    rep("NOTE", notePos, notes);
    rep("VOLUME", volPos, vols);
    rep("TEMPO", tempoPos, tempos);
    printf("   tempo float range: %f .. %f\n", tmin, tmax);
    rep("BEAT", beatPos, beats);
    printf("   first beat u16 vals:"); for (int i = 0; i < nbv; i++) printf(" %ld", beats_u16[i]); printf("\n");
    return 0;
}
