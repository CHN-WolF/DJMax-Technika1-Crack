// ptsong.c - for each extracted_pt/*.pt: print filename, first instrument (song tag),
// instrument count, note count, and any non-empty track names.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

static int cmpstr(const void *a, const void *b){ return strcmp(*(char*const*)a, *(char*const*)b); }

int main(void){
    DIR *d = opendir("extracted_pt");
    if (!d) { puts("no extracted_pt"); return 1; }
    struct dirent *e;
    char *names[512]; int nn = 0;
    while ((e = readdir(d)) && nn < 512) if (strstr(e->d_name, ".pt")) names[nn++] = _strdup(e->d_name);
    closedir(d);
    qsort(names, nn, sizeof(char*), cmpstr);
    for (int fi = 0; fi < nn; fi++) {
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s", names[fi]);
        FILE *f = fopen(path, "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); continue; }
        unsigned insCnt = rd16(b+0x16);
        // first instrument name = song tag
        char song[65] = {0};
        if (insCnt) { memcpy(song, b+0x18+4, 0x40); song[64] = 0; }
        long pos = 0x18 + (long)insCnt * 68;
        long notes = 0; char tracknames[512] = {0}; int tn = 0;
        while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
            char tname[65] = {0}; memcpy(tname, b+pos+6, 0x40); tname[64] = 0;
            if (tname[0] && tn < 3) {
                if (tn) strncat(tracknames, " | ", sizeof(tracknames)-strlen(tracknames)-1);
                strncat(tracknames, tname, sizeof(tracknames)-strlen(tracknames)-1);
                tn++;
            }
            long blockSize = (long)rd32(b+pos+0x4A);
            long cnt = blockSize / 0x10, ep = pos + 0x50, k;
            for (k = 0; k < cnt; k++, ep += 0x10) if (b[ep+4] == 1) notes++;
            pos = ep;
        }
        printf("%-14s song=%-28s ins=%3u notes=%5ld trk=[%s]\n",
               names[fi], song, insCnt, notes, tracknames);
        free(b);
    }
    return 0;
}
