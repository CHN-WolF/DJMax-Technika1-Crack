// ptlanes.c - per file: note sums by track class (T00/Dummy/1P/2P/Lights/BG/other) -> TSV
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}
static int cmpstr(const void *a, const void *b){ return strcmp(*(char*const*)a, *(char*const*)b); }

int main(void){
    DIR *d = opendir("extracted_pt");
    if (!d) return 1;
    struct dirent *e;
    char *names[512]; int nn = 0;
    while ((e = readdir(d)) && nn < 512) if (strstr(e->d_name, ".pt")) names[nn++] = _strdup(e->d_name);
    closedir(d);
    qsort(names, nn, sizeof(char*), cmpstr);
    printf("file\tt00\tdummy\tp1\tp2\tlights\tbg\tother\n");
    for (int fi = 0; fi < nn; fi++) {
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s", names[fi]);
        FILE *f = fopen(path, "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); continue; }
        unsigned insCnt = rd16(b+0x16);
        long pos = 0x18 + (long)insCnt * 68;
        long t00=0, dum=0, p1=0, p2=0, li=0, bg=0, oth=0;
        int ti = 0;
        while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
            char tname[65] = {0}; memcpy(tname, b+pos+6, 0x40); tname[64] = 0;
            long blockSize = (long)rd32(b+pos+0x4A);
            long cnt = blockSize / 0x10, ep = pos + 0x50, k, notes = 0;
            for (k = 0; k < cnt; k++, ep += 0x10) if (b[ep+4] == 1) notes++;
            if (!strncmp(tname, "(1P)", 4)) p1 += notes;
            else if (!strncmp(tname, "(2P)", 4)) p2 += notes;
            else if (!strncmp(tname, "Dummy", 5)) dum += notes;
            else if (!strncmp(tname, "Lights", 6)) li += notes;
            else if (!strncmp(tname, "BG_", 3)) bg += notes;
            else if (ti == 0) t00 += notes;
            else oth += notes;
            pos = ep; ti++;
        }
        printf("%s\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\t%ld\n", names[fi], t00, dum, p1, p2, li, bg, oth);
        free(b);
    }
    return 0;
}
