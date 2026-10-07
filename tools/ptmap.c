// ptmap.c - per pt file dump: id, notes, note-stream hash, insCnt, all instrument names (TSV)
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
        long pos = 0x18 + (long)insCnt * 68;
        long notes = 0;
        unsigned long long h = 1469598103934665603ULL; // FNV-1a over note events
        while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
            long blockSize = (long)rd32(b+pos+0x4A);
            long cnt = blockSize / 0x10, ep = pos + 0x50, k;
            for (k = 0; k < cnt; k++, ep += 0x10) {
                if (b[ep+4] != 1) continue;
                notes++;
                // hash tick + payload (ex[3..10], skip random salt ex[0:3])
                const unsigned char *p = b + ep;
                for (int i = 0; i < 4; i++) { h ^= p[i]; h *= 1099511628211ULL; }
                for (int i = 8; i < 15; i++) { h ^= p[i]; h *= 1099511628211ULL; }
            }
            pos = ep;
        }
        printf("%s\t%ld\t%016llx\t%u", names[fi], notes, h, insCnt);
        for (unsigned i = 0; i < insCnt; i++) {
            char nm[65] = {0}; memcpy(nm, b + 0x18 + i*68 + 4, 0x40); nm[64] = 0;
            printf("\t%s", nm);
        }
        printf("\n");
        free(b);
    }
    return 0;
}
