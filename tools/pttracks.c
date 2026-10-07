// pttracks.c - per-file, per-track note counts (TSV): pttracks <id> [id...]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

int main(int argc, char **argv){
    for (int i = 1; i < argc; i++) {
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s.pt", argv[i]);
        FILE *f = fopen(path, "rb"); if (!f) { printf("%s LOADFAIL\n", argv[i]); continue; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); printf("%s BADFILE\n", argv[i]); continue; }
        unsigned insCnt = rd16(b+0x16);
        long pos = 0x18 + (long)insCnt * 68;
        int ti = 0;
        while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
            char tname[65] = {0}; memcpy(tname, b+pos+6, 0x40); tname[64] = 0;
            for (char *p = tname; *p; p++) if (*p == ' ' || *p == '\t') *p = '_';
            long blockSize = (long)rd32(b+pos+0x4A);
            long cnt = blockSize / 0x10, ep = pos + 0x50, k, notes = 0;
            for (k = 0; k < cnt; k++, ep += 0x10) if (b[ep+4] == 1) notes++;
            printf("%s\tT%02d\t%s\t%ld\n", argv[i], ti, tname[0] ? tname : "-", notes);
            pos = ep; ti++;
        }
        free(b);
    }
    return 0;
}
