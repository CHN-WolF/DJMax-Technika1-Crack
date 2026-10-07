// ptcorr.c - what does event byte [10] (0x77) correlate with? (tick vs headerEndTick, duration, attr)
// and dump a few raw VOLUME events to inspect bytes [4..9].
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

int main(int argc, char **argv){
    DIR *d = opendir("extracted_pt");
    if (!d) { puts("no extracted_pt"); return 1; }
    struct dirent *e;
    // correlation counters
    long n77_dur6=0, n77_durX=0, n00_dur6=0, n00_durX=0;
    long n77_pre=0, n77_post=0, n00_pre=0, n00_post=0;
    long v77=0, v00=0, t77=0, t00=0;
    long attr77[256] = {0}; long attr00[256] = {0};
    int vdumped = 0;
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, ".pt")) continue;
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s", e->d_name);
        FILE *f = fopen(path, "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); continue; }
        unsigned insCnt = rd16(b+0x16);
        unsigned hdrEnd = rd32(b+0x0E);
        long pos = 0x18 + (long)insCnt * 68;
        while (sz - pos >= 4 && !memcmp(b+pos, "EZTR", 4)) {
            long blockSize = (long)rd32(b+pos+0x4A);
            long cnt = blockSize / 0x10, ep = pos + 0x50, k;
            for (k = 0; k < cnt; k++, ep += 0x10) {
                long tick = (long)rd32(b+ep);
                int id = b[ep+4];
                const unsigned char *ex = b+ep+5;
                int m77 = ex[10] == 0x77;
                if (id == 1) {
                    unsigned dur = rd16(ex+8);
                    if (m77) { if (dur > 6) n77_durX++; else n77_dur6++; attr77[ex[7]]++; }
                    else     { if (dur > 6) n00_durX++; else n00_dur6++; attr00[ex[7]]++; }
                    if (tick < (long)hdrEnd) { if (m77) n77_pre++; else n00_pre++; }
                    else                     { if (m77) n77_post++; else n00_post++; }
                } else if (id == 2) {
                    if (m77) v77++; else v00++;
                    if (vdumped < 12 && argc > 1) {
                        printf("VOL tick=%6ld raw:", tick);
                        for (int i = 0; i < 11; i++) printf(" %02x", ex[i]);
                        printf("   volByte=%d\n", ex[3]);
                        vdumped++;
                    }
                } else if (id == 3) {
                    if (m77) t77++; else t00++;
                }
            }
            pos = ep;
        }
        free(b);
    }
    closedir(d);
    printf("NOTE 0x77 x duration: dur<=6:%ld dur>6:%ld | 0x00: dur<=6:%ld dur>6:%ld\n",
           n77_dur6, n77_durX, n00_dur6, n00_durX);
    printf("NOTE 0x77 x tick vs headerEnd: pre:%ld post:%ld | 0x00: pre:%ld post:%ld\n",
           n77_pre, n77_post, n00_pre, n00_post);
    printf("VOL 77:%ld 00:%ld  TEMPO 77:%ld 00:%ld\n", v77, v00, t77, t00);
    printf("attr with 0x77:"); for (int i=0;i<256;i++) if (attr77[i]) printf(" %02x:%ld", i, attr77[i]); printf("\n");
    printf("attr with 0x00:"); { int shown=0; for (int i=0;i<256;i++) if (attr00[i] && shown<12) { printf(" %02x:%ld", i, attr00[i]); shown++; } } printf("\n");
    return 0;
}
