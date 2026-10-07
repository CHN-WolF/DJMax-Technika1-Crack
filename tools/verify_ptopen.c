// verify_ptopen.c - replicate PTOpenFile.cs (DJMax-Editor) parsing over
// extracted_pt/*.pt and report desyncs plus the real-world values of every
// field the editor treats as padding (data its Save path would zero out).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){return p[0]|p[1]<<8|p[2]<<16|(unsigned)p[3]<<24;}

typedef struct { const char *name; long total, nonzero; unsigned char ex[16]; int exlen; } Pad;
static void pad_rec(Pad *pd, const unsigned char *b, int len){
    int i, nz = 0;
    for (i = 0; i < len; i++) if (b[i]) nz = 1;
    pd->total++;
    if (nz) {
        pd->nonzero++;
        if (pd->nonzero == 1) { memcpy(pd->ex, b, len < 16 ? len : 16); pd->exlen = len < 16 ? len : 16; }
    }
}
static void pad_rep(Pad *pd){
    printf("%-14s total=%ld nonzero=%ld", pd->name, pd->total, pd->nonzero);
    if (pd->nonzero) {
        int i; printf("  first: ");
        for (i = 0; i < pd->exlen; i++) printf("%02x", pd->ex[i]);
    }
    printf("\n");
}

int main(void){
    DIR *d = opendir("extracted_pt");
    if (!d) { puts("no extracted_pt"); return 1; }
    long files = 0, ok = 0, tracks = 0, notes = 0, orphan = 0, endmm = 0, emptyname = 0;
    long idcnt[256] = {0};
    long ver[256] = {0};
    Pad insPad = {"ins u1,u2",0,0,{0},0}, ezPad = {"eztr+2",0,0,{0},0}, trkTail = {"track tail",0,0,{0},0};
    Pad notePad0 = {"note[0:3]",0,0,{0},0}, notePadA = {"note[0xA]",0,0,{0},0};
    Pad volPad = {"vol pad",0,0,{0},0}, tempoPad = {"tempo pad",0,0,{0},0}, beatPad = {"beat pad",0,0,{0},0};
    long velmin=1<<30,velmax=0,panmin=1<<30,panmax=0,attmin=1<<30,attmax=0,durmin=1L<<40,durmax=0;
    long trail[65] = {0};
    struct dirent *e;
    char failmsg[256] = {0}; char failfile[300] = {0};
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, ".pt")) continue;
        char path[512]; snprintf(path, sizeof path, "extracted_pt/%s", e->d_name);
        FILE *f = fopen(path, "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        files++;
        if (sz < 0x18 || memcmp(b, "PTFF", 4)) { snprintf(failmsg,255,"bad magic"); snprintf(failfile,299,"%s",path); free(b); continue; }
        ver[b[4]]++;
        if (b[4] != 1) { snprintf(failmsg,255,"version %d", b[4]); snprintf(failfile,299,"%s",path); free(b); continue; }
        unsigned insCnt = rd16(b+0x16);
        long pos = 0x18;
        unsigned short *insnos = malloc((insCnt+1)*2); unsigned nins = 0;
        long i;
        int failed = 0;
        for (i = 0; i < insCnt; i++) {
            if (pos + 68 > sz) { failed=1; snprintf(failmsg,255,"ins overrun"); break; }
            insnos[nins++] = rd16(b+pos);
            pad_rec(&insPad, b+pos+2, 2);
            pos += 68;
        }
        if (failed) { snprintf(failfile,299,"%s",path); free(b); free(insnos); continue; }
        while (sz - pos >= 4) {
            if (memcmp(b+pos, "EZTR", 4)) { failed=1; snprintf(failmsg,255,"EZTR desync at %#lx", pos); break; }
            pad_rec(&ezPad, b+pos+4, 2);
            int nameEmpty = 1;
            for (i = 0; i < 0x40; i++) if (b[pos+6+i]) { nameEmpty = 0; break; }
            if (nameEmpty) emptyname++;
            long endTick = (long)rd32(b+pos+0x46);
            long blockSize = (long)rd32(b+pos+0x4A);
            pad_rec(&trkTail, b+pos+0x4E, 2);
            if (blockSize % 0x10) { failed=1; snprintf(failmsg,255,"blockSize %ld %% 16", blockSize); break; }
            long cnt = blockSize / 0x10, ep = pos + 0x50, maxtick = -1, k;
            if (ep + blockSize > sz) { failed=1; snprintf(failmsg,255,"block overrun"); break; }
            for (k = 0; k < cnt; k++, ep += 0x10) {
                long tick = (long)rd32(b+ep);
                int id = b[ep+4];
                const unsigned char *ex = b+ep+5;
                idcnt[id & 0xff]++;
                if (id == 1) {
                    unsigned char pad7[7];
                    notes++;
                    pad_rec(&notePad0, ex, 3);
                    pad_rec(&notePadA, ex+0xA, 1);
                    memcpy(pad7, ex+7, 1); /* silence -Wmaybe-uninitialized on pad7 */
                    unsigned ino = rd16(ex+3);
                    unsigned vel = ex[5], pan = ex[6], att = ex[7], dur = rd16(ex+8);
                    if ((long)vel<velmin)velmin=vel; if ((long)vel>velmax)velmax=vel;
                    if ((long)pan<panmin)panmin=pan; if ((long)pan>panmax)panmax=pan;
                    if ((long)att<attmin)attmin=att; if ((long)att>attmax)attmax=att;
                    if ((long)dur<durmin)durmin=dur; if ((long)dur>durmax)durmax=dur;
                    size_t j; int found = 0;
                    for (j = 0; j < nins; j++) if (insnos[j] == ino) { found = 1; break; }
                    if (!found) orphan++;
                } else if (id == 2) {
                    unsigned char p[10]; memcpy(p, ex, 3); memcpy(p+3, ex+4, 7);
                    pad_rec(&volPad, p, 10);
                } else if (id == 3) {
                    unsigned char p[7]; memcpy(p, ex, 3); memcpy(p+3, ex+7, 4);
                    pad_rec(&tempoPad, p, 7);
                } else if (id == 4) {
                    unsigned char p[8]; memcpy(p, ex, 3); memcpy(p+3, ex+5, 5);
                    pad_rec(&beatPad, p, 8);
                }
                if (tick > maxtick) maxtick = tick;
            }
            if (failed) break;
            if (cnt && maxtick != endTick) endmm++;
            tracks++;
            pos = ep;
        }
        if (failed) { snprintf(failfile,299,"%s",path); free(b); free(insnos); continue; }
        long t = sz - pos; if (t >= 0 && t < 65) trail[t]++;
        ok++;
        free(b); free(insnos);
    }
    closedir(d);
    printf("files ok: %ld/%ld  tracks: %ld  notes: %ld\n", ok, files, tracks, notes);
    printf("versions:"); { int i; for (i=0;i<256;i++) if (ver[i]) printf(" v%d=%ld", i, ver[i]); } printf("\n");
    printf("event ids:"); { int i; for (i=0;i<256;i++) if (idcnt[i]) printf(" %d=%ld", i, idcnt[i]); } printf("\n");
    printf("trailing bytes:"); { int i; for (i=0;i<65;i++) if (trail[i]) printf(" %dB=%ld", i, trail[i]); } printf("\n");
    pad_rep(&insPad); pad_rep(&ezPad); pad_rep(&trkTail);
    pad_rep(&notePad0); pad_rep(&notePadA);
    pad_rep(&volPad); pad_rep(&tempoPad); pad_rep(&beatPad);
    printf("vel [%ld..%ld] pan [%ld..%ld] attr [%ld..%ld] dur [%ld..%ld]\n", velmin,velmax,panmin,panmax,attmin,attmax,durmin,durmax);
    printf("endTick!=maxtick blocks: %ld   orphan insNo: %ld   empty tracknames: %ld\n", endmm, orphan, emptyname);
    if (failfile[0]) printf("last FAIL: %s (%s)\n", failfile, failmsg);
    return 0;
}
