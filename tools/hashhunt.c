// hashhunt.c - hypothesis: p02 filename = HASH(song_id) + difficulty_index.
// Extract song ids from pt contents (first instrument wav name, plus all "0-xxx.wav"),
// try crc32/djb2/fnv1a/java31 on several string variants, and report any hash that
// lands within +-8 of an actual p02 number.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>

static unsigned rd16(const unsigned char*p){return p[0]|p[1]<<8;}
static unsigned rd32(const unsigned char*p){(void)p; return 0;}

static unsigned crc32(const char* s){unsigned c=0xFFFFFFFF;for(;*s;s++){c^=(unsigned char)*s;for(int k=0;k<8;k++)c=(c&1)?(c>>1)^0xEDB88320:c>>1;}return c^0xFFFFFFFF;}
static unsigned crc32n(const char* s,int lower){unsigned c=0xFFFFFFFF;for(;*s;s++){unsigned char ch=(unsigned char)*s;if(lower)ch=tolower(ch);c^=ch;for(int k=0;k<8;k++)c=(c&1)?(c>>1)^0xEDB88320:c>>1;}return c^0xFFFFFFFF;}
static unsigned djb2(const char* s){unsigned h=5381;while(*s)h=h*33^(unsigned char)*s++;return h;}
static unsigned fnv1a(const char* s){unsigned h=2166136261u;while(*s){h^=(unsigned char)*s++;h*=16777619;}return h;}
static unsigned java31(const char* s){unsigned h=0;while(*s)h=h*31+(unsigned char)*s++;return h;}

static int p02[512], np02;
static void near(const char* alg, const char* s, unsigned h){
    int v = (int)h;
    for (int i = 0; i < np02; i++) {
        int d = p02[i] - v;
        if (d >= -8 && d <= 8)
            printf("NEAR %-6s %-28s = %11d   p02=%11d delta=%+d\n", alg, s, v, p02[i], d);
    }
}
static void tryall(const char* s){
    char buf[160];
    near("crc32", s, crc32(s)); near("djb2", s, djb2(s));
    near("fnv1a", s, fnv1a(s)); near("java31", s, java31(s));
    snprintf(buf, sizeof buf, "%s.pt", s);
    near("crc32", buf, crc32(buf)); near("djb2", buf, djb2(buf));
    near("fnv1a", buf, fnv1a(buf)); near("java31", buf, java31(buf));
    snprintf(buf, sizeof buf, "@%s", s);
    near("crc32", buf, crc32(buf)); near("djb2", buf, djb2(buf));
    near("fnv1a", buf, fnv1a(buf)); near("java31", buf, java31(buf));
}

int main(int argc, char **argv){
    const char *p02dir = argc > 1 ? argv[1] : "p02";
    const char *ptdir  = argc > 2 ? argv[2] : "extracted_pt";
    DIR *d = opendir(p02dir);
    if (!d) { puts("no p02 dir"); return 1; }
    struct dirent *e;
    while ((e = readdir(d))) { if (e->d_name[0] == '.' || !strcmp(e->d_name,"..")) continue;
        int v = atoi(e->d_name); if (v) p02[np02++] = v; }
    closedir(d);
    printf("%d p02 ids\n", np02);

    d = opendir(ptdir);
    if (!d) { puts("no pt dir"); return 1; }
    char seen[128][65]; int nseen = 0;
    while ((e = readdir(d))) {
        if (!strstr(e->d_name, ".pt")) continue;
        char path[512]; snprintf(path, sizeof path, "%s/%s", ptdir, e->d_name);
        FILE *f = fopen(path, "rb"); if (!f) continue;
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        unsigned char *b = malloc(sz); fread(b, 1, sz, f); fclose(f);
        if (sz < 0x18 || memcmp(b, "PTFF", 4) || b[4] != 1) { free(b); continue; }
        unsigned insCnt = rd16(b+0x16);
        // scan all instrument names; keep unique song-ish ones (strip .wav, leading 0-)
        for (unsigned i = 0; i < insCnt; i++) {
            char nm[65] = {0}; memcpy(nm, b + 0x18 + i*68 + 4, 0x40); nm[64] = 0;
            char *dot = strrchr(nm, '.'); if (dot) *dot = 0;
            char *s = nm; if (s[0]=='0' && s[1]=='-') s += 2;
            if (!*s) continue;
            int known = 0;
            for (int j = 0; j < nseen; j++) if (!strcmp(seen[j], s)) { known = 1; break; }
            if (known || nseen >= 128) continue;
            strcpy(seen[nseen++], s);
            tryall(s);
        }
        free(b);
    }
    closedir(d);
    printf("%d distinct instrument ids tried\n", nseen);
    return 0;
}
