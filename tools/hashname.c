// hashname2.c — check whether p02 numeric filenames are hashes of song ids.
// usage: hashname2 <p02dir> <pattern_dir>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned int crc32(const char* s) {
    unsigned int c = 0xFFFFFFFF;
    for (; *s; s++) { c ^= (unsigned char)*s; for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : c >> 1; }
    return c ^ 0xFFFFFFFF;
}
static unsigned int djb2(const char* s) { unsigned int h = 5381; while (*s) h = h * 33 ^ (unsigned char)*s++; return h; }
static unsigned int fnv1a(const char* s) { unsigned int h = 2166136261u; while (*s) { h ^= (unsigned char)*s++; h *= 16777619; } return h; }

static int p02[512]; static int np02;
static void tryh(const char* alg, unsigned int h, const char* s) {
    int v = (int)h;
    for (int i = 0; i < np02; i++) if (p02[i] == v) { printf("HIT %s(\"%s\") = %d\n", alg, s, v); return; }
}

int main(int argc, char** argv) {
    char pat[MAX_PATH];
    _snprintf(pat, MAX_PATH, "%s\\*", argv[1]);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    while (h != INVALID_HANDLE_VALUE) {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) p02[np02++] = atoi(fd.cFileName);
        if (!FindNextFileA(h, &fd)) { FindClose(h); break; }
    }
    printf("%d p02 files\n", np02);

    const char* suf[] = { "", "0", "1", "2", "3", "_0", "_1", "_2", "_3", "1_0", "2_0", "3_0",
                          "_nm", "_hd", "_mx", "nm", "hd", "mx", "NM", "HD", "MX", ".pt", ".PT" };
    _snprintf(pat, MAX_PATH, "%s\\*.tpk", argv[2]);
    h = FindFirstFileA(pat, &fd);
    while (h != INVALID_HANDLE_VALUE) {
        char base[128];
        _snprintf(base, 127, "%s", fd.cFileName);
        char* dot = strrchr(base, '.');
        if (dot) *dot = 0;
        char nb[128]; _snprintf(nb, 127, "%s", base[0] == '@' ? base + 1 : base);
        for (int f = 0; f < 2; f++) {
            const char* core = f ? nb : base;
            for (int s = 0; s < 22; s++) {
                char cand[160]; _snprintf(cand, 159, "%s%s", core, suf[s]);
                tryh("crc32", crc32(cand), cand);
                tryh("djb2", djb2(cand), cand);
                tryh("fnv1a", fnv1a(cand), cand);
                char cup[160];
                int i;
                for (i = 0; cand[i]; i++) cup[i] = (cand[i] >= 'a' && cand[i] <= 'z') ? cand[i] - 32 : cand[i];
                cup[i] = 0;
                tryh("crc32U", crc32(cup), cup);
            }
        }
        if (!FindNextFileA(h, &fd)) { FindClose(h); break; }
    }
    printf("done\n");
    return 0;
}
