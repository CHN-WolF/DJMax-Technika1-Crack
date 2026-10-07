// hashmap.c — test if p02 numeric names are hashes of virtual resource paths.
// usage: hashmap <p02dir>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static unsigned int crc32(const char* s) {
    unsigned int c = 0xFFFFFFFF;
    for (; *s; s++) { c ^= (unsigned char)*s; for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : c >> 1; }
    return c ^ 0xFFFFFFFF;
}
static unsigned int crc32r(const char* s) { // no final xor
    unsigned int c = 0xFFFFFFFF;
    for (; *s; s++) { c ^= (unsigned char)*s; for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320 : c >> 1; }
    return c;
}
static unsigned int djb2(const char* s) { unsigned int h = 5381; while (*s) h = h * 33 ^ (unsigned char)*s++; return h; }
static unsigned int djb2i(const char* s) { unsigned int h = 5381; while (*s) { char c = *s++; if (c >= 'A' && c <= 'Z') c += 32; h = h * 33 ^ c; } return h; }
static unsigned int fnv1a(const char* s) { unsigned int h = 2166136261u; while (*s) { h ^= (unsigned char)*s++; h *= 16777619; } return h; }
static unsigned int fnv1(const char* s) { unsigned int h = 2166136261u; while (*s) { h *= 16777619; h ^= (unsigned char)*s++; } return h; }
static unsigned int jenkins(const char* s) {
    unsigned int h = 0;
    while (*s) { h += (unsigned char)*s++; h += h << 10; h ^= h >> 6; }
    h += h << 3; h ^= h >> 11; h += h << 15;
    return h;
}

static int p02[512]; static int np02;
static int hits;
static void tryh(const char* alg, unsigned int h, const char* s) {
    int v = (int)h;
    for (int i = 0; i < np02; i++) if (p02[i] == v) { printf("HIT %s(\"%s\") = %d\n", alg, s, v); hits++; return; }
}
static void test(const char* s) {
    tryh("crc32", crc32(s), s); tryh("crc32r", crc32r(s), s);
    tryh("djb2", djb2(s), s); tryh("djb2i", djb2i(s), s);
    tryh("fnv1a", fnv1a(s), s); tryh("fnv1", fnv1(s), s); tryh("jenkins", jenkins(s), s);
    // case variants
    char up[256], lo[256];
    int i;
    for (i = 0; s[i]; i++) { up[i] = (s[i] >= 'a' && s[i] <= 'z') ? s[i] - 32 : s[i]; lo[i] = (s[i] >= 'A' && s[i] <= 'Z') ? s[i] + 32 : s[i]; }
    up[i] = lo[i] = 0;
    tryh("crc32(up)", crc32(up), up); tryh("djb2(up)", djb2(up), up);
    // backslash variant
    char bs[256];
    for (i = 0; s[i]; i++) bs[i] = s[i] == '/' ? '\\' : s[i];
    bs[i] = 0;
    if (strcmp(bs, s)) { tryh("crc32(bs)", crc32(bs), bs); tryh("djb2(bs)", djb2(bs), bs); }
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

    const char* demos[] = { "firstkiss_demo", "future_demo", "howtoplay_demo", "lite_howtoplay", "firstkiss", "cheoum", "@cheoum" };
    const char* fmts[] = { "%s", "Pattern/%s.pt", "pattern/%s.pt", "Pattern/%s", "pattern/%s",
                           "Pattern\\%s.pt", "song/pattern/%s.tpk", "song/pattern/%s", "Song/Pattern/%s",
                           "p02/%s", "%s.pt", "%s.tpk" };
    for (int d = 0; d < 7; d++)
        for (int f = 0; f < 12; f++) {
            char s[256];
            _snprintf(s, 255, fmts[f], demos[d]);
            test(s);
        }
    printf("done, hits=%d\n", hits);
    return 0;
}
