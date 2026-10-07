// valcheck.c — count extracted files by extension and validate magic bytes.
// usage: valcheck <dir>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static const struct { const char* ext; const char* magic; int n; } V[] = {
    { ".wav", "RIFF", 4 },
    { ".ogg", "OggS", 4 },
    { ".jpg", "\xff\xd8\xff", 3 },
    { ".png", "\x89PNG", 4 },
    { ".vce", "VCMF", 4 },
    { ".xml", "<?xml", 5 },
    { ".ini", "[", 1 },
    { 0, 0, 0 },
};
static const struct { const char* ext; int cmap_max; } TG = { ".tga", 1 };

static int counts[32][2]; // [ext idx][ok,bad]
static int findext(const char* e) {
    for (int i = 0; V[i].ext; i++) if (!stricmp(e, V[i].ext)) return i;
    if (!stricmp(e, ".tga")) return 31;
    return -1;
}

static void scan(const char* dir) {
    char pat[MAX_PATH];
    _snprintf(pat, MAX_PATH, "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        char fp[MAX_PATH];
        _snprintf(fp, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { scan(fp); continue; }
        const char* e = strrchr(fd.cFileName, '.');
        if (!e) continue;
        int idx = findext(e);
        if (idx < 0) continue;
        FILE* f = fopen(fp, "rb");
        if (!f) continue;
        unsigned char b[8] = {0};
        fread(b, 1, 8, f); fclose(f);
        int ok = 0;
        if (idx == 31) {
            ok = (b[1] <= 1 && (b[2] == 2 || b[2] == 10 || b[2] == 3 || b[2] == 9 || b[2] == 11));
        } else {
            ok = !memcmp(b, V[idx].magic, V[idx].n);
        }
        counts[idx][ok ? 0 : 1]++;
        if (!ok) printf("BAD %s\n", fp);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

int main(int argc, char** argv) {
    scan(argv[1]);
    for (int i = 0; V[i].ext; i++)
        if (counts[i][0] || counts[i][1])
            printf("%-5s ok=%-6d bad=%-6d\n", V[i].ext, counts[i][0], counts[i][1]);
    if (counts[31][0] || counts[31][1]) printf(".tga  ok=%-6d bad=%-6d\n", counts[31][0], counts[31][1]);
    return 0;
}
