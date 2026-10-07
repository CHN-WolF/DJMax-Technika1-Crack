// entrydump.c — walk tpk.dec entries, print ext + bytes at +128..+160
// usage: entrydump <file.dec> [maxentries]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int name_ok(const unsigned char* p) {
    if (p[0] < 32 || p[0] > 126) return 0;
    int n = 0;
    for (int i = 0; i < 128; i++) {
        if (!p[i]) break;
        if (p[i] < 32 || p[i] > 126) return 0;
        n++;
    }
    return n >= 4 && n < 120;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* d = malloc(len);
    fread(d, 1, len, f); fclose(f);
    int maxn = argc > 2 ? atoi(argv[2]) : 20;

    long pos = 0;
    for (int n = 0; n < maxn && pos + 150 < len; n++) {
        if (!name_ok(d + pos)) { pos++; continue; }
        char name[128]; memcpy(name, d + pos, 127); name[127] = 0;
        unsigned f1 = *(unsigned*)(d + pos + 132);
        const char* ext = strrchr(name, '.');
        printf("%-36s f1=%-8u +144: %02x %02x | +146: %02x %02x %02x %02x %02x %02x\n",
               ext ? ext : name, f1, d[pos + 144], d[pos + 145],
               d[pos + 146], d[pos + 147], d[pos + 148], d[pos + 149], d[pos + 150], d[pos + 151]);
        pos += 146 + (long)f1 - 2;
    }
    return 0;
}
