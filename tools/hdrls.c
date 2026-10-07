// hdrls.c — dump all entry headers of a .dec (walk by f1; show f2/rsv/prefix)
// usage: hdrls <file.dec>
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
    long pos = 0;
    int n = 0;
    while (pos + 150 < len) {
        if (!name_ok(d + pos)) { pos++; continue; }
        char name[128]; memcpy(name, d + pos, 127); name[127] = 0;
        unsigned hash = *(unsigned*)(d + pos + 128);
        unsigned f1 = *(unsigned*)(d + pos + 132);
        unsigned f2 = *(unsigned*)(d + pos + 136);
        unsigned rsv = *(unsigned*)(d + pos + 140);
        printf("%-36s f1=%-8u f2=%-10u rsv=%-8u pfx=%02x%02x data=%02x%02x%02x%02x\n",
               name, f1, f2, rsv, d[pos+144], d[pos+145], d[pos+146], d[pos+147], d[pos+148], d[pos+149]);
        pos += 144 + f1;
        n++;
    }
    printf("entries=%d\n", n);
    return 0;
}
