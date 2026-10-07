// bxor.c — xor two files byte-wise from a given offset, print hex+ascii
// usage: bxor <f1> <f2> <offset> <len>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    FILE* a = fopen(argv[1], "rb");
    FILE* b = fopen(argv[2], "rb");
    long off = atol(argv[3]);
    long len = atol(argv[4]);
    fseek(a, off, SEEK_SET); fseek(b, off, SEEK_SET);
    for (long i = 0; i < len; i += 16) {
        printf("%08lx: ", off + i);
        unsigned char line[16];
        for (int j = 0; j < 16 && i + j < len; j++) {
            int ca = fgetc(a), cb = fgetc(b);
            int x = (ca ^ cb) & 0xff;
            line[j] = x;
            printf("%02x ", x);
        }
        printf(" |");
        for (int j = 0; j < 16 && i + j < len; j++)
            printf("%c", (line[j] >= 32 && line[j] < 127) ? line[j] : '.');
        printf("|\n");
    }
    fclose(a); fclose(b);
    return 0;
}
