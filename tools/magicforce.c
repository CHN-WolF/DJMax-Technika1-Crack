// magicforce.c — assume second layer = 16-byte repeating XOR key, phase reset
// at entry start. For each candidate entry-start offset O and known 16-byte
// plaintext prefix P (png magic etc.), derive K2 = dec[O..O+15]^P, then test:
// decrypt dec[O..O+64) with K2 and score "looks like file header".
// usage: magicforce <file.dec>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char PNG[16] = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52};
static const unsigned char DDS8[8] = {0x44,0x44,0x53,0x20,0x7C,0x00,0x00,0x00};
static const unsigned char JPG8[8] = {0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46};
static const unsigned char OGG4[4] = {0x4F,0x67,0x67,0x53};
static const unsigned char RIFF4[4] = {0x52,0x49,0x46,0x46};
static const unsigned char ZIP4[4] = {0x50,0x4B,0x03,0x04};

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* b = malloc(sz);
    fread(b, 1, sz, f); fclose(f);

    for (long O = 0; O + 80 < sz && O < 4000000; O += 16) {
        // skip zero pads
        int allz = 1;
        for (int i = 0; i < 16; i++) if (b[O + i]) { allz = 0; break; }
        if (allz) continue;

        // candidate 1: PNG (16 known bytes)
        unsigned char K[16];
        for (int i = 0; i < 16; i++) K[i] = b[O + i] ^ PNG[i];
        // verify: next chunk after IHDR data: bytes 16.. = width/height (any),
        // byte 24..28 = bitdepth/colortype ... just check bytes 16-23 nonzero-ish
        // and that decrypting 64B produces plausible IHDR structure
        unsigned char w[64];
        for (int i = 0; i < 64; i++) w[i] = b[O + i] ^ K[(i) & 15];
        long width = (w[16] << 24) | (w[17] << 16) | (w[18] << 8) | w[19];
        long height = (w[20] << 24) | (w[21] << 16) | (w[22] << 8) | w[23];
        if (width > 0 && width < 8192 && height > 0 && height < 8192 &&
            (w[24] == 8) && w[25] <= 6) {
            printf("PNG? O=%ld K=", O);
            for (int i = 0; i < 16; i++) printf("%02x", K[i]);
            printf(" w=%ld h=%ld depth=%d ctype=%d\n", width, height, w[24], w[25]);
        }
        // candidate 2: DDS (8 known bytes; remaining 8 of block free)
        // K2 from first 8 bytes only; report if rest looks plausible (all-zero pad after 124B header is common)
        unsigned char K8[16];
        for (int i = 0; i < 8; i++) K8[i] = b[O + i] ^ DDS8[i];
        for (int i = 8; i < 16; i++) K8[i] = 0;
        printf(""); // placeholder minimal output for DDS: check height/width at 12/16
        long hh = 0, ww = 0;
        // DDS: magic(4) size(4) flags(4) height(4) width(4)
        // with 16B key unknown bytes 8..15 we can't fully check; skip detailed DDS scoring
        (void)hh; (void)ww;
    }
    printf("scan done\n");
    return 0;
}
