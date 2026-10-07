// ptffbrute.c — brute-force PTFF decryption candidates, score by byte skew.
// tries: AES-128-ECB key="Shit!DontTouchMe" at offsets 0..80;
//        AES-128-CBClike (xor prev cipherblock / IV=header) same offsets;
//        raw XOR16 (tpk outer key) as sanity.
// usage: ptffbrute <file>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
static u8 sbox[256], isbox[256];
static u8 gmul(u8 a, u8 b){u8 r=0;for(;b;b>>=1){if(b&1)r^=a;a=(a<<1)^((a&0x80)?0x1b:0);}return r;}
static u8 ginv(u8 a){if(!a)return 0;u8 r=1;for(int i=0;i<254;i++)r=gmul(r,a);return r;}
static void init_tables(void){for(int i=0;i<256;i++){u8 x=ginv((u8)i);u8 s=x^((x<<1)|(x>>7))^((x<<2)|(x>>6))^((x<<3)|(x>>5))^((x<<4)|(x>>4))^0x63;sbox[i]=s;isbox[s]=(u8)i;}}
static u8 rk[176];
static void key_exp(const u8* key){static const u8 rcon[10]={1,2,4,8,16,32,64,128,27,54};memcpy(rk,key,16);for(int i=16;i<176;i+=4){u8 t[4]={rk[i-4],rk[i-3],rk[i-2],rk[i-1]};if((i&15)==0){u8 x=t[0];t[0]=t[1];t[1]=t[2];t[2]=t[3];t[3]=x;for(int j=0;j<4;j++)t[j]=sbox[t[j]];t[0]^=rcon[(i>>4)-1];}for(int j=0;j<4;j++)rk[i+j]=rk[i-16+j]^t[j];}}
static void shift_rows(u8*s){for(int row=1;row<4;row++){u8 t[4];for(int c=0;c<4;c++)t[c]=s[((c-row)&3)*4+row];for(int c=0;c<4;c++)s[c*4+row]=t[c];}}
static void mix_columns(u8*s){for(int c=0;c<4;c++){u8*p=s+c*4;u8 a0=p[0],a1=p[1],a2=p[2],a3=p[3];p[0]=gmul(a0,14)^gmul(a1,11)^gmul(a2,13)^gmul(a3,9);p[1]=gmul(a0,9)^gmul(a1,14)^gmul(a2,11)^gmul(a3,13);p[2]=gmul(a0,13)^gmul(a1,9)^gmul(a2,14)^gmul(a3,11);p[3]=gmul(a0,11)^gmul(a1,13)^gmul(a2,9)^gmul(a3,14);}}
static void aes_dec(const u8 in[16],u8 out[16]){u8 s[16];memcpy(s,in,16);for(int i=0;i<16;i++)s[i]^=rk[160+i];for(int r=9;r>=1;r--){shift_rows(s);for(int i=0;i<16;i++)s[i]=isbox[s[i]];for(int i=0;i<16;i++)s[i]^=rk[r*16+i];mix_columns(s);}shift_rows(s);for(int i=0;i<16;i++)s[i]=isbox[s[i]];for(int i=0;i<16;i++)s[i]^=rk[i];memcpy(out,s,16);}
static const u8 KEY[16]={'S','h','i','t','!','D','o','n','t','T','o','u','c','h','M','e'};

static long skew(const u8* b, long n) {
    long h[256] = {0}, mx = 0;
    for (long i = 0; i < n; i++) h[b[i]]++;
    for (int i = 0; i < 256; i++) if (h[i] > mx) mx = h[i];
    return mx;
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    u8* b = malloc(sz); fread(b, 1, sz, f); fclose(f);
    init_tables(); key_exp(KEY);
    long n = sz > 8192 ? 8192 : sz;
    u8 w[8192], prev[16];
    printf("baseline skew( raw ) = %ld\n", skew(b, n));
    // extra keys: LZO-wrapper passphrase candidate found in exe strings
    const u8 KEY2[16] = { 'v','o','a','l','f','f','l','d','n','j','r','t','m','a','k','s' };
    key_exp(KEY2);
    for (long off = 0; off <= 192; off += 8) {
        if (off + 16 > n) break;
        long m = n - off;
        for (long i = 0; i + 16 <= m; i += 16) aes_dec(b + off + i, w + i);
        printf("ECBvoalf off=%3ld skew=%ld first: %02x %02x %02x %02x\n", off, skew(w, m & ~15L), w[0], w[1], w[2], w[3]);
        // CBC with IV = header[8..24)
        memcpy(prev, b + 8, 16);
        for (long i = 0; i + 16 <= m; i += 16) {
            u8 t[16]; memcpy(t, b + off + i, 16);
            aes_dec(t, w + i);
            for (int j = 0; j < 16; j++) w[i + j] ^= prev[j];
            memcpy(prev, t, 16);
        }
        printf("CBChdr off=%3ld skew=%ld first: %02x %02x %02x %02x\n", off, skew(w, m & ~15L), w[0], w[1], w[2], w[3]);
    }
    key_exp(KEY);
    long n0 = n;  // original flows below use tpk key
    for (long off = 0; off <= 80; off += 16) {
        if (off + 16 > n) break;
        // ECB
        long m = n - off;
        for (long i = 0; i + 16 <= m; i += 16) aes_dec(b + off + i, w + i);
        printf("ECB off=%3ld skew=%ld  first: %02x %02x %02x %02x %c%c%c%c\n", off, skew(w, m & ~15L),
               w[0], w[1], w[2], w[3],
               w[0]>=32&&w[0]<127?w[0]:'.', w[1]>=32&&w[1]<127?w[1]:'.', w[2]>=32&&w[2]<127?w[2]:'.', w[3]>=32&&w[3]<127?w[3]:'.');
        // CBC with IV=0
        memset(prev, 0, 16);
        for (long i = 0; i + 16 <= m; i += 16) {
            u8 t[16]; memcpy(t, b + off + i, 16);
            aes_dec(t, w + i);
            for (int j = 0; j < 16; j++) w[i + j] ^= prev[j];
            memcpy(prev, t, 16);
        }
        printf("CBC0 off=%3ld skew=%ld first: %02x %02x %02x %02x\n", off, skew(w, m & ~15L), w[0], w[1], w[2], w[3]);
    }
    return 0;
}
