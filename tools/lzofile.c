// lzofile.c — LZO1X-decompress a file blob to an output file.
// usage: lzofile <in> <out>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;

static long lzo_dec(const u8* in, long in_len, u8* out, long outcap) {
    const u8* ip = in;
    const u8* const ip_end = in + in_len;
    u8* op = out;
    u8* const op_end = out + outcap;
    long t, state = 0, next;
    const u8* m_pos;

#define NEED_IP(x) if (ip_end - ip < (x)) return -1
#define NEED_OP(x) if (op_end - op < (x)) return -2
#define TEST_LB(mp) if ((mp) < out) return -3

    if (in_len < 3) return -1;
    if (in_len >= 5 && *ip == 17) ip += 2;
    if (*ip > 17) {
        t = *ip++ - 17;
        if (t < 4) { next = t; goto match_next; }
        goto copy_literal_run;
    }
    for (;;) {
        t = *ip++;
        if (t < 16) {
            if (state == 0) {
                if (t == 0) {
                    long offset = 0;
                    while (*ip == 0) { ip++; NEED_IP(1); offset += 255; }
                    t += offset + 15 + *ip++;
                }
                t += 3;
copy_literal_run:
                NEED_OP(t); NEED_IP(t + 3);
                do { *op++ = *ip++; } while (--t > 0);
                state = 4;
                continue;
            } else if (state != 4) {
                next = t & 3;
                m_pos = op - 1;
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;
                TEST_LB(m_pos);
                NEED_OP(2);
                op[0] = m_pos[0]; op[1] = m_pos[1];
                op += 2;
                goto match_next;
            } else {
                next = t & 3;
                m_pos = op - (1 + 0x0800);
                m_pos -= t >> 2;
                m_pos -= *ip++ << 2;
                t = 3;
            }
        } else if (t >= 64) {
            next = t & 3;
            m_pos = op - 1;
            m_pos -= (t >> 2) & 7;
            m_pos -= *ip++ << 3;
            t = (t >> 5) + 1;
        } else if (t >= 32) {
            t = (t & 31) + 2;
            if (t == 2) {
                long offset = 0;
                while (*ip == 0) { ip++; NEED_IP(1); offset += 255; }
                t += offset + 31 + *ip++;
                NEED_IP(2);
            }
            m_pos = op - 1;
            next = ip[0] | (ip[1] << 8);
            ip += 2;
            m_pos -= next >> 2;
            next &= 3;
        } else {
            NEED_IP(2);
            next = ip[0] | (ip[1] << 8);
            m_pos = op;
            m_pos -= (t & 8) << 11;
            t = (t & 7) + 2;
            if (t == 2) {
                long offset = 0;
                while (*ip == 0) { ip++; NEED_IP(1); offset += 255; }
                t += offset + 7 + *ip++;
                NEED_IP(2);
                next = ip[0] | (ip[1] << 8);
            }
            ip += 2;
            m_pos -= next >> 2;
            next &= 3;
            if (m_pos == op) {
                if (t != 3) return -4;
                return op - out;
            }
            m_pos -= 0x4000;
        }
        TEST_LB(m_pos);
        {
            u8* oe = op + t;
            NEED_OP(t);
            do { *op++ = *m_pos++; } while (op < oe);
        }
match_next:
        state = next;
        t = next;
        NEED_IP(t + 3); NEED_OP(t);
        while (t-- > 0) *op++ = *ip++;
    }
}

int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long la = ftell(f); fseek(f, 0, SEEK_SET);
    u8* A = malloc(la); fread(A, 1, la, f); fclose(f);
    long cap = la * 8 + 65536;
    u8* out = malloc(cap);
    long n = lzo_dec(A, la, out, cap);
    printf("decoded %ld\n", n);
    if (n > 0) {
        FILE* o = fopen(argv[2], "wb"); fwrite(out, 1, n, o); fclose(o);
    }
    return 0;
}
