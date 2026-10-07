// fakeserver.c — minimal TCP placeholder listener on 127.0.0.1:4723
// replacement for fakeserver.py (no Python on this machine).
// Accepts every connection, logs received bytes, never replies.
#include <winsock2.h>
#include <stdio.h>

int main(void) {
    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w)) { printf("WSAStartup fail\n"); return 1; }
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons(4723);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr*)&a, sizeof(a)) || listen(s, 8)) {
        printf("bind/listen fail (port busy?)\n"); return 1;
    }
    printf("fake server on 127.0.0.1:4723\n");
    fflush(stdout);
    for (;;) {
        SOCKET c = accept(s, 0, 0);
        if (c == INVALID_SOCKET) continue;
        printf("connect\n");
        fflush(stdout);
        // one connection at a time is fine: the game only opens one
        char buf[4096];
        for (;;) {
            int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            printf("recv %d:", n);
            for (int i = 0; i < n && i < 32; i++) printf(" %02x", buf[i] & 0xff);
            printf("\n");
            fflush(stdout);
        }
        printf("closed\n");
        fflush(stdout);
        closesocket(c);
    }
    return 0;
}
