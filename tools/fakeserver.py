import socket, threading, sys
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 4723))
srv.listen(8)
print("fake server on 127.0.0.1:4723", flush=True)
def handle(c, a):
    print("connect from", a, flush=True)
    c.settimeout(2)
    try:
        while True:
            try:
                d = c.recv(4096)
                if not d: break
                print("recv", len(d), d[:64].hex(), flush=True)
            except socket.timeout:
                pass
    except OSError:
        pass
    print("closed", a, flush=True)
    c.close()
while True:
    c, a = srv.accept()
    threading.Thread(target=handle, args=(c, a), daemon=True).start()
