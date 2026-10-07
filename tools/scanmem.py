import ctypes, sys
from ctypes import wintypes as w
pid, addr, size, pathex = int(sys.argv[1]), int(sys.argv[2],16), int(sys.argv[3],16), sys.argv[4]
pat = bytes.fromhex(pathex)
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
CH = 0x100000
hits = []
off = 0
while off < size:
    n = min(CH, size-off)
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    k32.ReadProcessMemory(h, addr+off, buf, n, ctypes.byref(got))
    d = buf.raw[:got.value]
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0: break
        hits.append(addr+off+i)
        i += 1
        if len(hits) > 30: break
    off += n
print(f"{len(hits)} refs to {pathex}:")
for x in hits[:30]: print(hex(x))
k32.CloseHandle(h)
