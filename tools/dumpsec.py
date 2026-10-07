import ctypes, sys
from ctypes import wintypes as w
pid, addr, size, out = int(sys.argv[1]), int(sys.argv[2],16), int(sys.argv[3],16), sys.argv[4]
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
res = bytearray()
off = 0
while off < size:
    n = min(0x100000, size-off)
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, addr+off, buf, n, ctypes.byref(got)):
        res += buf.raw[:got.value]
        if got.value < n: res += b"\x00"*(n-got.value)
    else:
        res += b"\x00"*n
    off += n
open(out,'wb').write(bytes(res))
print("dumped", len(res), "->", out)
