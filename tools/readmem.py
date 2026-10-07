import ctypes, sys, math
from ctypes import wintypes as w
from collections import Counter

pid, addr, size = int(sys.argv[1]), int(sys.argv[2],16), int(sys.argv[3],16)
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
buf = ctypes.create_string_buffer(size)
got = ctypes.c_size_t(0)
ok = k32.ReadProcessMemory(h, addr, buf, size, ctypes.byref(got))
d = buf.raw[:got.value]
print("read", got.value, "bytes")
print(d[:64].hex())
c=Counter(d); n=len(d)
if n: print("entropy:", round(-sum((v/n)*math.log2(v/n) for v in c.values()),2))
k32.CloseHandle(h)
