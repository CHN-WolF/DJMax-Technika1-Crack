import ctypes, sys
from ctypes import wintypes as w
pid, pathex = int(sys.argv[1]), sys.argv[2]
pat = bytes.fromhex(pathex)
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong),("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD),("__a", w.DWORD),("RegionSize", ctypes.c_ulonglong),
                ("State", w.DWORD),("Protect", w.DWORD),("Type", w.DWORD),("__b", w.DWORD)]
mbi = MBI(); addr = 0; hits = {}
while addr < 0x7fff0000:
    if not k32.VirtualQueryEx(h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)): break
    base, sz = mbi.BaseAddress, mbi.RegionSize
    if mbi.State == 0x1000 and mbi.Protect & 0xf0:  # any executable
        off = 0
        while off < sz:
            n = min(0x100000, sz-off)
            buf = ctypes.create_string_buffer(n)
            got = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h, base+off, buf, n, ctypes.byref(got)):
                d = buf.raw[:got.value]
                i = 0
                while True:
                    i = d.find(pat, i)
                    if i < 0: break
                    hits.setdefault(base, 0)
                    hits[base] += 1
                    i += 1
            off += n
    addr = base + sz
for b, c in sorted(hits.items()):
    print(f"region {b:08x}: {c} refs")
