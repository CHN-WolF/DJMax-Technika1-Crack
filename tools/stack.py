import ctypes, sys
from ctypes import wintypes as w
pid, esp, size = int(sys.argv[1]), int(sys.argv[2],16), int(sys.argv[3],16)
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
# align down to page
start = esp & ~0xfff
buf = ctypes.create_string_buffer(size)
got = ctypes.c_size_t(0)
k32.ReadProcessMemory(h, start, buf, size, ctypes.byref(got))
d = buf.raw[:got.value]
# module executable regions of interest
regions = [(0x401000,0x290000,'sec1'),(0x691000,0xf352000,'sec23'),(0xfa34000,0x1c000,'sec6'),(0xfa50000,0x4c7000,'sec7')]
import struct
vals = struct.unpack(f"<{len(d)//4}I", d[:(len(d)//4)*4])
seen=set()
for i, v in enumerate(vals):
    if v in seen: continue
    for rb, rs, name in regions:
        if rb <= v < rb+rs:
            print(f"stack+{i*4:05x}: {v:08x} -> {name}+{v-rb:x}")
            seen.add(v)
