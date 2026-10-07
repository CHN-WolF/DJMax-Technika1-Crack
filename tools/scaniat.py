import ctypes, sys, json, struct, collections
from ctypes import wintypes as w
pid = int(sys.argv[1])
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
exports = {int(k,16): v for k,v in json.load(open(f"exports_{pid}.json")).items()}
class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong),("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD),("__a", w.DWORD),("RegionSize", ctypes.c_ulonglong),
                ("State", w.DWORD),("Protect", w.DWORD),("Type", w.DWORD),("__b", w.DWORD)]
mbi = MBI(); addr = 0
regions = []
while addr < 0x7fff0000:
    if not k32.VirtualQueryEx(h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)): break
    if mbi.State == 0x1000 and (mbi.Protect & 0xcc) and mbi.RegionSize >= 0x1000:  # RW-ish
        regions.append((mbi.BaseAddress, mbi.RegionSize, mbi.Protect))
    addr = mbi.BaseAddress + mbi.RegionSize
print(len(regions), "writable regions")
report = {}
for base, size, prot in regions:
    data = bytearray()
    off = 0
    while off < size:
        n = min(0x200000, size-off)
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(h, base+off, buf, n, ctypes.byref(got)):
            data += buf.raw[:got.value]
        off += n
    vals = struct.unpack(f"<{len(data)//4}I", bytes(data[:len(data)//4*4]))
    runs = []
    cur = []
    for i, v in enumerate(vals):
        if v in exports:
            cur.append((i, exports[v]))
        else:
            if len(cur) >= 3: runs.append(cur)
            cur = []
    if len(cur) >= 3: runs.append(cur)
    if runs:
        total = sum(len(r) for r in runs)
        report[f"{base:08x}"] = {"size": size, "runs": len(runs), "total": total}
        print(f"region {base:08x} ({size:#x}): {len(runs)} runs, {total} api ptrs")
        for r in runs[:5]:
            print(f"    +{r[0][0]*4:x}: {r[0][1]} ... ({len(r)})")
json.dump(report, open("iat_regions.json","w"))
