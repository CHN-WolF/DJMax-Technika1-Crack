import ctypes, sys, json, struct, collections
from ctypes import wintypes as w
pid = int(sys.argv[1])
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.ReadProcessMemory.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
h = k32.OpenProcess(0x410, False, pid)
def rpm(addr, size):
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, addr, buf, size, ctypes.byref(got)): return None
    return buf.raw[:got.value]

mods = [m for m in json.load(open(f"modules_{pid}.json")) if m["base"] >= 0x10000 and m["base"] < 0x80000000]
addr2name = {}
for m in mods:
    base, size = m["base"], m["size"]
    hdr = rpm(base, 0x1000)
    if not hdr or hdr[:2] != b"MZ": continue
    pe = struct.unpack("<I", hdr[0x3c:0x40])[0]
    exp_rva, exp_sz = struct.unpack("<II", hdr[pe+24+96:pe+24+104])
    if not exp_rva: continue
    exp = rpm(base+exp_rva, 0x1000)
    if not exp: continue
    try:
        (chars, ts, vmaj, vmin, name_rva, obase, nfunc, nname,
         afunc, aname, aord) = struct.unpack("<IIHHIIIIIII", exp[:40])
    except struct.error: continue
    dllname_b = rpm(base+name_rva, 64)
    dllname = dllname_b.split(b"\x00")[0].decode(errors="replace") if dllname_b else m["name"]
    funcs = rpm(base+afunc, nfunc*4)
    names = rpm(base+aname, nname*4)
    ords  = rpm(base+aord, nname*2)
    if not (funcs and names and ords): continue
    fa = struct.unpack(f"<{nfunc}I", funcs)
    na = struct.unpack(f"<{nname}I", names)
    oa = struct.unpack(f"<{nname}H", ords)
    for i in range(nname):
        fva = base + fa[oa[i]]
        nb = rpm(base+na[i], 128)
        if not nb: continue
        fn = nb.split(b"\x00")[0].decode(errors="replace")
        addr2name[fva] = f"{dllname}!{fn}"
    for i in range(nfunc):
        fva = base + fa[i]
        if fva not in addr2name:
            addr2name[fva] = f"{dllname}!ord_{obase+i}"

json.dump(addr2name, open(f"exports_{pid}.json","w"))
print("exports mapped:", len(addr2name))

d = open("sec7.bin","rb").read()
vals = struct.unpack(f"<{len(d)//4}I", d)
hits = collections.Counter()
locs = collections.defaultdict(list)
for i, v in enumerate(vals):
    if v in addr2name:
        hits[addr2name[v]] += 1
        locs[v].append(i*4)
print("api pointer slots in sec7:", sum(len(x) for x in locs.values()), "unique:", len(locs))
for name, c in hits.most_common(40):
    print(f"  {c:4d}  {name}")
json.dump({hex(k): v for k,v in locs.items()}, open("sec7_apislots.json","w"))
