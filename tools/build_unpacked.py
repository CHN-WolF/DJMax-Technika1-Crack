# Build client_unpacked.exe from the pe-sieve realigned dump.
# - compacts raw layout (trims the 254MB zero section)
# - extends last section with a real import table:
#   original Themida mini-imports (kernel32/user32/advapi32, FT slots at 0xf6500xx)
#   + extra DLL descriptors to force-load game DLLs
import struct, sys

SRC = 'process_35692/400000.client_renamed.exe'
DST = 'client_unpacked.exe'
IMGBASE = 0x400000

d = open(SRC, 'rb').read()
pe = struct.unpack('<I', d[0x3c:0x40])[0]
assert d[pe:pe+4] == b'PE\x00\x00'
OPT = 0xe0
so = pe + 24

def sec(i):
    o = so + OPT + 40 * i
    name = bytes(d[o:o+8])
    vs, va, rs, rp = struct.unpack('<IIII', d[o+8:o+24])
    chars = struct.unpack('<I', d[o+36:o+40])[0]
    return {'o': o, 'name': name, 'vs': vs, 'va': va, 'rs': rs, 'rp': rp, 'chars': chars}

secs = [sec(i) for i in range(7)]

# sanity: mini import descriptors present at 0xf65004c
assert d[0xf65004c:0xf650050] == struct.pack('<I', 0xf6500a4), d[0xf65004c:0xf650050].hex()
assert d[0xf6500c0:0xf6500c4] == b'>\x01Ge', d[0xf6500c0:0xf6500d0]

# ---- layout plan: (index, new_raw_size, keep_data_from_rva)
# compact raw pointers; trim sec2 (0000003) to 0x41000 (rest is zero); extend sec6 to 0x4d000
plan = []
rp = 0x1000
newraws = [0x290000, 0x8b000, 0x41000, 0x1000, 0x51000, 0x1c000, 0x4ca000]
for i, s in enumerate(secs):
    nr = newraws[i]
    plan.append({'i': i, 'rp': rp, 'rs': nr})
    rp += nr

# ---- build new section data
secdata = []
for i, s in enumerate(secs):
    nr = newraws[i]
    old = d[s['rp']:s['rp'] + min(nr, s['rs'])]
    if nr > s['rs']:
        old = old + b'\x00' * (nr - len(old))
    else:
        old = old[:nr]
    secdata.append(bytearray(old))

# ---- extra import area at sec6 end, page aligned
# sec6: va 0xf650000, raw data ends at RVA 0xfb17f2b -> extend to 0x4d000 raw
EXTRA_RVA = 0xfb18000
extra_dlls = [
    ("WS2_32.dll",    "WSAStartup"),
    ("d3d9.dll",      "Direct3DCreate9"),
    ("D3DX9_39.dll",  "D3DXCreateEffect"),
    ("DSOUND.dll",    "DirectSoundCreate"),
    ("WINMM.dll",     "timeGetTime"),
    ("DINPUT8.dll",   "DirectInput8Create"),
    ("binkw32.dll",   "_BinkOpen@8"),
    ("MSVCR80.dll",   "malloc"),
    ("msvcrt.dll",    "malloc"),
    ("GDI32.dll",     "GetDeviceCaps"),
    ("ole32.dll",     "CoInitialize"),
    ("OLEAUT32.dll",  "SysAllocString"),
    ("SHELL32.dll",   "ShellExecuteA"),
    ("SHLWAPI.dll",   "PathFileExistsA"),
    ("comdlg32.dll",  "GetOpenFileNameA"),
    ("COMCTL32.dll",  "InitCommonControls"),
    ("VERSION.dll",   "GetFileVersionInfoA"),
    ("IMM32.dll",     "ImmGetContext"),
    ("iphlpapi.dll",  "GetAdaptersInfo"),
    ("RPCRT4.dll",    "UuidCreate"),
    ("CRT_R1.dll",    "AT88SC102_Read"),
]

NDESC = 3 + len(extra_dlls) + 1
desc_area = bytearray()
# original 3 descriptors (unchanged RVAs)
orig_descs = [
    (0xf6500a4, 0xf65010c, 0xf650008),  # kernel32
    (0xf6500b8, 0xf650128, 0xf65001c),  # user32
    (0xf65009c, 0xf650144, 0xf650000),  # advapi32
]
for oft, nm, ft in orig_descs:
    desc_area += struct.pack('<IIIII', oft, 0, 0, nm, ft)

# layout extra tables after descriptor array
cur = EXTRA_RVA + NDESC * 20
extra_blobs = bytearray()
extra_descs = []
for dll, fn in extra_dlls:
    oft_rva = cur; cur += 8
    ft_rva = cur; cur += 8
    hn_rva = cur
    hn = struct.pack('<H', 0) + fn.encode() + b'\x00'
    if len(hn) % 2: hn += b'\x00'
    cur += len(hn)
    name_rva = cur
    nb = dll.encode() + b'\x00'
    if len(nb) % 2: nb += b'\x00'
    cur += len(nb)
    extra_descs.append((oft_rva, name_rva, ft_rva))
    extra_blobs += struct.pack('<II', hn_rva, 0)   # OFT
    extra_blobs += struct.pack('<II', hn_rva, 0)   # FT
    extra_blobs += hn
    extra_blobs += nb

for oft_rva, name_rva, ft_rva in extra_descs:
    desc_area += struct.pack('<IIIII', oft_rva, 0, 0, name_rva, ft_rva)
desc_area += b'\x00' * 20  # null descriptor

import_area = bytes(desc_area) + bytes(extra_blobs)
assert len(import_area) <= 0x3000
sec6_off = EXTRA_RVA - 0xf650000  # 0x4d000
secdata[6][sec6_off:sec6_off+len(import_area)] = import_area

# ---- write output
out = bytearray()
hdr_size = 0x1000
out += d[:hdr_size]
for p, sdata in zip(plan, secdata):
    assert len(out) <= p['rp']
    out += b'\x00' * (p['rp'] - len(out))
    out += bytes(sdata)

# patch headers in `out`
def w32(off, v): out[off:off+4] = struct.pack('<I', v)
def wsec(i, field_off, v): w32(so + OPT + 40 * i + field_off, v)

for i, p in enumerate(plan):
    wsec(i, 16, p['rs'])   # SizeOfRawData
    wsec(i, 20, p['rp'])   # PointerToRawData
# sec2 virtual size stays huge (0xf2c6000) intentionally
# sec6 virtual size -> 0x50000 (0x4d000 rounded up to 0x1000)
wsec(6, 8, 0x4ca000)

# optional header
w32(pe + 24 + 56, 0xfb1a000)          # SizeOfImage
w32(pe + 24 + 96 + 9 * 8, 0)          # TLS dir rva = 0
w32(pe + 24 + 96 + 9 * 8 + 4, 0)      # TLS dir size = 0
w32(pe + 24 + 96 + 1 * 8, EXTRA_RVA)  # import dir
w32(pe + 24 + 96 + 1 * 8 + 4, NDESC * 20)
w32(pe + 24 + 96 + 12 * 8, 0xf650000) # IAT dir (original slots)
w32(pe + 24 + 96 + 12 * 8 + 4, 0x40)
# zero checksum
w32(pe + 24 + 64, 0)

open(DST, 'wb').write(bytes(out))
print("written", DST, len(out), "bytes")
