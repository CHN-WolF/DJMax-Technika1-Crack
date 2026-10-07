# rebuild.py — build client_unpacked2.exe from client.exe + OEP image dump
# - sections' raw content <- OEP runtime content
# - plain 3-DLL import table at the existing import dir (RVA 0xf65004c)
# - EP stays 0xf659700, TLS dir cleared, reloc dir cleared
import struct, pefile, os

GAME = r"G:\SteamLibrary\steamapps/common/DJMax Technika 1 China Version"
SRC = os.path.join(GAME, "client.exe")
IMG = os.path.join(GAME, "crack_work", "analysis", "img_oep.bin")
DST = os.path.join(GAME, "crack_work", "dump", "client_unpacked2.exe")

data = bytearray(open(SRC, "rb").read())
img_lo = open(os.path.join(GAME, "crack_work", "analysis", "img_lo_oep.bin"), "rb").read()
img_hi = open(os.path.join(GAME, "crack_work", "analysis", "img_hi_oep.bin"), "rb").read()
LO_VA, HI_VA = 0x401000, 0xF9E2000

def oep_bytes(va, n):
    if LO_VA <= va and va + n <= LO_VA + len(img_lo):
        return img_lo[va - LO_VA : va - LO_VA + n]
    if HI_VA <= va and va + n <= HI_VA + len(img_hi):
        return img_hi[va - HI_VA : va - HI_VA + n]
    return None

pe = pefile.PE(SRC, fast_load=True)
pe.parse_data_directories()

# 1) overwrite section raw data with OEP memory content
for s in pe.sections:
    rva = s.VirtualAddress
    rawsz = s.SizeOfRawData
    rawoff = s.PointerToRawData
    name = s.Name.rstrip(b'\0').decode('latin-1')
    va = 0x400000 + rva
    if os.environ.get('ONLY_SEC7') and name != '0000007':
        print(f"section {name}: V3 keep original file bytes")
        continue
    chunk = oep_bytes(va, rawsz)
    if chunk is None:
        print(f"section {name}: NO OEP DATA for va {va:#x} size {rawsz:#x} - keeping file content")
        continue
    data[rawoff:rawoff + rawsz] = chunk
    print(f"section {name}: wrote {rawsz:#x} bytes from OEP image")

# helper: raw offset <-> rva
def rva2off(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (rva - s.VirtualAddress)
    return None

# 2) build plain import table at RVA 0xf65004c (dir size 0x152)
import os
if os.environ.get('KEEP_IMP'):
    print('V1: keeping shell import descriptors, skipping import rewrite')
    IMP_RVA = 0xf65004c
    off = rva2off(IMP_RVA)
    # jump straight to header patch section by faking completion
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    opt = pe_off + 0x18
    dd = opt + 0x60
    if not os.environ.get('KEEP_TLS'):
        struct.pack_into('<II', data, dd + 9 * 8, 0, 0)
    struct.pack_into('<II', data, dd + 5 * 8, 0, 0)
    struct.pack_into('<II', data, dd + 6 * 8, 0, 0)
    chars = struct.unpack_from('<H', data, pe_off + 0x16)[0]
    struct.pack_into('<H', data, pe_off + 0x16, chars | 0x0001)
    open(DST, 'wb').write(bytes(data))
    print('wrote', DST, len(data), 'bytes (V1)')
    raise SystemExit
IMP_RVA = 0xf65004c
off = rva2off(IMP_RVA)
base = IMP_RVA

def wstr(o, b):
    data[o:o + len(b)] = b

# layout: descs at +0x00 (4*20), OFT arrays at +0x50, strings at +0x80
ADV, KRN, USR = b"ADVAPI32.dll\0", b"KERNEL32.dll\0", b"USER32.dll\0"
apis = [
    # (dll, dllname_off, firstthunk_rva, [api names])
    ("adv", 0, 0xf650000, [b"RegOpenKeyExA"]),
    ("krn", 0, 0xf650008, [b"GetSystemDirectoryA", b"LoadLibraryA", b"GetModuleHandleA", b"GetProcAddress"]),
    ("usr", 0, 0xf65001c, [b"MessageBoxA"]),
]

p = off + 0x50
oft_rvas = []
for dll, _, ft, names in apis:
    oft_rvas.append(p - off + base)
    for n in names:
        hintname_rva = 0  # fill later
        struct.pack_into('<I', data, p, 0)  # placeholder
        p += 4
    struct.pack_into('<I', data, p, 0)
    p += 4

str_rva_ptr = off + 0x80
hint_entries = []  # (oft_table_pos, hintname_rva)
dll_name_rvas = {}
for dll, _, ft, names in apis:
    # dll name string
    dllnm = {"adv": ADV, "krn": KRN, "usr": USR}[dll]
    wstr(str_rva_ptr, dllnm)
    dll_name_rvas[dll] = str_rva_ptr - off + base
    str_rva_ptr += len(dllnm)
for dll, _, ft, names in apis:
    for n in names:
        wstr(str_rva_ptr, b'\0\0' + n + b'\0')
        hint_entries.append(str_rva_ptr - off + base)
        str_rva_ptr += 2 + len(n) + 1
if (str_rva_ptr - off) % 2:
    str_rva_ptr += 1

# fill OFT tables with hintname rvas
idx = 0
p = off + 0x50
for di, (dll, _, ft, names) in enumerate(apis):
    for n in names:
        struct.pack_into('<I', data, p, hint_entries[idx])
        idx += 1
        p += 4
    p += 4  # null term

# descriptors
for di, (dll, _, ft, names) in enumerate(apis):
    struct.pack_into('<IIIII', data, off + di * 20,
                     oft_rvas[di], 0, 0, dll_name_rvas[dll], ft)
# null descriptor
struct.pack_into('<IIIII', data, off + 3 * 20, 0, 0, 0, 0, 0)
print("import table written, ends at", hex(str_rva_ptr - off + base), "dir size 0x152 =", 0x152, "fits:", (str_rva_ptr - off) <= 0x152)

# 3) headers: EP stays; clear TLS dir; clear reloc dir; clear debug
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
opt = pe_off + 0x18
dd = opt + 0x60
struct.pack_into('<II', data, dd + 9 * 8, 0, 0)   # TLS
struct.pack_into('<II', data, dd + 5 * 8, 0, 0)   # reloc
struct.pack_into('<II', data, dd + 6 * 8, 0, 0)   # debug
# force no-ASLR: set RELOCS_STRIPPED in Characteristics
chars = struct.unpack_from('<H', data, pe_off + 0x16)[0]
struct.pack_into('<H', data, pe_off + 0x16, chars | 0x0001)
print("headers patched (TLS/reloc/debug cleared, relocs stripped)")

open(DST, "wb").write(bytes(data))
print("wrote", DST, len(data), "bytes")
