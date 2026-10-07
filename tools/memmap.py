import ctypes, sys
from ctypes import wintypes as w

pid = int(sys.argv[1])
k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = w.HANDLE
k32.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
k32.VirtualQueryEx.restype = ctypes.c_size_t
k32.VirtualQueryEx.argtypes = [w.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

h = k32.OpenProcess(0x410, False, pid)
if not h: print("OpenProcess failed"); sys.exit(1)

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong),("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", w.DWORD),("__align1", w.DWORD),
                ("RegionSize", ctypes.c_ulonglong),
                ("State", w.DWORD),("Protect", w.DWORD),("Type", w.DWORD),("__align2", w.DWORD)]

PROT = {1:"---",2:"R--",4:"RW-",8:"WC-",0x10:"X--",0x20:"RX-",0x40:"RWX",0x80:"WCX"}
addr = 0
mbi = MBI()
while addr < 0x7fff0000:
    r = k32.VirtualQueryEx(h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi))
    if not r: break
    if mbi.State == 0x1000:
        t = {0x1000000:"IMG",0x40000:"MAP",0x20000:"PRV"}.get(mbi.Type,hex(mbi.Type))
        print(f"{mbi.BaseAddress:08x} {mbi.RegionSize:>10x} {PROT.get(mbi.Protect&0xff,hex(mbi.Protect)):>4} {t}")
    addr = mbi.BaseAddress + mbi.RegionSize
k32.CloseHandle(h)
