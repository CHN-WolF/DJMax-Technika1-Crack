import ctypes, sys, json
from ctypes import wintypes as w
pid = int(sys.argv[1])
k32 = ctypes.windll.kernel32
class ME32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD),("th32ModuleID", w.DWORD),("th32ProcessID", w.DWORD),
                ("GlblcntUsage", w.DWORD),("ProccntUsage", w.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),("modBaseSize", w.DWORD),
                ("hModule", w.HMODULE),("szModule", ctypes.c_char*256),("szExePath", ctypes.c_char*260)]
snap = k32.CreateToolhelp32Snapshot(0x18, pid)  # MODULE|MODULE32
me = ME32(); me.dwSize = ctypes.sizeof(ME32)
mods = []
ok = k32.Module32First(snap, ctypes.byref(me))
while ok:
    base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
    mods.append({"name": me.szModule.decode(errors='replace'), "base": base, "size": me.modBaseSize})
    ok = k32.Module32Next(snap, ctypes.byref(me))
k32.CloseHandle(snap)
json.dump(mods, open(f"modules_{pid}.json","w"), indent=1)
for m in mods: print(f"{m['base']:08x} {m['size']:>9x} {m['name']}")
