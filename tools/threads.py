import ctypes, sys, collections
from ctypes import wintypes as w
pid = int(sys.argv[1])
k32 = ctypes.windll.kernel32
TH32CS_SNAPTHREAD = 0x4
class TE32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD),("cntUsage", w.DWORD),("th32ThreadID", w.DWORD),
                ("th32OwnerProcessID", w.DWORD),("tpBasePri", w.LONG),("tpDeltaPri", w.LONG),("dwFlags", w.DWORD)]
snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
te = TE32(); te.dwSize = ctypes.sizeof(TE32)
tids = []
ok = k32.Thread32First(snap, ctypes.byref(te))
while ok:
    if te.th32OwnerProcessID == pid: tids.append(te.th32ThreadID)
    ok = k32.Thread32Next(snap, ctypes.byref(te))
k32.CloseHandle(snap)
print(len(tids), "threads")

class CTX(ctypes.Structure):  # 32-bit CONTEXT on wow64: use Wow64GetThreadContext
    _fields_ = [("ContextFlags", w.DWORD),
                ("Dr0", w.DWORD),("Dr1", w.DWORD),("Dr2", w.DWORD),("Dr3", w.DWORD),("Dr6", w.DWORD),("Dr7", w.DWORD),
                ("FloatSave", w.BYTE*112),
                ("SegGs", w.DWORD),("SegFs", w.DWORD),("SegEs", w.DWORD),("SegDs", w.DWORD),
                ("Edi", w.DWORD),("Esi", w.DWORD),("Ebx", w.DWORD),("Edx", w.DWORD),("Ecx", w.DWORD),("Eax", w.DWORD),
                ("Ebp", w.DWORD),("Eip", w.DWORD),("SegCs", w.DWORD),("EFlags", w.DWORD),("Esp", w.DWORD),("SegSs", w.DWORD),
                ("ExtendedRegisters", w.BYTE*512)]

for tid in tids:
    ht = k32.OpenThread(0x0040 | 0x0002 | 0x0008 | 0x0020, False, tid)  # GET_CONTEXT|SUSPEND_RESUME|QUERY_INFORMATION...
    if not ht: continue
    k32.SuspendThread(ht)
    ctx = CTX(); ctx.ContextFlags = 0x10001  # WOW64_CONTEXT_CONTROL|INTEGER
    if k32.Wow64GetThreadContext(ht, ctypes.byref(ctx)):
        eip, esp = ctx.Eip, ctx.Esp
        k32.Wow64SetThreadContext  # noqa
        print(f"tid {tid:>6} eip={eip:08x} esp={esp:08x}")
    k32.ResumeThread(ht)
    k32.CloseHandle(ht)
