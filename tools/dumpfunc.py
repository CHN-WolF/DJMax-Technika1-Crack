import ctypes, struct, sys, time, subprocess
from ctypes import wintypes as w
exec(open('crack_work/tools/minidbg.py', encoding='utf-8').read().split('def main()')[0])

ADDR = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x652a00
SIZE = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x600
OUT = sys.argv[3] if len(sys.argv) > 3 else "crack_work/analysis/func_652a00.bin"

subprocess.Popen(["client.exe", "1", "127.0.0.1:4723"])
pid = None
hp = None
t0 = time.time()
while time.time() - t0 < 25:
    out = subprocess.run(["tasklist", "/NH", "/FI", "IMAGENAME eq client.exe"],
                         capture_output=True, text=True, errors="replace").stdout
    pids = [int(l.split()[1]) for l in out.splitlines() if l.lower().startswith("client.exe")]
    if pids:
        pid = pids[-1]
        hp = k32.OpenProcess(0x410, False, pid)
        code = rpm(hp, ADDR, SIZE) if hp else None
        if code:
            nops = code.count(0x90)
            zeros = code.count(0)
            if nops + zeros < SIZE * 0.6:
                open(OUT, "wb").write(code)
                print(f"dumped {SIZE:#x} at {ADDR:#x} from pid {pid}, nops={nops} zeros={zeros}")
                sys.exit(0)
            else:
                print(f"waiting... nops={nops} zeros={zeros}")
    time.sleep(1.0)
print("gave up")
