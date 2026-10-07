#!/bin/bash
# usage: xcode.sh <hexva> [logfile]  -- extract dumped code bytes around VA and disassemble
VA=$(echo "$1" | tr 'A-F' 'a-f' | sed 's/^0x//')
VA=$(printf "%08x" 0x$VA)
LOG=${2:-/tmp/cleanlog.txt}
OD="g:/SteamLibrary/steamapps/common/DJMax Technika 1 China Version/crack_work/tools/toolchain/w64devkit_x/w64devkit/bin/objdump.exe"
awk -v va="$VA" '
  index($0, "code@" va) && !done {grab=1; done=1; next}
  grab && /^ +[0-9a-f]{8}:/ {
    line=$0; sub(/^ +[0-9a-f]{8}: */, "", line)
    n=split(line, a, " ")
    for(i=1;i<=n;i++) if (a[i] ~ /^[0-9a-f][0-9a-f]$/) printf "%s", a[i]
    next
  }
  grab {grab=0}
' "$LOG" | xxd -r -p > /tmp/code_$VA.bin
SIZE=$(stat -c %s /tmp/code_$VA.bin)
echo "VA=0x$VA dumped=$SIZE bytes (dump starts at VA-0x30)"
START=$(printf "%d" 0x$VA)
ADJ=$((START - 48))
"$OD" -D -b binary -m i386 --adjust-vma=$ADJ /tmp/code_$VA.bin 2>/dev/null | grep -E "^\s+[0-9a-f]+:"
