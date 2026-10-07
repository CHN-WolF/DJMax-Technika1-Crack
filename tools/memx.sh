#!/bin/bash
# memx.sh — tools for memdump_at_abort.bin (format: [DWORD base][DWORD size][bytes] x2)
#   memx.sh split <file>          -> writes /tmp/mem_lo.bin /tmp/mem_hi.bin
#   memx.sh dis  <va> <len>       -> disassemble [va, va+len)
#   memx.sh xref <imm32hex>       -> find little-endian dword references to a VA (e.g. 0x6efb94)
set -e
F=${F:-/tmp/memdump_at_abort.bin}
OD="g:/SteamLibrary/steamapps/common/DJMax Technika 1 China Version/crack_work/tools/toolchain/w64devkit_x/w64devkit/bin/objdump.exe"
LO_BASE=$((0x401000)); LO_SIZE=$((0x75D000-0x401000))
HI_BASE=$((0xFA50000)); HI_SIZE=$((0xFF17000-0xFA50000))

case "$1" in
split)
  dd if="$F" of=/tmp/mem_lo.bin bs=1 skip=8 count=$LO_SIZE status=none
  off=$((8 + LO_SIZE + 8))
  dd if="$F" of=/tmp/mem_hi.bin bs=1 skip=$off count=$HI_SIZE status=none
  echo "lo: $(stat -c %s /tmp/mem_lo.bin) bytes @0x401000 ; hi: $(stat -c %s /tmp/mem_hi.bin) bytes @0xFA50000"
  ;;
dis)
  VA=$(printf "%d" $2); LEN=$(printf "%d" $3)
  if [ $VA -ge $LO_BASE ] && [ $VA -lt $((LO_BASE+LO_SIZE)) ]; then
    B=/tmp/mem_lo.bin; BASE=$LO_BASE
  else
    B=/tmp/mem_hi.bin; BASE=$HI_BASE
  fi
  OFF=$((VA-BASE))
  dd if=$B bs=1 skip=$OFF count=$LEN status=none of=/tmp/memdis.bin
  "$OD" -D -b binary -m i386 --adjust-vma=$VA /tmp/memdis.bin | grep -E "^\s+[0-9a-f]+:"
  ;;
xref)
  V=$(echo "$2" | sed 's/^0x//')
  # little-endian bytes
  B1=${V:6:2}; B2=${V:4:2}; B3=${V:2:2}; B4=${V:0:2}
  PAT=$(printf '\\x%s\\x%s\\x%s\\x%s' $B1 $B2 $B3 $B4)
  for pair in "/tmp/mem_lo.bin $LO_BASE" "/tmp/mem_hi.bin $HI_BASE"; do
    set -- $pair
    grep -aboP "$PAT" "$1" | while IFS=: read -r off rest; do
      printf "xref to 0x%s: VA 0x%x (file %s off 0x%x)\n" "$V" $(( $2 + off )) "$1" $off
    done
  done
  ;;
esac
