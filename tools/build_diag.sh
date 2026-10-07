#!/bin/bash
# Build RC_GrandLocal_diag.dll (diagnostic replay local-layer with abort catcher)
# using the portable w64devkit toolchain in tools/toolchain/.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
TC="$DIR/toolchain/w64devkit_x/w64devkit/bin"
GCC="$TC/gcc.exe"
WINDRES="$TC/windres.exe"
cd "$DIR"

# resource: embedded official RC_GrandLocal.dll (RC_GrandLocal_official.dll must be here)
"$WINDRES" -F pe-i386 -i rclocal_replay.rc -o rclocal_diag_res.o

"$GCC" -m32 -O1 -mpreferred-stack-boundary=2 -Wall -Wno-unused -c rclocal_diag.c -o rclocal_diag_c.o
"$GCC" -m32 -c thunks_gas.S -o thunks_gas.o

"$GCC" -m32 -shared -static-libgcc -mpreferred-stack-boundary=2 \
    -o RC_GrandLocal_diag.dll \
    rclocal_diag_c.o thunks_gas.o rclocal_diag_res.o rclocal_diag.def \
    -lwinmm -Wl,--disable-auto-import

echo "built: $DIR/RC_GrandLocal_diag.dll"
ls -la RC_GrandLocal_diag.dll
