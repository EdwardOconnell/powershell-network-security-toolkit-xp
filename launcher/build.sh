#!/bin/sh
# Builds NetSecToolkitXP.exe for Windows XP SP3 (32-bit) with mingw-w64.
#   Debian/Ubuntu: sudo apt install gcc-mingw-w64-i686
#   Windows:       MSYS2 "mingw-w64-i686-gcc", run from this folder
# No C runtime: only kernel32/user32 imports, all present on XP.
set -e
cd "$(dirname "$0")"
CC=${CC:-i686-w64-mingw32-gcc}
WINDRES=${WINDRES:-i686-w64-mingw32-windres}
$WINDRES NetSecToolkitXP.rc -O coff -o resource.o
$CC -Os -municode -ffreestanding -fno-stack-protector -nostdlib -s \
    -Wall -Wextra \
    -Wl,-e,_Start@0 -Wl,--subsystem,console:5.01 \
    -Wl,--major-os-version,5 -Wl,--minor-os-version,1 \
    -Wl,--nxcompat -Wl,--dynamicbase \
    -o ../NetSecToolkitXP.exe NetSecToolkitXP.c resource.o -lkernel32 -luser32 -lgcc
rm -f resource.o
echo "Built ../NetSecToolkitXP.exe"
