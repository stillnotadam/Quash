#!/bin/bash
# Dump GCC GIMPLE in SSA form for one library source file of a built release.
# Usage: wsl_gimple.sh <version> <lib-relative source, e.g. socks.c> <outdir>
V=$1; SRC=$2; OUT=$3
D=~/gslop/build/$V-cg
cd $D/lib || exit 1
mkdir -p "$OUT"
B=$(basename $SRC .c)
# -O1 keeps SSA readable while folding trivial temporaries; ssa dump is taken before most optimizations
gcc -O1 -fno-inline -fdump-tree-ssa-lineno -DHAVE_CONFIG_H -DBUILDING_LIBCURL -DCURL_HIDDEN_SYMBOLS \
    -I../include -I. -I../lib -c "$SRC" -o /tmp/gimple_$B.o -dumpdir "$OUT/$V-" 2> "$OUT/$V-$B.err"
ls "$OUT"/$V-* | head
