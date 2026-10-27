#!/bin/bash
# Dump GIMPLE-SSA for one lib file at a curl commit, compiled against the commit's OWN full source tree
# (materialized via git archive) plus a generated curl_config.h borrowed from an era-matched release build.
# Usage: wsl_gimple_commit.sh <commit> <lib/file.c> <build-version> <out-tag>
# Output: results/gimple_diff/<out-tag>.023t.ssa
COMMIT=$1; FILE=$2; BV=$3; TAG=$4
REPO=~/gslop/curl
BD=~/gslop/build/$BV-cg
OUT="/mnt/c/research_notes/Grounded slop/results/gimple_diff"
TREES=~/gslop/trees
mkdir -p "$OUT" "$TREES"
[ -f "$BD/lib/curl_config.h" ] || { echo "nobuild $BV"; exit 1; }
T="$TREES/$COMMIT"
if [ ! -d "$T/lib" ]; then
  mkdir -p "$T"
  git -C $REPO archive "$COMMIT" 2>/dev/null | tar -x -C "$T" 2>/dev/null || { echo "noarchive $COMMIT"; exit 1; }
fi
# inject generated config headers from the era build (configure outputs)
cp "$BD/lib/curl_config.h" "$T/lib/curl_config.h" 2>/dev/null
[ -f "$BD/include/curl/curlbuild.h" ] && cp "$BD/include/curl/curlbuild.h" "$T/include/curl/" 2>/dev/null
b=$(basename "$FILE" .c)
dir="$T/$(dirname "$FILE")"
[ -f "$dir/$b.c" ] || { echo "nofile $FILE @ $COMMIT"; exit 1; }
DD=$(mktemp -d)
( cd "$dir" && gcc -O1 -fno-inline -fdump-tree-ssa-lineno -DHAVE_CONFIG_H -DBUILDING_LIBCURL \
    -DCURL_HIDDEN_SYMBOLS -I"$T/include" -I"$T/lib" -I. -c "$b.c" -o "$DD/$b.o" \
    -dumpdir "$DD/d-" 2> "$DD/err" )
if [ -f "$DD/d-$b.c.023t.ssa" ]; then
  cp "$DD/d-$b.c.023t.ssa" "$OUT/$TAG.023t.ssa"; echo "ok $TAG ($BV)"
else
  echo "FAIL $TAG ($BV)"; cp "$DD/err" "$OUT/$TAG.err"; head -2 "$DD/err"
fi
rm -rf "$DD"
