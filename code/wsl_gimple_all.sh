#!/bin/bash
# Dump GIMPLE-SSA for every (release,file) in data/gimple_targets.txt, consistent naming, subdir-aware, 8 at a time.
R="/mnt/c/research_notes/Grounded slop"; OUT="$R/results/gimple"; mkdir -p "$OUT"
dump1() {
  v="$1"; src="$2"; BD=~/gslop/build/$v-cg
  [ -d "$BD/lib" ] || { echo "nobuild $v"; return; }
  b=$(basename "$src" .c)
  o="$OUT/$v-gimple_$b.c.023t.ssa"
  [ -f "$o" ] && { echo "skip $v $b"; return; }
  # locate the real source dir (lib, lib/vtls, lib/vauth, lib/vquic, lib/vssh, src, src/...)
  p=$(cd "$BD" && ls lib/$src lib/*/$src src/$src src/*/$src 2>/dev/null | head -1)
  [ -z "$p" ] && { echo "nosrc $v $src"; return; }
  d=$(dirname "$BD/$p")
  inc="-I$BD/include -I$BD/lib -I$d"
  [ -d "$BD/src" ] && inc="$inc -I$BD/src -I$BD/lib"
  ( cd "$d" && gcc -O1 -fno-inline -fdump-tree-ssa-lineno -DHAVE_CONFIG_H -DBUILDING_LIBCURL \
      -DCURL_HIDDEN_SYMBOLS $inc -c "$(basename $p)" -o $(mktemp -d)/gimple_$b.o -dumpdir "$OUT/$v-" 2>/dev/null )
  [ -f "$o" ] && echo "ok $v $b" || echo "FAIL $v $src"
}
export -f dump1; export OUT
tr -d '\r' < "$R/data/gimple_targets.txt" | awk -F'\t' 'NF==2' | \
  xargs -P8 -d'\n' -I{} bash -c 'IFS=$'"'"'\t'"'"' read v s <<< "{}"; dump1 "$v" "$s"' > "$OUT/../gimple_all.log" 2>&1
grep -c '^ok\|^skip' "$OUT/../gimple_all.log"; grep -c '^FAIL\|^nosrc' "$OUT/../gimple_all.log"; ls "$OUT"/*.ssa | wc -l
