#!/bin/bash
# Extract call graphs for every built release (static only unless gcovj/ exists), 8 in parallel.
cd "/mnt/c/research_notes/Grounded slop/code"
mkdir -p ../results/cg
ls -d ~/gslop/build/*-cg | xargs -P8 -I{} bash -c 'v=$(basename {} -cg); [ -f ../results/cg/cg-$v.json ] || python3 callgraph.py {} ../results/cg/cg-$v.json > ~/gslop/cgx-$v.log 2>&1; echo $v $(tail -2 ~/gslop/cgx-$v.log | tr "\n" " ")'
