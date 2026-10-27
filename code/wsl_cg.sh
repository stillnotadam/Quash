#!/bin/bash
V=${1:-8.23.0}
cd "/mnt/c/research_notes/Grounded slop/code"
python3 callgraph.py ~/gslop/build/$V-cg ~/gslop/cg-$V.json && cp ~/gslop/cg-$V.json "../results/cg-$V.json"
