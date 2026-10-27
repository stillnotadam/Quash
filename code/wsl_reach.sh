#!/bin/bash
cd "/mnt/c/research_notes/Grounded slop/code"
git -C ~/gslop/curl tag | grep -c '^curl-'
python3 reach_check.py ~/gslop/curl ../data/h1 ../data/master.csv ../results/cg ../results/reach.csv --release-col release_built
