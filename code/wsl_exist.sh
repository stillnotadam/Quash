#!/bin/bash
cd "/mnt/c/research_notes/Grounded slop/code"
python3 exist_check.py ~/gslop/curl ../data/h1 ../data/master.csv ../results/existence_crude.csv 2>/dev/null
python3 exist_check.py ~/gslop/curl ../data/h1 ../data/master.csv ../results/existence_scoped.csv scoped 2>/dev/null
tail -5 ~/gslop/build-8.4.0.log
