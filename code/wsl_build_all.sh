#!/bin/bash
# Build the call-graph variant of every needed release, 4 at a time, then extract graphs.
L="/mnt/c/research_notes/Grounded slop/data/releases_needed.txt"
B="/mnt/c/research_notes/Grounded slop/code/wsl_build.sh"
export JOBS=8
tr -d '\r' < "$L" | xargs -P4 -I{} bash -c "bash '$B' {} cg > ~/gslop/build-{}.log 2>&1 && echo OK {} || echo FAIL {}"
