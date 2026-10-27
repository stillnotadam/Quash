#!/bin/bash
# Emit gcov JSON for the real library (libcurl_la-*) and the tool (src), NOT the unit-test library (libcurlu_la-*),
# which calls internal functions directly and would overstate public reachability.
# Usage: wsl_tests.sh <version> [run]   ("run" also (re)runs the test suite first)
V=${1:-8.23.0}
D=~/gslop/build/$V-cg
if [ "$2" = run ]; then
  cd $D/tests
  make -j32 > ../tests_build.log 2>&1 || { tail -30 ../tests_build.log; exit 1; }
  perl ./runtests.pl -j32 -a -n > ../tests_run.log 2>&1
  tail -3 ../tests_run.log
fi
cd $D
rm -rf gcovj && mkdir gcovj && cd gcovj
for f in $(find ../lib -name 'libcurl_la-*.gcda') $(find ../src -name '*.gcda'); do
  gcov --json-format -o "$(dirname $f)" "$f" > /dev/null 2>&1
  for j in *.gcov.json.gz; do [ -f "$j" ] && mv "$j" "$(basename $f .gcda).json.gz"; done
done
ls | wc -l
