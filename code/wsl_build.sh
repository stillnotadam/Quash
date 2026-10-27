#!/bin/bash
# Usage: wsl_build.sh <version> <variant: asan|cg>
# asan: -O1 ASan+UBSan build for reproduction
# suffix -nd: release-style build without --enable-debug (no debug-only code paths)
# cg:   -O0 build with GCC call-graph info, function sections and gcov coverage
set -e
V=$1; VAR=$2
mkdir -p ~/gslop/tar ~/gslop/build
cd ~/gslop/tar
[ -f curl-$V.tar.gz ] || curl -sfLO https://curl.se/download/curl-$V.tar.gz
D=~/gslop/build/$V-$VAR
if [ -x $D/src/curl ]; then echo "exists $D"; exit 0; fi
rm -rf $D; mkdir -p $D
tar xzf curl-$V.tar.gz -C $D --strip-components=1
cd $D
DBG=--enable-debug
case "$VAR" in *-nd) DBG=--disable-debug;; esac
if [ "${VAR%-nd}" = asan ]; then
  CF='-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined'
  LF='-fsanitize=address,undefined'
else
  CF='-O0 -g -fcallgraph-info -ffunction-sections -fdata-sections --coverage'
  LF='--coverage'
fi
CFLAGS="$CF" LDFLAGS="$LF" ./configure --without-ssl --without-zlib --without-libpsl --without-brotli \
  --without-zstd --without-nghttp2 --without-libidn2 --disable-shared $DBG > cfg.log 2>&1 \
  || { tail -20 cfg.log; exit 1; }
make -j${JOBS:-32} > build.log 2>&1 || { tail -30 build.log; exit 1; }
./src/curl -V | head -1
