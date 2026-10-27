#!/bin/bash
# Build TLS/HTTP2/SSH/zlib dependencies from official source releases into ~/gslop/deps (no root needed).
set -e
P=~/gslop/deps; mkdir -p $P ~/gslop/depsrc; cd ~/gslop/depsrc
which pkg-config || echo "no pkg-config"
dl() { [ -f "$2" ] || curl -sfL -o "$2" "$1"; }
dl https://zlib.net/fossils/zlib-1.3.1.tar.gz zlib.tgz
dl https://github.com/openssl/openssl/releases/download/openssl-3.0.15/openssl-3.0.15.tar.gz openssl.tgz
dl https://github.com/nghttp2/nghttp2/releases/download/v1.64.0/nghttp2-1.64.0.tar.gz nghttp2.tgz
dl https://github.com/libssh2/libssh2/releases/download/libssh2-1.11.1/libssh2-1.11.1.tar.gz libssh2.tgz
sha256sum *.tgz
for t in *.tgz; do tar xzf $t; done
(cd zlib-1.3.1 && ./configure --prefix=$P --static >/dev/null && make -j32 >/dev/null && make install >/dev/null) && echo zlib ok
(cd openssl-3.0.15 && ./Configure --prefix=$P --libdir=lib no-shared no-tests -fPIC >/dev/null && make -j32 >/dev/null 2>&1 && make install_sw >/dev/null) && echo openssl ok
(cd nghttp2-1.64.0 && ./configure --prefix=$P --enable-lib-only --disable-shared >/dev/null && make -j32 >/dev/null 2>&1 && make install >/dev/null) && echo nghttp2 ok
(cd libssh2-1.11.1 && ./configure --prefix=$P --disable-shared --with-crypto=openssl --with-libssl-prefix=$P --disable-examples-build >/dev/null && make -j32 >/dev/null 2>&1 && make install >/dev/null) && echo libssh2 ok
ls $P/lib
