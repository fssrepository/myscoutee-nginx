#!/bin/sh
set -eu
apk add --no-cache build-base linux-headers pcre2-dev openssl-dev zlib-dev s2geometry-dev json-c-dev curl-dev
cd /tmp
wget -q https://nginx.org/download/nginx-1.29.6.tar.gz
echo '316f298cd9f061d6d0679696152710285b72f75d88eb1f7e323f40c5c52fe0d7  nginx-1.29.6.tar.gz' | sha256sum -c -
tar xzf nginx-1.29.6.tar.gz
g++ -std=c++17 -O2 -fPIC -Wall -Wextra -Werror -pthread -I/module -c /module/geometry.cc -o /module/geometry.o
cd nginx-1.29.6
./configure --with-compat --with-threads --add-dynamic-module=/module --add-dynamic-module=/edge >/tmp/configure.log
make -j2 modules
cp objs/ngx_http_partition_module.so objs/ngx_http_edge_module.so /module/
