#!/bin/sh
set -eu
apk add --no-cache build-base linux-headers pcre2-dev openssl-dev zlib-dev s2geometry-dev json-c-dev curl-dev
cd /tmp
wget -q https://nginx.org/download/nginx-1.31.8.tar.gz
echo '0652b760b3b772d2ec17b47c2fc15d9a95e6fe35cd5b877eadc1a62d9bc75af1  nginx-1.31.8.tar.gz' | sha256sum -c -
tar xzf nginx-1.31.8.tar.gz
g++ -std=c++17 -O2 -fPIC -Wall -Wextra -Werror -pthread -I/module -c /module/geometry.cc -o /module/geometry.o
cd nginx-1.31.8
./configure --with-compat --with-threads --add-dynamic-module=/module --add-dynamic-module=/edge >/tmp/configure.log
make -j2 modules
cp objs/ngx_http_partition_module.so objs/ngx_http_edge_module.so /module/
