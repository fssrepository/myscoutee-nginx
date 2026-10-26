ARG NGINX_IMAGE=nginx:1.29.6-alpine
FROM ${NGINX_IMAGE} AS module-builder
RUN apk add --no-cache build-base linux-headers pcre2-dev openssl-dev zlib-dev s2geometry-dev json-c-dev curl-dev
COPY partition/ /module/
COPY edge/ /edge/
RUN sh /module/build.sh

FROM ${NGINX_IMAGE}
LABEL org.opencontainers.image.source="https://github.com/fssrepository/myscoutee-nginx" \
      org.opencontainers.image.licenses="BSD-3-Clause"
RUN apk add --no-cache s2geometry json-c libcurl bash netcat-openbsd dcron curl inotify-tools openssl tzdata jq
COPY --from=module-builder /module/ngx_http_partition_module.so /usr/lib/nginx/modules/ngx_http_partition_module.so
COPY --from=module-builder /module/ngx_http_edge_module.so /usr/lib/nginx/modules/ngx_http_edge_module.so
RUN mkdir -p /var/lib/nginx/myscoutee /usr/share/nginx/diagnostics && chown nginx:nginx /var/lib/nginx/myscoutee
COPY --chmod=0644 browser/landing.js /usr/share/nginx/diagnostics/landing.js
COPY conf/ /etc/nginx/myscoutee/
COPY --chmod=0755 runtime/ /scripts/
COPY tools/render-routes.py /opt/myscoutee-nginx/tools/render-routes.py
RUN mkdir -p /etc/nginx/myscoutee-operator && cp /etc/nginx/myscoutee/nginx-blocked-ips.json /etc/nginx/myscoutee-operator/nginx-blocked-ips.json
