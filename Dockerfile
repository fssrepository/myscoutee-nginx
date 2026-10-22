ARG NGINX_IMAGE=nginx:1.29.6-alpine
FROM ${NGINX_IMAGE} AS module-builder
COPY partition/ /module/
RUN sh /module/build.sh

FROM ${NGINX_IMAGE}
RUN apk add --no-cache s2geometry json-c
COPY --from=module-builder /module/ngx_http_partition_module.so /usr/lib/nginx/modules/ngx_http_partition_module.so
COPY conf/ /etc/nginx/myscoutee/
