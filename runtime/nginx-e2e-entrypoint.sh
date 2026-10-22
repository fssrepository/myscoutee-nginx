#!/bin/sh
set -eu

umask 077

certificate_directory=/etc/nginx/keys
certificate_path="${certificate_directory}/nginx.crt"
private_key_path="${certificate_directory}/nginx-nopass.key"

mkdir -p "${certificate_directory}"
if [ ! -s "${certificate_path}" ] || [ ! -s "${private_key_path}" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${private_key_path}" \
    -out "${certificate_path}" \
    -days 2 \
    -sha256 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

chmod 0644 "${certificate_path}"
chmod 0600 "${private_key_path}"
nginx -t

exec nginx -g "daemon off;"
