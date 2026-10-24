#! /bin/bash

# Dev owns a writable runtime copy; shared templates also feed production.
mkdir -p /etc/nginx/conf.d
cp /etc/nginx/dev-templates/*.conf /etc/nginx/conf.d/

# Configuration
DOMAIN=${DOMAIN:-localhost}
LETSENCRYPT_ENABLED=${LETSENCRYPT_ENABLED:-false}

echo "Starting Nginx with LETSENCRYPT_ENABLED=$LETSENCRYPT_ENABLED for DOMAIN=$DOMAIN"

ensure_default_certificate() {
    local cert_path="/etc/nginx/keys/nginx.crt"
    local key_path="/etc/nginx/keys/nginx-nopass.key"

    if [ -f "$cert_path" ] && [ -f "$key_path" ]; then
        return
    fi

    mkdir -p /etc/nginx/keys
    openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout "$key_path" \
        -out "$cert_path" \
        -days 365 \
        -subj "/CN=localhost" >/dev/null 2>&1
    chmod 600 "$key_path"
}

ensure_default_certificate

# Replace ${DOMAIN} in all config files
find /etc/nginx/conf.d -type f -name "*.conf" -exec sed -i "s/\${DOMAIN}/$DOMAIN/g" {} +

if [ "$LETSENCRYPT_ENABLED" = "true" ]; then
    echo "Configuring Let's Encrypt..."
    if ! command -v certbot >/dev/null 2>&1; then
        echo "LETSENCRYPT_ENABLED=true but certbot is not installed in this nginx image." >&2
        exit 1
    fi

    if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo "Certificates not found. Obtaining from Let's Encrypt..."

        # We need Nginx running for certbot --nginx to work.
        nginx -g 'daemon on;'
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"
        nginx -s stop
        sleep 2
    fi

    find /etc/nginx/conf.d -type f -name "*.conf" -exec sed -i '/#SSL_LE_START/,/#SSL_LE_END/ s/^#//' {} +
    find /etc/nginx/conf.d -type f -name "*.conf" -exec sed -i '/#SSL_DEFAULT_START/,/#SSL_DEFAULT_END/ { /^#/! s/^/#/ }' {} +

    echo "0 0 * * * certbot renew --quiet" > /etc/cron.d/certbot-renew
    chmod 0644 /etc/cron.d/certbot-renew
    if command -v crond >/dev/null 2>&1; then
        crond
    elif command -v service >/dev/null 2>&1; then
        service cron start
    fi
else
    echo "Using default/localhost configuration."
    find /etc/nginx/conf.d -type f -name "*.conf" -exec sed -i "s/$DOMAIN/localhost/g" {} +
fi

if command -v inotifywait >/dev/null 2>&1; then
    while true; do
        changed_path=$(inotifywait -q -r -e close_write,create,delete,moved_to --format '%w' \
            /etc/nginx/dev-templates /etc/nginx/stream_conf.d /etc/nginx/keys /etc/nginx/nginx.conf)
        if [[ "$changed_path" == /etc/nginx/dev-templates/* ]]; then
            cp /etc/nginx/dev-templates/*.conf /etc/nginx/conf.d/
        fi
        nginx -t && nginx -s reload
    done &
fi

if [[ -z "$WAIT_FOR" ]]; then
    nginx -g 'daemon off;';
else
    /scripts/wait-for-it.sh -t 0 $WAIT_FOR -- nginx -g 'daemon off;';
fi
