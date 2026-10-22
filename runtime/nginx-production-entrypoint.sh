#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${DOMAIN:-localhost}"
LETSENCRYPT_ENABLED="${LETSENCRYPT_ENABLED:-false}"
SPRING_TEMPLATE="/etc/nginx/myscoutee-templates/spring.conf"
SPRING_CONFIG="/etc/nginx/conf.d/spring.conf"

fail() {
    echo "Nginx production configuration failed: $1" >&2
    exit 1
}

validate_domain() {
    local label

    [[ -n "${DOMAIN}" && "${#DOMAIN}" -le 253 ]] \
        || fail "DOMAIN must be a non-empty DNS name of at most 253 characters."
    [[ "${DOMAIN}" != .* && "${DOMAIN}" != *. && "${DOMAIN}" != *..* ]] \
        || fail "DOMAIN is not a valid DNS name: ${DOMAIN}"
    [[ "${DOMAIN}" =~ ^[A-Za-z0-9.-]+$ ]] \
        || fail "DOMAIN contains unsupported characters: ${DOMAIN}"

    IFS='.' read -r -a labels <<< "${DOMAIN}"
    for label in "${labels[@]}"; do
        [[ -n "${label}" && "${#label}" -le 63 ]] \
            || fail "DOMAIN contains an invalid DNS label: ${DOMAIN}"
        [[ "${label}" != -* && "${label}" != *- ]] \
            || fail "DOMAIN contains an invalid DNS label: ${DOMAIN}"
    done
}

normalize_boolean() {
    case "${LETSENCRYPT_ENABLED,,}" in
        true|1|yes|on)
            LETSENCRYPT_ENABLED=true
            ;;
        false|0|no|off)
            LETSENCRYPT_ENABLED=false
            ;;
        *)
            fail "LETSENCRYPT_ENABLED must be true or false."
            ;;
    esac
}

validate_certificate_path() {
    local label="$1"
    local path="$2"

    [[ "${path}" =~ ^/[A-Za-z0-9_./@:+-]+$ ]] \
        || fail "${label} must be an absolute path containing only safe path characters."
    [[ -s "${path}" ]] || fail "${label} does not exist or is empty: ${path}"
}

escape_sed_replacement() {
    printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'
}

render_spring_config() {
    local escaped_domain escaped_certificate escaped_key
    local tmp

    [[ -f "${SPRING_TEMPLATE}" ]] \
        || fail "the packaged Nginx template is missing: ${SPRING_TEMPLATE}"
    grep -Fq 'server_name localhost;' "${SPRING_TEMPLATE}" \
        || fail "the packaged Nginx template has no server-name marker."
    grep -Fq 'ssl_certificate /etc/nginx/keys/nginx.crt;' "${SPRING_TEMPLATE}" \
        || fail "the packaged Nginx template has no certificate marker."
    grep -Fq 'ssl_certificate_key /etc/nginx/keys/nginx-nopass.key;' "${SPRING_TEMPLATE}" \
        || fail "the packaged Nginx template has no certificate-key marker."

    escaped_domain="$(escape_sed_replacement "${DOMAIN}")"
    escaped_certificate="$(escape_sed_replacement "${TLS_CERTIFICATE_PATH}")"
    escaped_key="$(escape_sed_replacement "${TLS_CERTIFICATE_KEY_PATH}")"
    tmp="${SPRING_CONFIG}.tmp"

    sed \
        -e "s|server_name localhost;|server_name ${escaped_domain};|g" \
        -e "s|ssl_certificate /etc/nginx/keys/nginx.crt;|ssl_certificate ${escaped_certificate};|" \
        -e "s|ssl_certificate_key /etc/nginx/keys/nginx-nopass.key;|ssl_certificate_key ${escaped_key};|" \
        "${SPRING_TEMPLATE}" > "${tmp}"
    mv "${tmp}" "${SPRING_CONFIG}"
}

validate_domain
normalize_boolean

if [[ "${LETSENCRYPT_ENABLED}" == "true" ]]; then
    TLS_CERTIFICATE_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    TLS_CERTIFICATE_KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    certificate_mode="Let's Encrypt"
else
    TLS_CERTIFICATE_PATH="${NGINX_TLS_CERTIFICATE_PATH:-/etc/nginx/keys/nginx.crt}"
    TLS_CERTIFICATE_KEY_PATH="${NGINX_TLS_CERTIFICATE_KEY_PATH:-/etc/nginx/keys/nginx-nopass.key}"
    certificate_mode="operator-managed"
fi

validate_certificate_path "TLS certificate" "${TLS_CERTIFICATE_PATH}"
validate_certificate_path "TLS private key" "${TLS_CERTIFICATE_KEY_PATH}"
render_spring_config

echo "Starting production Nginx for ${DOMAIN} with ${certificate_mode} TLS."
nginx -t

if [[ "${NGINX_CONFIG_TEST_ONLY:-false}" == "true" ]]; then
    exit 0
fi

exec nginx -g 'daemon off;'
