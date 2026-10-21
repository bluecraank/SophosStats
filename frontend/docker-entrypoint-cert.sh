#!/bin/sh
# Erzeugt ein selbstsigniertes Zertifikat, falls keines nach /etc/nginx/certs gemountet wurde.
set -e
CERT_DIR=/etc/nginx/certs
if [ ! -f "$CERT_DIR/tls.crt" ] || [ ! -f "$CERT_DIR/tls.key" ]; then
    echo "Kein Zertifikat gefunden – erzeuge selbstsigniertes Zertifikat"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -newkey rsa:3072 -days 825 \
        -subj "/CN=${TLS_CN:-sophosstats}" \
        -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" >/dev/null 2>&1
fi
