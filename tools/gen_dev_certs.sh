#!/bin/bash
# SPDX-License-Identifier: MIT
# gen_dev_certs.sh - generates a throwaway CA + server cert (+ optional
# client cert) for exercising local-api's TLS/mTLS support (ADR-0012)
# without a real CA. NOT for production use - these are self-signed,
# short-lived, and the private keys land on disk in plain PEM.
#
# Usage:
#   tools/gen_dev_certs.sh [output-dir] [extra SAN, e.g. 10.99.0.1]
#
# Produces, in output-dir (default: ./dev-certs):
#   ca.pem, ca-key.pem           - the dev CA (keep ca-key.pem off any
#                                   shared host; only ca.pem is needed by
#                                   bouncers/curl to verify the server)
#   server.pem, server-key.pem   - local-api's TLS cert/key
#     (LOCAL_API_TLS_CERT / LOCAL_API_TLS_KEY)
#   client.pem, client-key.pem   - an optional client cert for mTLS
#     (LAPI_CLIENT_CERT / LAPI_CLIENT_KEY on a bouncer, and set
#     LOCAL_API_TLS_CLIENT_CA=ca.pem on local-api to require it)
set -e

OUT="${1:-dev-certs}"
EXTRA_SAN="${2:-}"
DAYS=365

mkdir -p "$OUT"
cd "$OUT"

SAN="DNS:localhost,IP:127.0.0.1"
if [ -n "$EXTRA_SAN" ]; then
    SAN="$SAN,IP:$EXTRA_SAN"
fi

echo "[*] Generating dev CA (ca.pem / ca-key.pem) ..."
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ca-key.pem -out ca.pem -days "$DAYS" \
    -subj "/CN=xdp-engine-dev-ca" 2>/dev/null

echo "[*] Generating local-api server cert (server.pem / server-key.pem, SAN=$SAN) ..."
openssl req -newkey rsa:2048 -nodes \
    -keyout server-key.pem -out server.csr \
    -subj "/CN=local-api" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out server.pem -days "$DAYS" \
    -extfile <(printf "subjectAltName=%s" "$SAN") 2>/dev/null
rm -f server.csr

echo "[*] Generating optional bouncer client cert (client.pem / client-key.pem, for mTLS) ..."
openssl req -newkey rsa:2048 -nodes \
    -keyout client-key.pem -out client.csr \
    -subj "/CN=xdp-engine-bouncer" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out client.pem -days "$DAYS" 2>/dev/null
rm -f client.csr ca.srl

chmod 600 ca-key.pem server-key.pem client-key.pem

echo ""
echo "[+] Done. Files written to $OUT/:"
ls -1
echo ""
echo "    Start local-api with TLS only:"
echo "      LOCAL_API_TOKEN=... LOCAL_API_TLS_CERT=$OUT/server.pem LOCAL_API_TLS_KEY=$OUT/server-key.pem \\"
echo "        ./local-api engine.db 8088"
echo ""
echo "    ...or with mTLS required too:"
echo "      LOCAL_API_TOKEN=... LOCAL_API_TLS_CERT=$OUT/server.pem LOCAL_API_TLS_KEY=$OUT/server-key.pem \\"
echo "        LOCAL_API_TLS_CLIENT_CA=$OUT/ca.pem ./local-api engine.db 8088"
echo ""
echo "    Point a bouncer at it:"
echo "      ./bouncer-nft --lapi-url https://127.0.0.1:8088 --lapi-token ... \\"
echo "        --lapi-ca-cert $OUT/ca.pem \\"
echo "        --lapi-client-cert $OUT/client.pem --lapi-client-key $OUT/client-key.pem  # only if mTLS is required"
echo ""
echo "See docs/local-api.md and docs/adr/0012-tls-local-api.md for the full writeup."
