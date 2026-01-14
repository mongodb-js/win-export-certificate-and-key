#!/usr/bin/env bash
set -euo pipefail

OUT="testkeys"
DAYS=99999 # Hopefully enough time so regenerating the certs is not a PITA
PASS="pass"

mkdir -p "$OUT"

# -------------------------
# 1) CA: Banana Corp
# -------------------------
openssl genrsa -out "$OUT/privateKey.key" 2048

openssl req -x509 -new -nodes \
  -key "$OUT/privateKey.key" \
  -sha256 -days "$DAYS" \
  -subj "/CN=Banana Corp" \
  -out "$OUT/certificate.pem"

cp "$OUT/certificate.pem" "$OUT/certificate.crt"

# -------------------------
# 2) TLS server cert (localhost), signed by CA
# -------------------------
openssl genrsa -out "$OUT/testserver-privkey.pem" 2048

openssl req -new \
  -key "$OUT/testserver-privkey.pem" \
  -subj "/CN=localhost" \
  -out "$OUT/testserver.csr"

cat > "$OUT/testserver.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req \
  -in "$OUT/testserver.csr" \
  -CA "$OUT/certificate.pem" \
  -CAkey "$OUT/privateKey.key" \
  -CAcreateserial \
  -days "$DAYS" \
  -sha256 \
  -extfile "$OUT/testserver.ext" \
  -out "$OUT/testserver-certificate.pem"

rm -f "$OUT/testserver.csr" "$OUT/testserver.ext" "$OUT/certificate.srl"

# -------------------------
# 3) Client cert (Internet Widgits Pty Ltd), PKCS#12
# -------------------------
openssl genrsa -out "$OUT/client-privkey.pem" 2048

openssl req -new \
  -key "$OUT/client-privkey.pem" \
  -subj "/CN=Internet Widgits Pty Ltd" \
  -out "$OUT/client.csr"

cat > "$OUT/client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF

openssl x509 -req \
  -in "$OUT/client.csr" \
  -CA "$OUT/certificate.pem" \
  -CAkey "$OUT/privateKey.key" \
  -CAcreateserial \
  -days "$DAYS" \
  -sha256 \
  -extfile "$OUT/client.ext" \
  -out "$OUT/client-certificate.pem"

openssl pkcs12 -export \
  -inkey "$OUT/client-privkey.pem" \
  -in "$OUT/client-certificate.pem" \
  -out "$OUT/certificate.pfx" \
  -passout "pass:${PASS}" \
  -certpbe AES-256-CBC \
  -keypbe AES-256-CBC
  -macalg sha1 \
  -iter 2048 \
  -provider default \
  -provider legacy

rm -f \
  "$OUT/client.csr" \
  "$OUT/client.ext" \
  "$OUT/client-privkey.pem" \
  "$OUT/client-certificate.pem" \
  "$OUT/certificate.srl"

echo "Thumbprint of the certificate for test.js:"
openssl pkcs12 -in testkeys/certificate.pfx -passin pass:pass -nodes -provider default -provider legacy \
  | openssl x509 -noout -fingerprint -sha1 \
  | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f'
