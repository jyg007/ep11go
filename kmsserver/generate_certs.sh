#!/bin/bash
set -e

# Output directory
OUTDIR=certs
mkdir -p $OUTDIR

# 1️⃣ Generate CA
openssl genrsa -out $OUTDIR/ca.key 4096
openssl req -x509 -new -nodes -key $OUTDIR/ca.key -sha256 -days 3650 \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=MyOrg/OU=CA/CN=MyRootCA" \
    -out $OUTDIR/ca.crt

# 2️⃣ Generate Server key & CSR
openssl genrsa -out $OUTDIR/server.key 4096
openssl req -new -key $OUTDIR/server.key \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=MyOrg/OU=Server/CN=localhost" \
    -out $OUTDIR/server.csr

# Sign server CSR with CA
openssl x509 -req -in $OUTDIR/server.csr -CA $OUTDIR/ca.crt -CAkey $OUTDIR/ca.key \
    -CAcreateserial -out $OUTDIR/server.crt -days 3650 -sha256

# 3️⃣ Generate Client key & CSR
openssl genrsa -out $OUTDIR/client.key 4096
openssl req -new -key $OUTDIR/client.key \
    -subj "/C=US/ST=CA/L=SanFrancisco/O=MyOrg/OU=Client/CN=client1" \
    -out $OUTDIR/client.csr

# Sign client CSR with CA
openssl x509 -req -in $OUTDIR/client.csr -CA $OUTDIR/ca.crt -CAkey $OUTDIR/ca.key \
    -CAcreateserial -out $OUTDIR/client.crt -days 3650 -sha256

# 4️⃣ Cleanup
rm $OUTDIR/*.csr
rm $OUTDIR/ca.srl

echo "Certificates generated in $OUTDIR:"
ls -1 $OUTDIR

