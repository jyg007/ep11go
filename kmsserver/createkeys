#!/bin/bash

# Client certificate/key
CERT="certs/client.crt"
KEY="certs/client.key"

# API endpoint
URL="https://localhost:4433/key"

# Loop to create 200 keys
for i in $(seq 1 200); do
    PUB="PubKey${i}"
    PRV="PrivKeySecret${i}"
    COIN="BTC"
    SOURCE="user"
    TYPE="independent"

    # JSON payload
    DATA=$(cat <<EOF
{
  "pub": "${PUB}",
  "prv": "${PRV}",
  "coin": "${COIN}",
  "source": "${SOURCE}",
  "type": "${TYPE}"
}
EOF
)

    # Send POST request
    RESPONSE=$(curl -sk \
      --cert "$CERT" \
      --key "$KEY" \
      -H "Content-Type: application/json" \
      -d "$DATA" \
      "$URL")

    echo "Created key $i: $RESPONSE"
done

