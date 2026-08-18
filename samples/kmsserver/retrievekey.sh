#!/bin/bash

# Client certificate/key
CERT="certs/client.crt"
KEY="certs/client.key"

# API endpoint
URL="https://localhost:4433/key"

# Loop to retrieve 200 keys
for i in $(seq 1 200); do
    PUB="pubKey${i}"
    SOURCE="user"

    # Send GET request
    RESPONSE=$(curl -sk \
      --cert "$CERT" \
      --key "$KEY" \
      -G \
      --data-urlencode "pub=${PUB}" \
      --data-urlencode "source=${SOURCE}" \
      "$URL")

    echo "Retrieved key $i ($PUB): $RESPONSE"
done

