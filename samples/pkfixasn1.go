package main

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <hex-encoded-public-key-or-SPKI>\n", os.Args[0])
		os.Exit(1)
	}

	inputHex := os.Args[1]

	data, err := hex.DecodeString(inputHex)
	if err != nil {
		log.Fatalf("Invalid hex input: %v", err)
	}

	// Try to parse input as SPKI. If not SPKI, treat as raw 32-byte Ed25519 public key.
	var rawKey []byte

	type spki struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}

	var parsed spki
	_, err = asn1.Unmarshal(data, &parsed)
	if err == nil && len(parsed.SubjectPublicKey.Bytes) == 32 {
		// Input is SPKI
		rawKey = parsed.SubjectPublicKey.Bytes
	} else {
		// Treat input as raw 32-byte Ed25519 public key
		if len(data) != 32 {
			log.Fatalf("Input is not a valid SPKI and not a 32-byte Ed25519 key")
		}
		rawKey = data
	}

	// Ed25519 OID per RFC 8410
	ed25519OID := asn1.ObjectIdentifier{1, 3, 101, 112}

	// Build the correct AlgorithmIdentifier (OID only, NO params)
	alg, err := asn1.Marshal(struct {
		Algorithm asn1.ObjectIdentifier
	}{Algorithm: ed25519OID})
	if err != nil {
		log.Fatalf("Failed to marshal AlgorithmIdentifier: %v", err)
	}

	// Build valid SPKI
	spkiOut := struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}{
		Algorithm: asn1.RawValue{
			FullBytes: alg,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     rawKey,
			BitLength: len(rawKey) * 8,
		},
	}

	der, err := asn1.Marshal(spkiOut)
	if err != nil {
		log.Fatalf("Failed to marshal final SPKI: %v", err)
	}

	// Print DER as hex
	fmt.Printf("SPKI DER (hex):\n%x\n\n", der)

	// Convert to PEM
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})

	fmt.Printf("PEM output:\n%s\n", pemBytes)
}

