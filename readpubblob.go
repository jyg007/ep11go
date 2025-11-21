package main

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
)

// ExtractSPKIAndMAC splits an EP11 export blob into SPKI and MACed trailer.
func ExtractSPKIAndMAC(blob []byte) (spki []byte, maced []byte, err error) {
	if len(blob) < 4 {
		return nil, nil, errors.New("blob too short")
	}

	if blob[0] != 0x30 {
		return nil, nil, errors.New("blob does not start with ASN.1 SEQUENCE (0x30)")
	}

	var headerLen int
	var contentLen int

	// Parse ASN.1 length field
	switch {
	case blob[1] < 0x80:
		headerLen = 2
		contentLen = int(blob[1])

	default:
		numLenBytes := int(blob[1] & 0x7f)
		if 2+numLenBytes > len(blob) {
			return nil, nil, errors.New("invalid ASN.1 long form length")
		}
		headerLen = 2 + numLenBytes

		contentLen = 0
		for i := 0; i < numLenBytes; i++ {
			contentLen = (contentLen << 8) | int(blob[2+i])
		}
	}

	spkiTotalLen := headerLen + contentLen
	if spkiTotalLen > len(blob) {
		return nil, nil, errors.New("ASN.1 length exceeds blob size")
	}

	spki = blob[:spkiTotalLen]
	maced = blob[spkiTotalLen:]

	// Optional: verify ASN.1 correctness
	var dummy asn1.RawValue
	if _, err := asn1.Unmarshal(spki, &dummy); err != nil {
		return nil, nil, fmt.Errorf("SPKI ASN.1 validation failed: %v", err)
	}

	return spki, maced, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <hexstring>\n", os.Args[0])
		os.Exit(1)
	}

	hexBlob := os.Args[1]
	blob, err := hex.DecodeString(hexBlob)
	if err != nil {
		fmt.Println("Invalid hex:", err)
		os.Exit(1)
	}

	spki, maced, err := ExtractSPKIAndMAC(blob)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	fmt.Println("===== SPKI =====")
	fmt.Println(hex.EncodeToString(spki))

	fmt.Println("===== MACED TRAILER =====")
	fmt.Println(hex.EncodeToString(maced))
}

