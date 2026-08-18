package main

import (
	"encoding/asn1"
	"encoding/hex"
        "encoding/pem"
	"fmt"
	"os"
)

// readASN1OctetString reads an OCTET STRING (tag 0x04) at the start of buf.
// Returns the value bytes and remaining slice.
func readASN1OctetString(buf []byte) ([]byte, []byte, error) {
	if len(buf) < 2 {
		return nil, nil, fmt.Errorf("buffer too short for OCTET STRING")
	}
	if buf[0] != 0x04 {
		return nil, nil, fmt.Errorf("expected OCTET STRING (0x04), got 0x%02X", buf[0])
	}
	length := int(buf[1])
	if length&0x80 != 0 { // long form
		numBytes := length & 0x7f
		if len(buf) < 2+numBytes {
			return nil, nil, fmt.Errorf("buffer too short for long-form length")
		}
		length = 0
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(buf[2+i])
		}
		buf = buf[1+numBytes:]
	} else {
		buf = buf[2:]
	}

	if len(buf) < length {
		return nil, nil, fmt.Errorf("buffer too short for content")
	}
	value := buf[:length]
	rest := buf[length:]
	return value, rest, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <hexstring>\n", os.Args[0])
		return
	}

	hexStr := os.Args[1]
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Total blob length: %d bytes\n\n", len(data))

	//------------------------------------------------------------------
	// Step 1: Parse SPKI
	//------------------------------------------------------------------
	var spki asn1.RawValue
	rest, err := asn1.Unmarshal(data, &spki)
	if err != nil {
		panic(fmt.Errorf("Failed to parse SPKI DER: %v", err))
	}
	spkiLen := len(data) - len(rest)
	fmt.Printf("SPKI detected (%d bytes):\n%s\n\n", spkiLen, hex.EncodeToString(data[:spkiLen]))

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data[:spkiLen],
	}

	fmt.Printf("%s", pem.EncodeToMemory(block))

	//------------------------------------------------------------------
	// Step 2: Parse MACed OCTET STRING fields
	//------------------------------------------------------------------
	buf := rest

	wkid, buf, err := readASN1OctetString(buf)
	if err != nil {
		panic(fmt.Errorf("WKID: %v", err))
	}

	sessionID, buf, err := readASN1OctetString(buf)
	if err != nil {
		panic(fmt.Errorf("SessionID: %v", err))
	}

	salt, buf, err := readASN1OctetString(buf)
	if err != nil {
		panic(fmt.Errorf("Salt: %v", err))
	}

	mode, buf, err := readASN1OctetString(buf)
	if err != nil {
		panic(fmt.Errorf("Mode: %v", err))
	}

	// Remaining bytes: attributes + MAC
	if len(buf) < 32 {
		panic("Not enough bytes for MAC")
	}
	mac := buf[len(buf)-32:]
	attributes := buf[:len(buf)-32]

	//------------------------------------------------------------------
	// Step 3: Print results
	//------------------------------------------------------------------
	fmt.Println("===== MACed Fields (OCTET STRING) =====")
	fmt.Printf("WKID (16 bytes):        %s\n", hex.EncodeToString(wkid))
	fmt.Printf("SessionID (32 bytes):   %s\n", hex.EncodeToString(sessionID))
	fmt.Printf("Salt (8 bytes):         %s\n", hex.EncodeToString(salt))
	fmt.Printf("Mode (8 bytes):         %s\n", hex.EncodeToString(mode))
	fmt.Printf("Attributes (%d bytes):  %s\n", len(attributes), hex.EncodeToString(attributes))
	fmt.Printf("MAC (32 bytes):         %s\n", hex.EncodeToString(mac))
}
