package main

import (
	"encoding/hex"
	"fmt"
	"os"
	//	"strconv"
)

const (
	EP11_BLOB_WKID_OFFSET =  32
	XCP_WKID_BYTES        = 128 / 8  
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <hexstring>")
		return
	}

	hexStr := os.Args[1]
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Println("Error decoding hex string:", err)
		return
	}

	if len(data) < EP11_BLOB_WKID_OFFSET+XCP_WKID_BYTES {
		fmt.Println("Input hex string is too short.")
		return
	}

	subData := data[EP11_BLOB_WKID_OFFSET : EP11_BLOB_WKID_OFFSET+XCP_WKID_BYTES]
	fmt.Println("mkvp:", hex.EncodeToString(subData))
}
