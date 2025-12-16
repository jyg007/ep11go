package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

const MAC_LEN = 32

type Cursor struct {
	data []byte
	pos  int
}

func (c *Cursor) off() int {
	return c.pos
}

func (c *Cursor) read(n int) []byte {
	if c.pos+n > len(c.data) {
		log.Fatalf("read beyond end at offset %d (+%d)", c.pos, n)
	}
	b := c.data[c.pos : c.pos+n]
	c.pos += n
	return b
}

func dump(name string, off int, b []byte) {
	fmt.Printf("%-40s off=%04d len=%5d\n", name, off, len(b))
	fmt.Printf("  %s\n\n", hex.EncodeToString(b))
}

func decodeHex(s string) []byte {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\t', '\r':
			return -1
		default:
			return r
		}
	}, s)

	b, err := hex.DecodeString(clean)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage: %s <hex-blob>\n", os.Args[0])
		os.Exit(1)
	}

	c := &Cursor{data: decodeHex(os.Args[1])}

	fmt.Println("----- MACed (clear header): --------------------------------------------")

	dump("1. Session identifier", c.off(), c.read(32))
	dump("2. WK identifier", c.off(), c.read(16))
	dump("3. Boolean attributes", c.off(), c.read(8))
	dump("4. Mode identification", c.off(), c.read(8))

	fmt.Println("----- IV ---------------------------------------------------------------")

	dump("5. Structure version", c.off(), c.read(2))
	dump("6. IV", c.off(), c.read(14))

	fmt.Println("----- encrypted blob (opaque) ------------------------------------------")

	encStart := c.off()
	encLen := len(c.data) - encStart - MAC_LEN
	if encLen <= 0 {
		log.Fatalf("invalid blob: no encrypted region")
	}

	dump("Encrypted region (7–14, opaque)", encStart, c.read(encLen))

	fmt.Println("----- end of encrypted region ------------------------------------------")
	fmt.Println("----- end of MACed region ----------------------------------------------")

	dump("15. MAC", c.off(), c.read(MAC_LEN))

	if c.off() != len(c.data) {
		fmt.Printf("WARNING: %d trailing bytes\n", len(c.data)-c.off())
	}
}

