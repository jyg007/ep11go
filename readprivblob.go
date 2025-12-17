package main

import (
	"encoding/binary"
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

func (c *Cursor) off() int { return c.pos }

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

/* ---------- Boolean attributes decoding ---------- */

type attrFlag struct {
	mask uint32
	name string
}

var attrFlags = []attrFlag{
	{0x00000001, "XCP_BLOB_EXTRACTABLE"},
	{0x00000002, "XCP_BLOB_NEVER_EXTRACTABLE"},
	{0x00000004, "XCP_BLOB_MODIFIABLE"},
	{0x00000008, "XCP_BLOB_NEVER_MODIFIABLE"},
	{0x00000010, "XCP_BLOB_RESTRICTABLE"},
	{0x00000020, "XCP_BLOB_LOCAL"},
	{0x00000040, "XCP_BLOB_ATTRBOUND"},
	{0x00000080, "XCP_BLOB_USE_AS_DATA"},
	{0x00000100, "XCP_BLOB_SIGN"},
	{0x00000200, "XCP_BLOB_SIGN_RECOVER"},
	{0x00000400, "XCP_BLOB_DECRYPT"},
	{0x00000800, "XCP_BLOB_ENCRYPT"},
	{0x00001000, "XCP_BLOB_DERIVE"},
	{0x00002000, "XCP_BLOB_UNWRAP"},
	{0x00004000, "XCP_BLOB_WRAP"},
	{0x00008000, "XCP_BLOB_VERIFY"},
	{0x00010000, "XCP_BLOB_VERIFY_RECOVER"},
	{0x00020000, "XCP_BLOB_TRUSTED"},
	{0x00040000, "XCP_BLOB_WRAP_W_TRUSTED"},
	{0x00080000, "XCP_BLOB_RETAINED"},
	{0x00100000, "XCP_BLOB_ALWAYS_RETAINED"},
	{0x00200000, "XCP_BLOB_PROTKEY_EXTRACTABLE"},
	{0x00400000, "XCP_BLOB_PROTKEY_NEVER_EXTRACTABLE"},
	{0x00800000, "XCP_BLOB_MLS"},
}

func decodeAttributes(v uint64) []string {
	var out []string
	lo := uint32(v & 0xffffffff)

	for _, f := range attrFlags {
		if lo&f.mask != 0 {
			out = append(out, f.name)
		}
	}
	if len(out) == 0 {
		out = append(out, "<none>")
	}
	return out
}

/* ---------- Mode decoding ---------- */

func decodeMode(v uint64) []string {
	var modes []string
	if v&1 != 0 {
		modes = append(modes, "XCP_ADMS_FIPS2009")
	}
	if v&2 != 0 {
		modes = append(modes, "XCP_ADMS_BSI2009")
	}
	if v&4 != 0 {
		modes = append(modes, "XCP_ADMS_FIPS2011")
	}
	if v&8 != 0 {
		modes = append(modes, "XCP_ADMS_BSI2011")
	}
	if len(modes) == 0 {
		modes = append(modes, "<none>")
	}
	return modes
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

	// Boolean attributes
	attrOff := c.off()
	attrRaw := c.read(8)
	attrVal := binary.BigEndian.Uint64(attrRaw)
	attrNames := decodeAttributes(attrVal)

	fmt.Printf("%-40s off=%04d len=8\n", "3. Boolean attributes", attrOff)
	fmt.Printf("  %s\n", hex.EncodeToString(attrRaw))
	fmt.Printf("  decoded: %v\n\n", attrNames)

	// Mode identification
	modeOff := c.off()
	modeRaw := c.read(8)
	modeVal := binary.BigEndian.Uint64(modeRaw)
	modeNames := decodeMode(modeVal)

	fmt.Printf("%-40s off=%04d len=8\n", "4. Mode identification", modeOff)
	fmt.Printf("  %s\n", hex.EncodeToString(modeRaw))
	fmt.Printf("  decoded: %v\n\n", modeNames)

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

