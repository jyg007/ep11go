package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>
#include <openssl/evp.h>
#include <stdlib.h>

*/
import "C"
import "ep11go/ep11"
import (
	"encoding/binary"
	"fmt"
	"encoding/hex"
	"encoding/asn1"
	"strings"
	"os"
//	"time"
	"strconv"
)

const (
    XCP_LOG_STATE_BYTES = 32
    XCP_WKID_BYTES      = 16
    MIN_RECORD_BYTES    = 290
)

// flag masks (32-bit big-endian)
const (
    FLAG_WK_PRESENT           = 0x80000000
    FLAG_COMPLIANCE_PRESENT   = 0x40000000
    FLAG_FINAL_WK_PRESENT     = 0x20000000
    FLAG_FINAL_TIME_PRESENT   = 0x01000000
    FLAG_KEY_REC0_PRESENT     = 0x10000000
    FLAG_KEY0_COMPLIANCE      = 0x08000000
    FLAG_KEY_REC1_PRESENT     = 0x04000000
    FLAG_KEY_REC2_PRESENT     = 0x02000000
    FLAG_SALT0_PRESENT        = 0x00800000
    FLAG_SALT1_PRESENT        = 0x00400000
    FLAG_SALT2_PRESENT        = 0x00200000
    FLAG_EVENT_DETAILS_PRESENT= 0x00100000
    FLAG_PRF_PRESENT          = 0x00080000
)

func displayAuditRecord(record []byte) {

var logEvents = map[uint16]string{
    0x0000: "XCP_LOGEV_QUERY",
    0x0001: "XCP_LOGEV_FUNCTION",
    0x0002: "XCP_LOGEV_ADMFUNCTION",
    0x0003: "XCP_LOGEV_STARTUP",
    0x0004: "XCP_LOGEV_SHUTDOWN",
    0x0005: "XCP_LOGEV_SELFTEST",
    0x0006: "XCP_LOGEV_DOM_IMPORT",
    0x0007: "XCP_LOGEV_DOM_EXPORT",
    0x0008: "XCP_LOGEV_FAILURE",
    0x0009: "XCP_LOGEV_GENERATE",
    0x000A: "XCP_LOGEV_REMOVE",
    0x000B: "XCP_LOGEV_SPECIFIC",
    0x000C: "XCP_LOGEV_STATE_IMPORT",
    0x000D: "XCP_LOGEV_STATE_EXPORT",
}


	// Event type example at offset 66..68
	eventCode := binary.BigEndian.Uint16(record[66:68])
	eventName, ok := logEvents[eventCode]
	if !ok {
		eventName = "UNKNOWN_EVENT"
	}

    fmt.Printf("Offset | Field                     | Bytes | Value\n")
    fmt.Println("----------------------------------------------------------")

    fmt.Printf("%-6d | %-25s | %-5d | 0x%02x ('%c')\n", 0, "Record type", 1, record[0], record[0])
    fmt.Printf("%-6d | %-25s | %-5d | %d\n", 1, "Record version", 1, record[1])
    fmt.Printf("%-6d | %-25s | %-5d | %d\n", 2, "Record bytecount", 2, binary.BigEndian.Uint16(record[2:4]))
    fmt.Printf("%-6d | %-25s | %-5d | %d\n", 4, "Sequence number", 6, binary.BigEndian.Uint64(append([]byte{0, 0}, record[4:10]...)))
    fmt.Printf("%-6d | %-25s | %-5d | %d\n", 10, "Extended time_t", 6, binary.BigEndian.Uint64(append([]byte{0, 0}, record[10:16]...)))
    fmt.Printf("%-6d | %-25s | %-5d | %s\n", 16, "Initial hash state", XCP_LOG_STATE_BYTES, hex.EncodeToString(record[16:48]))
    fmt.Printf("%-6d | %-25s | %-5d | %s\n", 48, "Module identifier", 16, hex.EncodeToString(record[48:64]))
    fmt.Printf("%-6d | %-25s | %-5d | %d\n", 64, "Audit instance", 2, binary.BigEndian.Uint16(record[64:66]))
    fmt.Printf("%-6d | %-25s | %-5d | %s\n", 66, "Event type", 2, eventName)
    fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", 68, "Firmware identifier", 4, binary.BigEndian.Uint32(record[68:72]))

    // Extract flags
    flags := binary.BigEndian.Uint32(record[72:76])
    fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", 72, "Event flags", 4, flags)
/*    fmt.Println("Flags set:")

    flagDescriptions := []struct{
        mask uint32
        desc string
    }{
        {FLAG_WK_PRESENT, "WK is present"},
        {FLAG_COMPLIANCE_PRESENT, "Compliance field present"},
        {FLAG_FINAL_WK_PRESENT, "Final WK present"},
        {FLAG_FINAL_TIME_PRESENT, "Final time present"},
        {FLAG_KEY_REC0_PRESENT, "Key record 0 present"},
        {FLAG_KEY0_COMPLIANCE, "Key 0 compliance present"},
        {FLAG_KEY_REC1_PRESENT, "Key record 1 present"},
        {FLAG_KEY_REC2_PRESENT, "Key record 2 present"},
        {FLAG_SALT0_PRESENT, "Salt field 0 present"},
        {FLAG_SALT1_PRESENT, "Salt field 1 present"},
        {FLAG_SALT2_PRESENT, "Salt field 2 present"},
        {FLAG_EVENT_DETAILS_PRESENT, "Event details/reason present"},
        {FLAG_PRF_PRESENT, "Deterministic PRF present"},
    }

    for _, f := range flagDescriptions {
        if flags & f.mask != 0 {
            fmt.Printf("  - %s\n", f.desc)
        }
    }
*/
    fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", 76, "Function identifier", 4, binary.BigEndian.Uint32(record[76:80]))
    fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", 80, "Hosting domain", 4, binary.BigEndian.Uint32(record[80:84]))

    // Optional fields
    offset := 84
    if flags & FLAG_WK_PRESENT != 0 {
        fmt.Printf("%-6d | %-25s | %-5d | %s\n", offset, "Original WK identifier", XCP_WKID_BYTES, hex.EncodeToString(record[offset:offset+XCP_WKID_BYTES]))
        offset += XCP_WKID_BYTES
    }
    if flags & FLAG_FINAL_WK_PRESENT != 0 {
        fmt.Printf("%-6d | %-25s | %-5d | %s\n", offset, "Final WK identifier", XCP_WKID_BYTES, hex.EncodeToString(record[offset:offset+XCP_WKID_BYTES]))
        offset += XCP_WKID_BYTES
    }
    if flags & FLAG_SALT0_PRESENT != 0 {
        fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", offset, "Salt[0]", 4, binary.BigEndian.Uint32(record[offset:offset+4]))
        offset += 4
    }
    if flags & FLAG_SALT1_PRESENT != 0 {
        fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", offset, "Salt[1]", 4, binary.BigEndian.Uint32(record[offset:offset+4]))
        offset += 4
    }
    if flags & FLAG_SALT2_PRESENT != 0 {
        fmt.Printf("%-6d | %-25s | %-5d | 0x%08x\n", offset, "Salt[2]", 4, binary.BigEndian.Uint32(record[offset:offset+4]))
        offset += 4
    }
    if flags & FLAG_PRF_PRESENT != 0 {
        fmt.Printf("%-6d | %-25s | %-5d | %s\n", offset, "Deterministic PRF", 8, hex.EncodeToString(record[offset:offset+8]))
        offset += 8
    }

// Safe handling of final hash state
if len(record) >= XCP_LOG_STATE_BYTES {
    start := len(record) - XCP_LOG_STATE_BYTES
    fmt.Printf("%-6d | %-25s | %-5d | %s\n",
        start,
        "Final hash state",
        XCP_LOG_STATE_BYTES,
        hex.EncodeToString(record[start:]))
} else {
    fmt.Printf("%-6d | %-25s | %-5d | %s\n",
        0,
        "Final hash state",
        len(record),
        hex.EncodeToString(record))
}
}

func printSKIs(payload []byte) {
    const skiSize = 32
    count := len(payload) / skiSize

    fmt.Printf("Detected %d full SKIs (SHA-256):\n", count)

    for i := 0; i < count; i++ {
        start := i * skiSize
        end := start + skiSize
        fmt.Printf("Admin %d SKI: %x\n", i+1, payload[start:end])
    }

    // Check for trailing data (if the payload was 92 instead of 96)
    if len(payload)%skiSize != 0 {
        remainder := payload[count*skiSize:]
        fmt.Printf("Trailing/Partial Data (%d bytes): %x\n", len(remainder), remainder)
    }
}

func PrintAdminAttributes(data []byte) {
    if len(data)%8 != 0 {
        fmt.Errorf("invalid attribute buffer length: %d", len(data))
	return
    }

    for i := 0; i < len(data); i += 8 {
        index := binary.BigEndian.Uint32(data[i : i+4])
        value := binary.BigEndian.Uint32(data[i+4 : i+8])

        fmt.Printf("%-25s = 0x%08x (%d)\n",
            adminAttrName(index),
            value,
            value,
        )
    }

}

type Permission struct {
	Name  string
	Value uint32
}

func AnalysePermissions(perm uint32) {

	permissions := []Permission{
		// Base permissions
		{"XCP_ADMP_WK_IMPORT", 0x00000001},
		{"XCP_ADMP_WK_EXPORT", 0x00000002},
		{"XCP_ADMP_WK_1PART", 0x00000004},
		{"XCP_ADMP_WK_RANDOM", 0x00000008},
		{"XCP_ADMP_1SIGN", 0x00000010},
		{"XCP_ADMP_CP_1SIGN", 0x00000020},
		{"XCP_ADMP_ZERO_1SIGN", 0x00000040},
		{"XCP_ADMP_NO_DOMAIN_IMPRINT", 0x00000080},
		{"XCP_ADMP_STATE_IMPORT", 0x00000100},
		{"XCP_ADMP_STATE_EXPORT", 0x00000200},
		{"XCP_ADMP_STATE_1PART", 0x00000400},
		{"XCP_ADMP_NO_EPX", 0x00000800},
		{"XCP_ADMP_NO_EPXVM", 0x00001000},
		{"XCP_ADMP_DO_NOT_DISTURB", 0x00002000},

		// Change permissions
		{"XCP_ADMP_CHG_WK_IMPORT", 0x00010000},
		{"XCP_ADMP_CHG_WK_EXPORT", 0x00020000},
		{"XCP_ADMP_CHG_WK_1PART", 0x00040000},
		{"XCP_ADMP_CHG_WK_RANDOM", 0x00080000},
		{"XCP_ADMP_CHG_SIGN_THR", 0x00100000},
		{"XCP_ADMP_CHG_REVOKE_THR", 0x00200000},
		{"XCP_ADMP_CHG_1SIGN", 0x00400000},
		{"XCP_ADMP_CHG_CP_1SIGN", 0x00800000},
		{"XCP_ADMP_CHG_ZERO_1SIGN", 0x01000000},
		{"XCP_ADMP_CHG_ST_IMPORT", 0x02000000},
		{"XCP_ADMP_CHG_ST_EXPORT", 0x04000000},
		{"XCP_ADMP_CHG_ST_1PART", 0x08000000},
		{"XCP_ADMP_CHG_NO_EPX", 0x20000000},
		{"XCP_ADMP_CHG_NO_EPXVM", 0x40000000},
		{"XCP_ADMP_CHG_DO_NOT_DISTURB", 0x80000000},
	}

	var enabled []string

	for _, p := range permissions {
		if perm&p.Value != 0 {
			fmt.Printf("✔ %s (0x%08X)\n", p.Name, p.Value)
			enabled = append(enabled, p.Name)
		}
	}

	// Print all enabled permissions as a single | separated string
	if len(enabled) > 0 {
		fmt.Println("\nAll enabled permissions:")
		fmt.Println(strings.Join(enabled, " | "))
	}
}


func adminAttrName(index uint32) string {
    switch index {
    case 1:
        return "XCP_ADMINT_SIGN_THR"
    case 2:
        return "XCP_ADMINT_REVOKE_THR"
    case 3:
        return "XCP_ADMINT_PERMS"
    case 4:
        return "XCP_ADMINT_MODE"
    case 5:
        return "XCP_ADMINT_STD"
    case 6:
        return "XCP_ADMINT_PERMS_EXT01"
    case 7:
        return "XCP_ADMINT_GEN_KTYPES"
    case 8:
        return "XCP_ADMINT_ECC_KTYPES"
    case 9:
        return "XCP_ADMINT_DIL_KTYPES"
    case 10:
        return "XCP_ADMINT_ADM_COMPL"
    default:
        return fmt.Sprintf("UNKNOWN_%d", index)
    }
}


 type ResponseBlock struct {
      Domain           []byte `asn1:"octet"`
      ModuleIdentifier []byte  `asn1:"octet"`
      Response         []byte  `asn1:"octet"`
  }


func main() {
        if len(os.Args) != 3 {
                fmt.Fprintf(os.Stderr, "usage: %s <control-domain> <domain>\n", os.Args[0])
                os.Exit(1)
        }

        // 1) Control domain (e.g. "3.19")
        controlDomain := os.Args[1]

        // 2) Target domain (e.g. 16)
        domain64, err := strconv.ParseUint(os.Args[2], 10, 32)
        domain := uint32(domain64)
        if err != nil {
                fmt.Fprintf(os.Stderr, "invalid domain: %v\n", err)
                os.Exit(1)
        }

        target := ep11.HsmInit(controlDomain) 
	

        
	resp , err := ep11.AdminQuery(target,domain, C.XCP_ADMQ_AUDIT_STATE)        
        if err != nil {    
            fmt.Println(err)
        }

	numEvents := binary.BigEndian.Uint32(resp.Response[:4])
	fmt.Printf("Number of audit events: %d\n", numEvents)

	for i := uint32(1); i < numEvents; i++ {	
		var payload[4]byte
	        binary.BigEndian.PutUint32(payload[:], i)
		resp , err := ep11.AdminQueryWithPayload(target,domain, C.XCP_ADMQ_AUDIT_STATE,payload[:])        
	        if err != nil {    
	            fmt.Println(err)
	        }
		fmt.Println()
	    	var rspBlock ResponseBlock
	    	_, err = asn1.Unmarshal(resp.Response, &rspBlock)
	     	if err != nil {
        	     fmt.Errorf("Failed to unmarshall response: %w", err)
			return
	     	}

		displayAuditRecord(rspBlock.Response)
	}

/*
	fmt.Printf("AdmFunctionId:    %X\n", resp.AdmFunctionId)
	fmt.Printf("Domain:           %X\n", resp.Domain)
	fmt.Printf("ModuleIdentifier: %X\n", resp.ModuleIdentifier)
	fmt.Printf("TransactionCtr:   %X\n", resp.TransactionCtr)
	fmt.Printf("ResponseCode:     %X ", resp.ResponseCode)
*/
	
//	fmt.Printf("Response:          %X\n", resp.Response)
//	fmt.Println("---------------------------------")

}
