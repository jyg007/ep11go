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
//	"encoding/hex"
	"strings"
	"os"
	"strconv"
)

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
	if (index==3) {
		AnalysePermissions(value)
	}
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
//			fmt.Printf("✔ %s (0x%08X)\n", p.Name, p.Value)
			enabled = append(enabled, p.Name)
		}
	}

	// Print all enabled permissions as a single | separated string
	if len(enabled) > 0 {
		fmt.Printf("    %s\n",strings.Join(enabled, " | "))
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
	
// **********************************************************************************************************************
// QUERY ATTRIBUTES
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOM_ATTRS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	fmt.Printf("Domain attributes\n")
	PrintAdminAttributes(resp.Response)
*/


// **********************************************************************************************************************
// LIST ADMIN SKIs
// **********************************************************************************************************************
	resp , err := ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOMADMIN)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	printSKIs(resp.Response)

	 
// **********************************************************************************************************************
// SCAN CARD ATTRIBUTES
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_ATTRS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	fmt.Printf("Adapter attributes\n")
	PrintAdminAttributes(resp.Response)
	
// **********************************************************************************************************************
// SCAN DOMAIN ATTRIBUTES
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOM_ATTRS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Println()
	fmt.Printf("Domain attributes\n")
	PrintAdminAttributes(resp.Response)
	
// **********************************************************************************************************************
// SCAN MEK MKVPS
// **********************************************************************************************************************
	resp , err = ep11.AdminQuery(target,domain, C.XCP_ADMQ_WK_ORIGINS)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Printf("\nKey Parts pattern         %x\n", resp.Response)
	
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
