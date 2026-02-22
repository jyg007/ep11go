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
//	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"log"
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

func main() {
	if len(os.Args) < 3 {
	        fmt.Fprintf(os.Stderr,
	                "usage: %s <control-domain> <domain> --key-file <file>] [--key-hex <hex>],\n",
	                os.Args[0],
	        )
	        os.Exit(1)
	}
	
	controlDomain := os.Args[1]
	
	domain64, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil {
	        log.Fatalf("invalid domain: %v", err)
	}
	domain := uint32(domain64)
	
	target := ep11.HsmInit(controlDomain)
	
	args   := os.Args[3:]
	keyBytes, err := ep11.LoadKeyBytes(args)
        if err != nil {
                  log.Fatal(err)
		  return
        }

// **********************************************************************************************************************
// SET ATTRIBUTES
// **********************************************************************************************************************
	attrs := []ep11.AdminAttribute{
        	{Attribute: C.XCP_ADMINT_SIGN_THR , Value: 1}, 
        	{Attribute: C.XCP_ADMINT_REVOKE_THR, Value: 1},
        	{Attribute: C.XCP_ADMINT_PERMS, Value: uint32(C.XCP_ADMP_WK_RANDOM | C.XCP_ADMP_WK_IMPORT | C.XCP_ADMP_WK_EXPORT | C.XCP_ADMP_WK_1PART | C.XCP_ADMP_1SIGN | C.XCP_ADMP_CHG_1SIGN | C.XCP_ADMP_CP_1SIGN | C.XCP_ADMP_CHG_SIGN_THR | C.XCP_ADMP_CHG_REVOKE_THR | C.XCP_ADMP_DO_NOT_DISTURB)}, 
    	}

	attrsBytes	:= ep11.GenerateAttributeBytes(attrs)

	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_SET_ATTR,attrsBytes,[][]byte{keyBytes})        
        if err != nil {    
            fmt.Println(err)
        }
//	PrintAdminAttributes(resp.Response)
	fmt.Println()
	
// **********************************************************************************************************************
//  GENERATE MEK  One for Current and one for New register
// **********************************************************************************************************************
	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_GEN_WK,nil,[][]byte{keyBytes})        
        if err != nil {    
            fmt.Println(err)
        } else {
		fmt.Printf("MEK verification pattern     %x\n", resp.Response)
   	}
}
