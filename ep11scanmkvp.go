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
	"fmt"
	"os"
	"strconv"
)

func main() {
        if len(os.Args) != 3 {
                fmt.Fprintf(os.Stderr, "usage: %s <control-domain> <max nb>\n", os.Args[0])
                os.Exit(1)
        }

        // 1) Control domain (e.g. "3.19")
        controlDomain := os.Args[1]

        // 2) Target domain (e.g. 16)
        max64, err := strconv.ParseUint(os.Args[2], 10, 32)
	max := uint32(max64)
        if err != nil {
                fmt.Fprintf(os.Stderr, "invalid: %v\n", err)
                os.Exit(1)
        }

        target := ep11.HsmInit(controlDomain) 

	
// **********************************************************************************************************************
// SCAN DOMAINS
// **********************************************************************************************************************
for domain := uint32(0); domain <= max; domain++ {
    fmt.Printf("\n--- Domain %d | 0x%x ---\n", domain,domain)

    resp, err := ep11.AdminQuery(target, domain, C.XCP_ADMQ_WK)
    if err != nil {
        fmt.Printf("Error reading current MEK pattern: %v\n", err)
    } else {
        fmt.Printf("Current MEK verification pattern: %x\n", resp.Response)
    }

    resp, err = ep11.AdminQuery(target, domain, C.XCP_ADMQ_NEXT_WK)
    if err != nil {
        fmt.Printf("Error reading next MEK pattern: %v\n", err)
    } else {
        fmt.Printf("Next MEK verification pattern:    %x\n", resp.Response)
    }
}

	 
}
