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
	"log"
)


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
// ZERORIZE DOMAIN
// **********************************************************************************************************************
	_ , err = ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_ZEROIZE,nil,[][]byte{keyBytes})        
        if err != nil {    
            fmt.Println(err)
        } else {
	 fmt.Printf("Domain %d zerofied\n", domain)
	}
	 
}
