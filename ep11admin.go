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
	"encoding/hex"
	"os"
	"strconv"
	"log"
)

// ExtractSKIs parses a payload of concatenated SHA-256 SKIs
// and returns a slice of hex-encoded SKIs.
func ExtractSKIs(payload []byte) []string {
    const skiSize = 32
    count := len(payload) / skiSize

    skis := make([]string, 0, count)

    for i := 0; i < count; i++ {
        start := i * skiSize
        end := start + skiSize
        skis = append(skis, hex.EncodeToString(payload[start:end]))
    }

    // Optional: handle trailing/partial data
    if len(payload)%skiSize != 0 {
        remainder := payload[count*skiSize:]
        fmt.Printf("Trailing/Partial Data (%d bytes): %x\n", len(remainder), remainder)
    }

    return skis
}

func addAdmin(target ep11.Target_t, domain uint32, cert []byte) error {

	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_ADMIN_LOGIN,cert,nil)        
//	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_ADMIN_LOGIN,cert1Bytes,nil)        
        if err != nil {    
            fmt.Println(err)
        }
	admins:= ExtractSKIs(resp.Response)
	fmt.Println("Upload admin list:")
 	for _, a := range admins {
                        fmt.Println(a)
        }
        return nil
}
 
func removeAdmin(target ep11.Target_t, domain uint32, ski []byte) error {
        // EP11 admin remove logic
	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_ADMIN_LOGOUT,ski,nil)        
//	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_ADMIN_LOGOUT,ski,nil)        
        if err != nil {    
            fmt.Println(err)
        }
	admins:= ExtractSKIs(resp.Response)
	fmt.Println("Upload admin list:")
 	for _, a := range admins {
                        fmt.Println(a)
        }
        return nil
}
 
func listAdmins(target ep11.Target_t, domain uint32) ([]string, error)  {
        // EP11 admin list logic
	resp , err := ep11.AdminQuery(target,domain, C.XCP_ADMQ_DOMADMIN)        
        if err != nil {    
            return nil, err
        }
	return ExtractSKIs(resp.Response),nil
	
}

func main() {
        if len(os.Args) < 4 {
                fmt.Fprintf(os.Stderr,
                        "usage: %s <control-domain> <domain> <add|list|remove> [options]\n",
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
        
        action := os.Args[3]
        args   := os.Args[4:]
        
        target := ep11.HsmInit(controlDomain)
        
        switch action {
        
        case "add":
                certBytes, err := ep11.LoadCertBytes(args)
                if err != nil {
                        log.Fatal(err)
                }
        
                if err := addAdmin(target, domain, certBytes); err != nil {
                        log.Fatal(err)
                }
        
        case "remove":
                skiBytes, err := ep11.LoadSKIBytes(args)
                if err != nil {
                        log.Fatal(err)
                }
        
                if err := removeAdmin(target, domain, skiBytes); err != nil {
                        log.Fatal(err)
                }
        
        case "list":
                admins, err := listAdmins(target, domain)
                if err != nil {
                        log.Fatal(err)
                }
        
                for _, a := range admins {
                        fmt.Println(a)
                }
        
        default:
                log.Fatalf("unknown action: %q (expected add, list, or remove)", action)
        }
}
