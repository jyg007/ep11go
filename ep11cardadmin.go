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
	"strings"
	"encoding/binary"
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
//                        fmt.Printf("✔ %s (0x%08X)\n", p.Name, p.Value)
                        enabled = append(enabled, p.Name)
                }
	}
        // Print all enabled permissions as a single | separated string
        if len(enabled) > 0 {
 //               fmt.Println("\nAll enabled permissions:")
                fmt.Println(strings.Join(enabled, " | "))
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


func addAdmin(target ep11.Target_t, domain uint32, cert []byte) error {

	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_ADMIN_LOGIN,cert,nil)        
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
	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_ADMIN_LOGOUT,ski,nil)        
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
	resp , err := ep11.AdminQuery(target,domain, C.XCP_ADMQ_ADMIN)        
        if err != nil {    
            return nil, err
        }
	return ExtractSKIs(resp.Response),nil
	
}

func setattr(target ep11.Target_t, domain uint32, keyBytes []byte) ( []byte, error)  {
    attrs := []ep11.AdminAttribute{
                {Attribute: C.XCP_ADMINT_SIGN_THR , Value: 1}, 
                {Attribute: C.XCP_ADMINT_REVOKE_THR, Value: 1},
                {Attribute: C.XCP_ADMINT_PERMS, Value: uint32(C.XCP_ADMP_1SIGN | C.XCP_ADMP_CHG_SIGN_THR | C.XCP_ADMP_CHG_REVOKE_THR | C.XCP_ADMP_CHG_1SIGN | C.XCP_ADMP_CHG_ZERO_1SIGN | C.XCP_ADMP_CHG_ST_IMPORT | C.XCP_ADMP_CHG_ST_EXPORT | C.XCP_ADMP_CHG_ST_1PART | C.XCP_ADMP_CHG_DO_NOT_DISTURB)}, 
        }

        attrsBytes      := ep11.GenerateAttributeBytes(attrs)

        resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_SET_ATTR,attrsBytes,[][]byte{keyBytes})        
        if err != nil {    
            fmt.Println(err)
	    return nil, err
        }

	return resp.Response, nil
}

func getattr(target ep11.Target_t, domain uint32) ( []byte, error)  {
        resp , err := ep11.AdminQuery(target,domain, C.XCP_ADMQ_ATTRS)        
        if err != nil {    
            fmt.Println(err)
	    return nil, err
        }

	return resp.Response, nil
}

func main() {
        if len(os.Args) < 4 {
                fmt.Fprintf(os.Stderr,
                        "usage: %s <control-domain> <domain> <add|list|remove|setattr|getattr> [options]\n",
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
        
        case "setattr":
                keyBytes, err := ep11.LoadKeyBytes(args)
                if err != nil {
                        log.Fatal(err)
                }
        
                param, err := setattr(target, domain,keyBytes)
                if err != nil {
                        log.Fatal(err)
                }
	        PrintAdminAttributes(param)

        case "getattr":
                param, err := getattr(target, domain)
                if err != nil {
                        log.Fatal(err)
                }
	        PrintAdminAttributes(param)


        
        default:
                log.Fatalf("unknown action: %q (expected add, list, or remove)", action)
        }
}
