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
//	"encoding/hex"
	"os"
	"strconv"
	"log"
	"strings"
)


// Map of CP numbers to their names
var cpNames = map[int]string{
    0:  "ADD_CPBS",
    1:  "DELETE_CPBS",
    2:  "SIGN_ASYMM",
    3:  "SIGN_SYMM",
    4:  "SIGVERIFY_SYMM",
    5:  "ENCRYPT_SYMM",
    6:  "DECRYPT_ASYMM",
    7:  "DECRYPT_SYMM",
    8:  "WRAP_ASYMM",
    9:  "WRAP_SYMM",
    10: "UNWRAP_ASYMM",
    11: "UNWRAP_SYMM",
    12: "KEYGEN_ASYMM",
    13: "KEYGEN_SYMM",
    14: "RETAINKEYS",
    15: "SKIP_KEYTESTS",
    16: "NON_ATTRBOUND",
    17: "MODIFY_OBJECTS",
    18: "RNG_SEED",
    19: "ALG_RAW_RSA",
    20: "ALG_NFIPS2009",
    21: "ALG_NBSI2009",
    22: "KEYSZ_HMAC_ANY",
    23: "KEYSZ_BELOW80BIT",
    24: "KEYSZ_80BIT",
    25: "KEYSZ_112BIT",
    26: "KEYSZ_128BIT",
    27: "KEYSZ_192BIT",
    28: "KEYSZ_256BIT",
    29: "KEYSZ_RSA65536",
    30: "ALG_RSA",
    31: "ALG_DSA",
    32: "ALG_EC",
    33: "ALG_EC_BPOOLCRV",
    34: "ALG_EC_NISTCRV",
    35: "ALG_NFIPS2011",
    36: "ALG_NBSI2011",
    37: "USER_SET_TRUSTED",
    38: "ALG_SKIP_CROSSCHK",
    39: "WRAP_CRYPT_KEYS",
    40: "SIGN_CRYPT_KEYS",
    41: "WRAP_SIGN_KEYS",
    42: "USER_SET_ATTRBOUND",
    43: "ALLOW_PASSPHRASE",
    44: "WRAP_STRONGER_KEY",
    45: "WRAP_WITH_RAW_SPKI",
    46: "ALG_DH",
    47: "DERIVE",
    48: "ALLOW_NONSESSION",
    55: "ALG_EC_25519",
    60: "ALG_EC_SECGCRV",
    61: "ALG_NBSI2017",
    62: "EMV",
    63: "EMV_MIX",
    64: "CPACF_PK",
    65: "ALG_PQC",
    66: "BTC",
    67: "ECDSA_OTHER",
    68: "ALG_NFIPS2021",
    69: "ALG_NFIPS2024",
    70: "COMPAT_LEGACY_SHA3",
    71: "DSA_PARAMETER_GEN",
    72: "DERIVE_NON_AB_KEYS",
    73: "ALLOW_LOGIN_PRE_F2021",
    74: "ALG_RSA_OAEP",
    75: "ALLOW_COMBINED_EXTRACT",
    76: "ALG_EC_PAIRING_FRIENDLY",
}


var cpByName = func() map[string]int {
    m := make(map[string]int, len(cpNames))
    for k, v := range cpNames {
        m[v] = k
    }
    return m
}()

// DecodeCPs returns the names of active CPs in the given []byte
func DecodeCPs(data []byte) []string {
    var active []string
    for i, b := range data {
        for bit := 0; bit < 8; bit++ {
            if b&(0x80>>bit) != 0 {
                cpNum := i*8 + bit
                if name, ok := cpNames[cpNum]; ok {
                    active = append(active, name)
                } else {
    //                active = append(active, fmt.Sprintf("Unknown_CP_%d", cpNum))
                }
            }
        }
    }
    return active
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

// SetCPMaskByName sets the bit for the named CP
func SetCPMaskByName(mask []byte, name string) error {
    cp, ok := cpByName[name]
    if !ok {
        return fmt.Errorf("unknown CP %q", name)
    }

    byteIdx := cp / 8
    bitIdx := cp % 8

    if byteIdx >= len(mask) {
        return fmt.Errorf("CP %d out of range", cp)
    }

    mask[byteIdx] |= (0x80 >> bitIdx)
    return nil
}

func ctrlPointOpcode(action string) (uint32, error) {
    switch action {
    case "add":
        return C.XCP_ADM_DOM_CTRLPOINT_ADD, nil
    case "del":
        return C.XCP_ADM_DOM_CTRLPOINT_DEL, nil
    default:
        return 0, fmt.Errorf("invalid action %q (use add or del)", action)
    }
}

func main() {
	 if len(os.Args) < 4 {
                fmt.Fprintf(os.Stderr,
                        "usage: %s <control-domain> <domain> <add|del|list> <controlpoint> [options]\n",
                        os.Args[0],
                )
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
	action := os.Args[3]

	switch action {
	case "list":
	    resp, err := ep11.AdminQuery(target, domain,C.XCP_ADMQ_DOM_CTRLPOINTS)
	    if err != nil {
	        fmt.Println(err)
	        return
	    }
	
	    fmt.Println("Active CPs:")
	    for _, cp := range DecodeCPs(resp.Response) {
	        fmt.Println(cp)
	    }
	    return
	
	case "add", "del":
	    if len(os.Args) < 5 {
	        fmt.Println("missing control point name")
	        return
	    }
	    keyBytes, err := ep11.LoadKeyBytes(os.Args[5:])
            if err != nil {
                log.Fatal(err)
		return
            }

	    param := strings.ToUpper(os.Args[4])
	
	    opcode, err := ctrlPointOpcode(action)
	    if err != nil {
	        fmt.Println(err)
	        return
	    }
	
	    cps := make([]byte, 16) // full padded CP mask
	
	    if err := SetCPMaskByName(cps, param); err != nil {
	        fmt.Println(err)
	        return
	    }
	
	    resp, err := ep11.AdminCommand(
	        target,
	        domain,
	        opcode,
	        cps,
	        [][]byte{keyBytes},
	    )
	    if err != nil {
	        fmt.Println(err)
	        return
	    }
	
	    fmt.Println("Active CPs:")
	    for _, cp := range DecodeCPs(resp.Response) {
	        fmt.Println(cp)
	    }
	    return
	
	default:
	    fmt.Printf("unknown action %q (use add, del, or list)\n", action)
	    return
	}

}
