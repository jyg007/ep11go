package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "os"
import "encoding/hex"
import "ep11go/ep11"
import "strings" 


var ckaNames = map[uint]string{
    uint(C.CKA_SIGN):                "CKA_SIGN",
    uint(C.CKA_VERIFY):              "CKA_VERIFY",
    uint(C.CKA_EXTRACTABLE):         "CKA_EXTRACTABLE",
    uint(C.CKA_NEVER_EXTRACTABLE):   "CKA_NEVER_EXTRACTABLE",
    uint(C.CKA_MODIFIABLE):          "CKA_MODIFIABLE",
    uint(C.CKA_SIGN_RECOVER):        "CKA_SIGN_RECOVER",
    uint(C.CKA_VERIFY_RECOVER):      "CKA_VERIFY_RECOVER",
    uint(C.CKA_WRAP):                "CKA_WRAP",
    uint(C.CKA_UNWRAP):              "CKA_UNWRAP",
    uint(C.CKA_ENCRYPT):             "CKA_ENCRYPT",
    uint(C.CKA_DECRYPT):             "CKA_DECRYPT",
    uint(C.CKA_DERIVE):              "CKA_DERIVE",
    uint(C.CKA_WRAP_WITH_TRUSTED):   "CKA_WRAP_WITH_TRUSTED",
    uint(C.CKA_TRUSTED):             "CKA_TRUSTED",
    uint(C.CKA_LOCAL):               "CKA_LOCAL",
}

// printAttributes prints EP11/PKCS#11 attributes in two columns,
// converting boolean byte values to true/false for readability.
func printAttributes(res map[uint]interface{}, ckaNames map[uint]string) {
    // Header
    fmt.Printf("%-30s %s\n", "Attribute", "Value")
    fmt.Println(strings.Repeat("-", 45))

    for k, v := range res {
        // Get human-readable name
        name, ok := ckaNames[k]
        if !ok {
            name = fmt.Sprintf("%d", k)
        }

        var valStr string

        switch val := v.(type) {
        case []byte:
            // If single-byte boolean (01/00), print true/false
            if len(val) == 1 && (val[0] == 0x00 || val[0] == 0x01) {
                valStr = fmt.Sprintf("%t", val[0] == 0x01)
            } else {
                // Otherwise print full hex
                valStr = hex.EncodeToString(val)
            }
        default:
            // fallback for other types
            valStr = fmt.Sprintf("%v", val)
        }

        fmt.Printf("%-30s %s\n", name, valStr)
    }
}

func main() { 
       target := ep11.HsmInit("3.19") 
       key := make([]byte, hex.DecodedLen(len(os.Args[1])))
       hex.Decode(key, []byte(os.Args[1]))


       attributeList := ep11.Attributes{
   	C.CKA_EXTRACTABLE: true,
   	C.CKA_NEVER_EXTRACTABLE: true,
   	C.CKA_MODIFIABLE: true,
   	C.CKA_SIGN: true,
   	C.CKA_SIGN_RECOVER: true,
   	C.CKA_VERIFY: true,
   	C.CKA_VERIFY_RECOVER: true,
   	C.CKA_WRAP: true,
   	C.CKA_UNWRAP: true,
   	C.CKA_ENCRYPT: true,
   	C.CKA_DECRYPT: true,
   	C.CKA_DERIVE: true,
   	C.CKA_WRAP_WITH_TRUSTED: true,
   	C.CKA_TRUSTED: true,
   	C.CKA_LOCAL: true,
        }

      res, rc  := ep11.GetAttributeValue(target, key, attributeList)


        if rc!= nil   {
                fmt.Println(rc)
        } else {
		resUint := make(map[uint]interface{})
		for k, v := range res {
		    resUint[uint(k)] = v
		}
		printAttributes(resUint, ckaNames)
    	}

}
