package main

/*


#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "ep11go/ep11"
import "os"
import "encoding/hex"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
        target := ep11.HsmInit("3.19") 

        sk, _  := hex.DecodeString(os.Args[1])
        data, _  := hex.DecodeString(os.Args[2])

        unwrapKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:       C.CKO_SECRET_KEY,
             //   C.CKA_KEY_TYPE:    C.CKK_GENERIC_SECRET,
                C.CKA_KEY_TYPE:    C.CKK_AES,
                C.CKA_VALUE_LEN:   32,
                C.CKA_WRAP:        true,
                C.CKA_UNWRAP:      true,
             //   C.CKA_SIGN:        true,
             //   C.CKA_VERIFY:      true,
                C.CKA_ENCRYPT:      true,
             //   C.CKA_DERIVE:      true,
             //   C.CKA_IBM_USE_AS_DATA: true,
                C.CKA_EXTRACTABLE: true,
        }
        
        unwrapKey , csum, err  := ep11.UnWrapKey(target , ep11.Mech(C.CKM_RSA_PKCS_OAEP,ep11.NewOAEPParams(C.CKM_SHA256, C.CKG_MGF1_SHA256,  0, nil )),sk,data,unwrapKeyTemplate) 

        if err != nil {
               fmt.Println(err)
        } else {
		fmt.Printf("\nUnWrapped Key:\n%x\n", unwrapKey)
		fmt.Printf("\nChecksum:\n%x\n", csum)
	}
}
