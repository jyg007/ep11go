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

        // Generate RSA key pair
        publicExponent := 65537
        keySize := 4096

        publicKeyTemplate := ep11.Attributes{
                C.CKA_ENCRYPT:         true,
                C.CKA_WRAP:            true, // to wrap a key
                C.CKA_MODULUS_BITS:    keySize,
                C.CKA_PUBLIC_EXPONENT: publicExponent,
        }

        privateKeyTemplate := ep11.Attributes{
                C.CKA_PRIVATE:   true,
                C.CKA_SENSITIVE: true,
                C.CKA_DECRYPT:   true,
                C.CKA_UNWRAP:    true, // to unwrap a key
        }
 

	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_RSA_PKCS_KEY_PAIR_GEN, nil), publicKeyTemplate,privateKeyTemplate)

        if err != nil   {
                        fmt.Println(err)
        } else {
		fmt.Printf("Private Key:\n%x\n\n", sk)
		fmt.Printf("\nPublic Key:\n%x\n", pk)
	}

        key,_  := hex.DecodeString(os.Args[1])

        wrapKey ,err  := ep11.WrapKey(target , ep11.Mech(C.CKM_RSA_PKCS_OAEP,ep11.NewOAEPParams(C.CKM_SHA512, C.CKG_MGF1_SHA512,  0, nil )),pk, key) 

        if err != nil {
               fmt.Println(err)
        } else {
		fmt.Printf("\nWrapped Key:\n%x\n", wrapKey)
	}


        unwrapKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:       C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:    C.CKK_GENERIC_SECRET,
                C.CKA_VALUE_LEN:   64,
                C.CKA_WRAP:        false,
                C.CKA_UNWRAP:      false,
                C.CKA_SIGN:        true,
                C.CKA_VERIFY:      true,
                C.CKA_DERIVE:      true,
                C.CKA_IBM_USE_AS_DATA: true,
                C.CKA_EXTRACTABLE: false,
        }
        
        unwrapKey ,err  := ep11.UnWrapKey(target , ep11.Mech(C.CKM_RSA_PKCS_OAEP,ep11.NewOAEPParams(C.CKM_SHA512, C.CKG_MGF1_SHA512,  0, nil )),sk, wrapKey,unwrapKeyTemplate) 

        if err != nil {
               fmt.Println(err)
        } else {
		fmt.Printf("\nUnWrapped Key:\n%x\n", unwrapKey)
	}
}
