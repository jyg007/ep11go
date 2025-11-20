package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "encoding/asn1"
import "ep11go/ep11"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
       target := ep11.HsmInit("3.19") 
 
       ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)

        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true, 
		    C.CKA_DERIVE:true, 
		    C.CKA_CLASS: C.CKO_PUBLIC_KEY,
        }
	privateKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_SIGN:true,
		    C.CKA_DERIVE:true, 
		    C.CKA_CLASS: C.CKO_PRIVATE_KEY,
		    C.CKA_EXTRACTABLE: true, //required for wrap
        }

	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)

        if err != nil   {
                        fmt.Println(err)
        } else {
		fmt.Printf("Private Key:\n%x\n\n", sk)
		fmt.Printf("\nPublic Key:\n%x\n", pk)
	}
}
