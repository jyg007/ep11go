package main

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "encoding/hex"
import "encoding/asn1"
import "ep11go/ep11"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
       target := ep11.HsmInit(3,19) 
 
       ecParameters, err := asn1.Marshal(ep11.OIDBLS12_381ET)
       fmt.Println(hex.EncodeToString(ecParameters))
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true, 
		    C.CKA_DERIVE:true, 
		    C.CKA_IBM_USE_AS_DATA: true,
		    C.CKA_KEY_TYPE: C.CKK_EC,

        }
	privateKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_SIGN:true,
		    C.CKA_PRIVATE:true,
		    C.CKA_SENSITIVE:true,
		    C.CKA_IBM_USE_AS_DATA:true,
		    C.CKA_KEY_TYPE: C.CKK_EC,

        }

	pk, sk , err  := ep11.GenerateKeyPair(target, []*ep11.Mechanism{ep11.NewMechanism(C.CKM_EC_KEY_PAIR_GEN, nil)}, publicKeyECTemplate,privateKeyECTemplate)

        if err != nil   {
                        fmt.Println(err)
        } else {
		fmt.Println("Private Key:", hex.EncodeToString(sk))
		fmt.Println("\nPublic Key:", hex.EncodeToString(pk))
	}
}
