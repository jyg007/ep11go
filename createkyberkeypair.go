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
       target := ep11.HsmInit("3.19") 
 
       kyberStrengthParam, err := asn1.Marshal(ep11.OIDKyberR2High) 

        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

       publicKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:          C.CKO_PUBLIC_KEY,
                C.CKA_IBM_PQC_PARAMS: kyberStrengthParam,
                C.CKA_ENCRYPT:     true,
                C.CKA_DERIVE:     true,

        }
        privateKeyTemplate := ep11.Attributes{
                C.CKA_EXTRACTABLE: false,
                C.CKA_DECRYPT:     true,
                C.CKA_DERIVE:     true,
                C.CKA_CLASS:   C.CKO_PRIVATE_KEY,
        }


	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_IBM_KYBER, nil), publicKeyTemplate,privateKeyTemplate)

        if err != nil   {
                        fmt.Println(err)
        } else {
		fmt.Println("Private Key:", hex.EncodeToString(sk))
		fmt.Println("\nPublic Key:", hex.EncodeToString(pk))
	}
}
