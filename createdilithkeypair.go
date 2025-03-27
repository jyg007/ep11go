package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
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
 
       dilithiumStrengthParam, err := asn1.Marshal(ep11.OIDDilithiumR3VHigh) 

        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

       publicKeyTemplate := ep11.Attributes{
                C.CKA_IBM_PQC_PARAMS: dilithiumStrengthParam,
                C.CKA_VERIFY:     true,
        }
        privateKeyTemplate := ep11.Attributes{
                C.CKA_SENSITIVE: true,
                C.CKA_SIGN:     true,
                C.CKA_PRIVATE:     true,
        }

	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_IBM_DILITHIUM, nil), publicKeyTemplate,privateKeyTemplate)

        if err != nil   {
                        fmt.Println(err)
        } else {
		fmt.Println("Private Key:", hex.EncodeToString(sk))
		fmt.Println("\nPublic Key:", hex.EncodeToString(pk))
	}
}
