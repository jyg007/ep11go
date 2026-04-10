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
import "log"
import "os"

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 

   	hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")

    	if hsmTarget == "" {
        	log.Fatalf("EP11_IBM_TARGET_HSM not set")
    	}

   	 target := ep11.HsmInit(hsmTarget)

 
       mlkemStrengthParam, err := asn1.Marshal(ep11.OIDML_KEM_1024) 

       if err != nil {
              panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
       }

       publicKeyTemplate := ep11.Attributes{
                C.CKA_IBM_PQC_PARAMS: 	mlkemStrengthParam,
                C.CKA_IBM_PARAMETER_SET:  C.CKP_IBM_ML_KEM_1024,
                C.CKA_DERIVE:     	true,

        }

        privateKeyTemplate := ep11.Attributes{
                C.CKA_DERIVE:     	true,
        }

	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_IBM_ML_KEM_KEY_PAIR_GEN, nil), publicKeyTemplate,privateKeyTemplate)

        if err != nil   {
                        fmt.Println(err)
        } else {
		fmt.Println("Private Key [descapsulation key] cryptogram:", hex.EncodeToString(sk))
		fmt.Println("\nPublic Key [encapsulation key]:", hex.EncodeToString(pk))
	}
}
