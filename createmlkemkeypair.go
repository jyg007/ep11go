package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
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

        publicKeyTemplate := ep11.Attributes{
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
		fmt.Printf("Private Key [descapsulation key] cryptogram: %x\n\n",sk)
		fmt.Printf("Public Key [encapsulation key]: %x\n", pk)
	}
}
