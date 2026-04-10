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
import "log"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
       	hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")
       	if hsmTarget == "" {
         log.Fatalf("EP11_IBM_TARGET_HSM not set")
    	}
	target := ep11.HsmInit(hsmTarget) 

        publicKeyTemplate := ep11.Attributes{
		C.CKA_IBM_PARAMETER_SET:  C.CKP_IBM_ML_DSA_87,
                C.CKA_VERIFY:     true,
        }
        privateKeyTemplate := ep11.Attributes{
                C.CKA_SIGN:     true,
        }

	pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_IBM_ML_DSA_KEY_PAIR_GEN, nil), publicKeyTemplate,privateKeyTemplate)

        if err != nil   {
                fmt.Println(err)
        } else {
		fmt.Printf("Private Key: %x\n\n", sk)
		fmt.Printf("Public Key: %x\n", pk)
	}
}
