package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki
#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "ep11go/ep11"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInit("3.19") 
 
      keyTemplate := ep11.Attributes{
	      C.CKA_VALUE_LEN: 32 ,
		C.CKA_UNWRAP: true,
		C.CKA_WRAP: true,
		C.CKA_ENCRYPT: true,
                C.CKA_EXTRACTABLE: true,
      }

	var aeskey ep11.KeyBlob
	var csum []byte

       	aeskey, csum ,_ = ep11.GenerateKey(target,
                	ep11.Mech(C.CKM_AES_KEY_GEN, nil),
	                keyTemplate)

	fmt.Printf("Generated Key: %x\n", aeskey)
	fmt.Printf("Csum: %x\n", csum)
}
