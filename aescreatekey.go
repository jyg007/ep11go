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
import "ep11go/ep11"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInit("3.19") 
 
      keyTemplate := ep11.Attributes{
	      C.CKA_VALUE_LEN: 16 ,
		C.CKA_UNWRAP: false,
		C.CKA_ENCRYPT: true,
      }


	var aeskey ep11.KeyBlob

       	aeskey, _ = ep11.GenerateKey(target,
                	ep11.Mech(C.CKM_AES_KEY_GEN, nil),
	                keyTemplate)
	fmt.Printf("Generated Key: %x\n", aeskey)
}
