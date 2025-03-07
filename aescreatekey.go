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
import "ep11go/ep11"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInit(3,19) 
 
      keyTemplate := []*ep11.Attribute{
                ep11.NewAttribute(C.CKA_VALUE_LEN,16 ),
                ep11.NewAttribute(C.CKA_UNWRAP, false),
                ep11.NewAttribute(C.CKA_ENCRYPT, true),
      }


	var aeskey ep11.KeyBlob

       	aeskey, _ = ep11.GenerateKey(target,
                	[]*ep11.Mechanism{ep11.NewMechanism(C.CKM_AES_KEY_GEN, nil)},
	                keyTemplate)
	fmt.Println("Generated Key:", hex.EncodeToString(aeskey))
}
