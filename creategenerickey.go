package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "encoding/hex"
import "ep11go/ep11"

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInit("3.19") 
 
        var err error

	keyTemplate := ep11.Attributes{
                C.CKA_CLASS:C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:C.CKK_GENERIC_SECRET,
                C.CKA_VALUE_LEN: 32,
                C.CKA_IBM_ATTRBOUND: true,
         }
        

	var key ep11.KeyBlob
	var csum []byte
	key,csum, err = ep11.GenerateKey(target, 
			ep11.Mech(C.CKM_GENERIC_SECRET_KEY_GEN, nil),
			keyTemplate,
		)

	if err != nil {
                        fmt.Println(err)
	} else {
	        fmt.Println("\nGeneric Key Blob: ", hex.EncodeToString(key))
	        fmt.Println("\nCsum: ", hex.EncodeToString(csum))
	}
}
