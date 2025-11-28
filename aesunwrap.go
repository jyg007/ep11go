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
import "os"

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInit("3.19") 
 
        var err error

	aeskey, _ := hex.DecodeString(os.Args[1])

        data,_ := hex.DecodeString(os.Args[2])

        KeyTemplate := ep11.Attributes{
                C.CKA_CLASS:       C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:    C.CKK_AES,
                C.CKA_VALUE_LEN:   32,
                C.CKA_WRAP:        false,
                C.CKA_UNWRAP:      false,
                C.CKA_SIGN:        true,
                C.CKA_VERIFY:      true,
                C.CKA_DERIVE:      true,
                C.CKA_IBM_USE_AS_DATA: true,
                C.CKA_EXTRACTABLE: true,
        }

       // iv := []byte("000000000000000000")
        iv := make([]byte, 16)

	var key ep11.KeyBlob
	var csum []byte
	key,csum,err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_AES_CBC, iv),
			aeskey ,
			data,
			KeyTemplate,
		)

	if err != nil {
                fmt.Println(err)
	} else {
	        fmt.Println("\nKey Blob :", hex.EncodeToString(key))
	        fmt.Println("\nChecksum :", hex.EncodeToString(csum))
	}
}
