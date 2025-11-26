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
import "os"

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
       target := ep11.HsmInit("3.19") 
 
       var err error

       aeskey, _ := hex.DecodeString(os.Args[1])

       data,_ := hex.DecodeString(os.Args[2])

//       ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
       ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveED25519)

       privateKeyECTemplate := ep11.Attributes{
                    C.CKA_KEY_TYPE:  C.CKK_EC,
                   C.CKA_EC_PARAMS:ecParameters,
                    C.CKA_SIGN:true,
//                    C.CKA_DERIVE:true,   // not set for ED25519 !
                    C.CKA_CLASS: C.CKO_PRIVATE_KEY,
                    C.CKA_EXTRACTABLE: true,
        }
        
	var eckey ep11.KeyBlob
	var csum []byte
        iv := make([]byte, 16)

	eckey,csum,err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			data,
			privateKeyECTemplate,
		)

	if err != nil {
                fmt.Println(err)
	} else {
	        fmt.Println("\nECKey Blob :", hex.EncodeToString(eckey))
	        fmt.Println("\nChecksum :", hex.EncodeToString(csum))
	}
}
