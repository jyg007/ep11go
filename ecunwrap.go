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

         if len(data) < 16 {
                fmt.Fprintln(os.Stderr, "Error: ciphertext too short to contain IV")
                os.Exit(1)
        }
        iv := data[:16]
        ciphertext := data[16:]

       ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)

       privateKeyECTemplate := ep11.Attributes{
                    C.CKA_KEY_TYPE:  C.CKK_EC,
                    C.CKA_EC_PARAMS:ecParameters,
                    C.CKA_SIGN:true,
                    C.CKA_DERIVE:true, 
                    C.CKA_CLASS: C.CKO_PRIVATE_KEY,
                    C.CKA_EXTRACTABLE: false,
        }
/*
privateKeyECTemplate := ep11.Attributes{
    C.CKA_EC_PARAMS:   ecParameters,   // required

    // Required key-lifecycle attributes for unwrap
    C.CKA_TOKEN:       trueVal,
    C.CKA_PRIVATE:     trueVal,
    C.CKA_SENSITIVE:   trueVal,
    C.CKA_EXTRACTABLE: falseVal,

    // Optional but recommended for EC
    C.CKA_SIGN:        trueVal,
    C.CKA_DERIVE:      trueVal,
}
*/
        var eckey ep11.KeyBlob
	eckey,err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			ciphertext,
			privateKeyECTemplate,
		)

	if err != nil {
                fmt.Println(err)
	} else {
	        fmt.Println("\nECKey Blob :", hex.EncodeToString(eckey))
	}
}
