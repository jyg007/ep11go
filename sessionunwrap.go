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
 
	var aeskey ep11.KeyBlob
	var Cipher,csum []byte
        var err error

        seed := make([]byte, hex.DecodedLen(len(os.Args[1])))
        hex.Decode(seed, []byte(os.Args[1]))

        seedLen := len(seed)
/*
        if seedLen != 64 {
                panic(fmt.Errorf("Invalid plain secret"))
        }
*/
	keyTemplate := ep11.Attributes{
                C.CKA_VALUE_LEN:16 ,
                C.CKA_UNWRAP: true,
                C.CKA_WRAP: true,
                C.CKA_ENCRYPT: true,
                C.CKA_DECRYPT: true,
                C.CKA_EXTRACTABLE: true,
         }
        iv := []byte("0123456789abcdef")

        aeskey, _ , _ = ep11.GenerateKey(target,
                	ep11.Mech(C.CKM_AES_KEY_GEN, nil),
	                keyTemplate)
	
        Cipher,_ = ep11.EncryptSingle(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			seed,
		)
	unwrapKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:C.CKK_GENERIC_SECRET,
                C.CKA_VALUE_LEN:seedLen ,
                C.CKA_UNWRAP:false,
                C.CKA_WRAP: false,
                C.CKA_SIGN: true,
                C.CKA_VERIFY: true,
                C.CKA_DERIVE: true,
                C.CKA_IBM_USE_AS_DATA: true,
                C.CKA_EXTRACTABLE: false,
         }
        

	var masterseed ep11.KeyBlob
	masterseed,csum , err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			Cipher,
			unwrapKeyTemplate,
		)

	if err != nil {
                        fmt.Println(err)
	} else {
	        fmt.Println("\n Blob:", hex.EncodeToString(masterseed))
	        fmt.Println("\n csum:", hex.EncodeToString(csum))
	}
}
