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

        der,_ := hex.DecodeString(os.Args[1])

       pubECTemplate := ep11.Attributes{
//                   C.CKA_EC_PARAMS:ecParameters,   Surtout ne pas mettre sinon cela provoque une erreur
		    //C.CKA_KEY_TYPE : C.CKK_EC,    Ditto
                    C.CKA_VERIFY:true, 
                    C.CKA_DERIVE:true, 
                    C.CKA_CLASS: C.CKO_PUBLIC_KEY,
        }
        
	var eckey ep11.KeyBlob
	var csum []byte
	eckey,csum,err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_IBM_TRANSPORTKEY, nil),
			[]byte("a") ,
			der,
			pubECTemplate,
		)

	if err != nil {
                fmt.Println(err)
	} else {
	        fmt.Println("\nKey maced ", hex.EncodeToString(eckey))
	        fmt.Println("\nChecksum :", hex.EncodeToString(csum))
	}
}
