/*******************************************************************************
* Copyright 2022 IBM Corp.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*******************************************************************************/

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
import (
	"ep11go/ep11"
	"fmt"
	"os"
	"encoding/hex"
)


func main() {

	var err error
	blob, _  := hex.DecodeString(os.Args[1])

	target := ep11.HsmInit("3.19")


        // Create an ephemeral AES key
        aeskeyTemplate := ep11.Attributes{
                C.CKA_VALUE_LEN: 256/8 ,
                C.CKA_UNWRAP: true,
                C.CKA_WRAP: true,
                C.CKA_ENCRYPT: true,
                C.CKA_DECRYPT: true,
                C.CKA_EXTRACTABLE: true,
         }
         aeskey, _,err := ep11.GenerateKey(target,
                        ep11.Mech(C.CKM_AES_KEY_GEN, nil),
                        aeskeyTemplate)



        iv, _ :=ep11.GenerateRandom(target,16 )

        var blobWrapped ep11.KeyBlob
        blobWrapped,err = ep11.WrapKey(target,
                        ep11.Mech(C.CKM_AES_CBC_PAD, iv),
                        aeskey,
                        blob,
                )

	if err != nil {
		panic(fmt.Errorf("Wrap key error: %s", err))
	}
                
       privateKeyECTemplate := ep11.Attributes{
                    C.CKA_KEY_TYPE:  C.CKK_EC,
//                    C.CKA_EC_PARAMS:ecParameters,
                    C.CKA_CLASS: C.CKO_PRIVATE_KEY,
        }
        
	var csum []byte
	_,csum,err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			blobWrapped,
			privateKeyECTemplate,
		)

	if err != nil {
                fmt.Println(err)
	} else {
	        fmt.Println("\nPubKey Blob :", hex.EncodeToString(csum))
	}
}
