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
	"encoding/asn1"
)


func main() {

	var err error /*
	pk, _  := hex.DecodeString(os.Args[1])
	mac, _  := hex.DecodeString(os.Args[2])
	key, _  := hex.DecodeString(os.Args[3])*/


	target := ep11.HsmInit("3.19")

      keyTemplate := ep11.Attributes{
                C.CKA_CLASS:C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:C.CKK_GENERIC_SECRET,
                C.CKA_VALUE_LEN: 32,
                C.CKA_IBM_ATTRBOUND: true,
         }
        

        mac,csum, err := ep11.GenerateKey(target, 
                        ep11.Mech(C.CKM_GENERIC_SECRET_KEY_GEN, nil),
                        keyTemplate,
                )
	_=csum
        if err != nil {
                        fmt.Println(err)
        } 

     ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)

        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

        publicKeyECTemplate := ep11.Attributes{
                    C.CKA_EC_PARAMS:ecParameters,
                    C.CKA_VERIFY:true, 
        //            C.CKA_WRAP: true,
                    C.CKA_ENCRYPT: true,
                    C.CKA_CLASS: C.CKO_PUBLIC_KEY,
                    C.CKA_IBM_ATTRBOUND: true,
        }
        privateKeyECTemplate := ep11.Attributes{
                    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_SENSITIVE: true,
   //                 C.CKA_DECRYPT: true,
     //               C.CKA_UNWRAP: true,
                    C.CKA_CLASS: C.CKO_PRIVATE_KEY,
   //                 C.CKA_EXTRACTABLE: false, //required for wrap
                    C.CKA_IBM_ATTRBOUND: true,
        }

        pk, sk , err  := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)

        if err != nil   {
                        fmt.Println(err)
			return
        } 

    keyTemplate2 := ep11.Attributes{
              C.CKA_VALUE_LEN: 32 ,
                C.CKA_DECRYPT: true,
                C.CKA_ENCRYPT: true,
                C.CKA_EXTRACTABLE: true,
               C.CKA_IBM_ATTRBOUND: true,
      }


        aeskey, csum2 ,_ := ep11.GenerateKey(target,
                        ep11.Mech(C.CKM_AES_KEY_GEN, nil),
                        keyTemplate2)
_=pk
        var blobWrapped ep11.KeyBlob
        blobWrapped, err = ep11.WrapKey2(target,
                        ep11.Mech(C.CKM_IBM_ATTRIBUTEBOUND_WRAP,nil),
                        sk,
                        aeskey,
			mac,
                )

	if err != nil {
		panic(fmt.Errorf("Wrap key error: %s", err))
	}
                
        fmt.Printf("%x\n", blobWrapped)
	_=sk
	_=csum2
}
