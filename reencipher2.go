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
import "time"

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInitNonVirtual("3.19") 
      
      keyTemplate := ep11.Attributes{
              C.CKA_VALUE_LEN: 16 ,
                C.CKA_UNWRAP: false,
                C.CKA_ENCRYPT: true,
      } 
        const numKeys = 100000
        var aeskeys []ep11.KeyBlob
        aeskeys = make([]ep11.KeyBlob, numKeys)
        
        startTime := time.Now()
        // Generate 100000 AES keys
        for i := 0; i < numKeys; i++ {
                aeskey, _ := ep11.GenerateKey(target, ep11.Mech(C.CKM_AES_KEY_GEN, nil), keyTemplate)
                aeskeys[i] = aeskey
        }

        // Time taken for key generation
        generationTime := time.Since(startTime)
        fmt.Printf("Time taken to generate %d keys: %v\n", numKeys,generationTime)

        // Measure the time to reencipher the keys
        startTime = time.Now()

        // Reencipher all 100000 keys
        for i := 0; i < numKeys; i++ {
                _, _ = ep11.Reencipher(target, aeskeys[i])
        }

        // Time taken for reenciphering
        reencipherTime := time.Since(startTime)
        fmt.Printf("Time taken to reencipher %d keys: %v\n", numKeys,reencipherTime)
}

