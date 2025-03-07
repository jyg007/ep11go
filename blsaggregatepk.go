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
       target := ep11.HsmInit(3,19) 
 
       ecParameters, err := asn1.Marshal(ep11.OIDBLS12_381ET)
        // Create an empty slice to hold the final concatenated byte array
        var aggregatePubKeyBytes []byte

        pubKeyElementSize:= uint( 0)
        // Iterate over the command-line arguments (skip the first one, which is the program name)
        for _, arg := range os.Args[1:] {
                // Decode each hex string to bytes
	        var decodedBytes []byte
                decodedBytes, err = hex.DecodeString(arg)


                if pubKeyElementSize==0 {
                        pubKeyElementSize=uint(len(decodedBytes))
                }
                if err != nil {
                        panic(fmt.Errorf("Error decoding hex string %s: %v", arg, err))
                }
                // Append the decoded bytes to the byteArray
                aggregatePubKeyBytes = append(aggregatePubKeyBytes, decodedBytes...)
        }
   
	publicKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true, 
		    C.CKA_DERIVE:true, 
		    C.CKA_IBM_USE_AS_DATA: true,
		    C.CKA_KEY_TYPE: C.CKK_EC,
        }


       Params := ep11.ECAGGParams{    
	       Version:        0,
               Mode:           C.CK_IBM_EC_AGG_BLS12_381_PKEY,
               PerElementSize: pubKeyElementSize,
               Elements:       aggregatePubKeyBytes,
	} 

       var NewKey ep11.KeyBlob
       NewKey, _ , err =  ep11.DeriveKey(target , 
                        []*ep11.Mechanism{ep11.NewMechanism(C.CKM_IBM_EC_AGGREGATE,ep11.NewECAGGParams(Params))} , 
                        nil,
                        publicKeyECTemplate  )  


        fmt.Printf("Aggregated Public Key: \n%x\n\n",NewKey) 



}
