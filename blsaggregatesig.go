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
       target := ep11.HsmInit(3,19) 

 var aggregateSigBytes []byte

       elementSize:= uint(0)
        // Iterate over the command-line arguments (skip the first one, which is the program name)
        for _, arg := range os.Args[2:] {
                // Decode each hex string to bytes
                decodedBytes, err := hex.DecodeString(arg)
                if elementSize==0 {
                        elementSize=uint(len(decodedBytes))
                }
                if err != nil {
                        panic(fmt.Errorf("Error decoding hex string %s: %v", arg, err))
                }
                // Append the decoded bytes to the byteArray
                aggregateSigBytes = append(aggregateSigBytes, decodedBytes...)
        }


       Params := ep11.ECAGGParams{    
	       Version:        0,
               Mode:           C.CK_IBM_EC_AGG_BLS12_381_SIGN,
               PerElementSize: elementSize,
               Elements:       aggregateSigBytes,
	} 

	sig,_ := ep11.SignSingle(target, []*ep11.Mechanism{ep11.NewMechanism(C.CKM_IBM_EC_AGGREGATE,ep11.NewECAGGParams(Params))},nil,aggregateSigBytes)
        fmt.Println("Signature: ", hex.EncodeToString(sig))

}
