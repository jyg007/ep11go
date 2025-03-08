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
import  "crypto/sha256"
import "os"

func main() { 
       target := ep11.HsmInit(3,19) 
       sk := make([]byte, hex.DecodedLen(len(os.Args[2])))

       hex.Decode(sk, []byte(os.Args[2]))
       signData := sha256.Sum256([]byte(os.Args[1]))

       sig,_ := ep11.SignSingle(target, ep11.Mech(C.CKM_IBM_DILITHIUM,nil),sk,signData[:])
       fmt.Printf("\nSignature: %x\n", sig)
}
