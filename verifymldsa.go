package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "encoding/hex"
import "ep11go/ep11"
import  "crypto/sha256"
import "os"
import "log"

func main() { 
    hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")

    if hsmTarget == "" {
                log.Fatalf("EP11_IBM_TARGET_HSM not set")
    }

    target := ep11.HsmInit(hsmTarget)

    pk := make([]byte, hex.DecodedLen(len(os.Args[3])))
    hex.Decode(pk, []byte(os.Args[3]))

    sign := make([]byte, hex.DecodedLen(len(os.Args[2])))
    hex.Decode(sign, []byte(os.Args[2]))

    signData := sha256.Sum256([]byte(os.Args[1]))

    res := ep11.VerifySingle(target, ep11.Mech(C.CKM_IBM_ML_DSA,nil),pk,signData[:],sign[:])
   if res == nil {
		fmt.Printf("Signarture verified\n")
	} else {
		fmt.Println(res)
	}
}
