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
import "os"
import "encoding/hex"
import "ep11go/ep11"

func main() { 
      target := ep11.HsmInit(3,19) 

        aeskey, _ := hex.DecodeString(os.Args[2])

        iv:= make([]byte,16)
        hex.Decode(iv,[]byte(os.Args[3]))

	Cipher,_ := ep11.EncryptSingle(target, 
                        []*ep11.Mechanism{ep11.NewMechanism(C.CKM_AES_CBC_PAD, iv)},
                        aeskey ,
                        []byte(os.Args[1]),
                )
        fmt.Printf("\nCipher:\n%x\n", Cipher)
}
