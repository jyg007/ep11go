package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "os"
import "encoding/hex"
import "ep11go/ep11"

func main() { 
      target := ep11.HsmInit("3.19") 

        aeskey, _ := hex.DecodeString(os.Args[1])

	iv, _ :=ep11.GenerateRandom(target,16 )

	Cipher,_ := ep11.EncryptSingle(target, 
                        ep11.Mech(C.CKM_AES_CBC_PAD, iv),
                        aeskey ,
                        []byte(os.Args[2]),
                )

        encryptedWithIV := append(iv, Cipher...)
        fmt.Printf("\nCipher:\n%x\n", encryptedWithIV)
}
