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
import "github.com/jyg007/ep11go/ep11"
import "log"

func main() { 

	hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")
        if hsmTarget == "" {
                log.Fatalf("EP11_IBM_TARGET_HSM not set")
        }

        target := ep11.HsmInit(hsmTarget)


        aeskey, _ := hex.DecodeString(os.Args[1])
        data :=  make([]byte,16)

	Cipher,err := ep11.EncryptSingle(target, 
                        ep11.Mech(C.CKM_AES_ECB,nil),
                        aeskey ,
                        []byte(data),
                )
	if err != nil  {
		fmt.Println(err)
	}
        fmt.Printf("\nCipher:\n%x\n", Cipher[:3])
}
