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
