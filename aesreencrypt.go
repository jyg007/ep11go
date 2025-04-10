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

        aeskey1, _ := hex.DecodeString(os.Args[2])
        aeskey2, _ := hex.DecodeString(os.Args[3])

	data,_ := hex.DecodeString(os.Args[1])

  iv:= make([]byte,16)
    hex.Decode(iv,[]byte(os.Args[4]))


	Cipher,_ := ep11.ReencryptSingle(target, 
                        ep11.Mech(C.CKM_AES_CBC_PAD, iv),
                        ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey1,
			aeskey2,
                        data,
                )
        fmt.Printf("\nReenciphered text:\n%x\n", Cipher)
}
