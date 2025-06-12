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
        data,_ := hex.DecodeString(os.Args[2])

	 if len(data) < 16 {
        	fmt.Fprintln(os.Stderr, "Error: ciphertext too short to contain IV")
	        os.Exit(1)
    	}
	iv := data[:16]
    	ciphertext := data[16:]

	Plain,_ := ep11.DecryptSingle(target, 
                        ep11.Mech(C.CKM_AES_CBC_PAD, iv),
                        aeskey ,
                        ciphertext,
                )
        fmt.Printf("\nPlain text:\n%s\n", Plain)
}
