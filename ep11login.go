package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>
#include <openssl/evp.h>
#include <stdlib.h>

*/
import "C"
import "ep11go/ep11"
import (
	"fmt"
	"os"
)

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################

func main() {
        target := ep11.HsmInit("3.19") 
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run main.go <logon> <fipspin>")
		return
	}

        pinBlob, rcc := ep11.EP11Login([]byte(os.Args[2]), target)
	if rcc != nil {
		fmt.Println("Failed to connect")
		fmt.Println(rcc)
		return
	}
	fmt.Printf("Login extended successful\npinBlob=%x\n\n", pinBlob)
        
	rcc = ep11.EP11Logout([]byte(os.Args[2]), target)
	if rcc != nil {
		fmt.Println("Failed to connect")
		fmt.Println(rcc)
		return
	}
	fmt.Printf("Logout extended successful\n")
}


