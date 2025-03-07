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



var target  ep11.Target_t

// The starting offset of the Kyber mechanism parameter, CipherText, for decapsulation operations
const cipherTextOffset uint = 7


func main() {

    target = ep11.HsmInit(3,19) 

    pk, _ := hex.DecodeString(os.Args[1])

    deriveKyberTemplate := ep11.Attributes{
                C.CKA_CLASS:     C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:  C.CKK_AES,
                C.CKA_VALUE_LEN: 256 / 8,
        }

	Params := ep11.KyberParams{Version:C.XCP_KYBER_KEM_VERSION , Mode: C.CK_IBM_KEM_ENCAPSULATE , Kdf: C.CKD_NULL } 
	
	NewKeyBytes, CheckSum, err :=  ep11.DeriveKey( target , 
                        []*ep11.Mechanism{ep11.NewMechanism(C.CKM_IBM_KYBER,ep11.NewKyberParams(Params))} , 
                        pk,
                        deriveKyberTemplate  )  

	if err != nil {
		panic(fmt.Errorf("Derived Child Key request error: %s", err))
	}

        fmt.Printf("Derived AES key: %x\n\n",NewKeyBytes)
        fmt.Printf("Checksum: %x\n\n",CheckSum[cipherTextOffset:])
	
  }
