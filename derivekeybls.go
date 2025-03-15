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
import "encoding/asn1"
import "ep11go/ep11"
import "os"
import "bytes"
import "strconv"



var ecParameters []byte 
var target  ep11.Target_t

func eip2333_deriveKey(deriveType uint, childKeyIndex uint, baseKey []byte, keyInfo []byte) ([]byte, []byte) {

        ecParameters, _ = asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
	/*
        DeriveKeyTemplate := []*ep11.Attribute{
                    ep11.NewAttribute(C.CKA_EC_PARAMS,ecParameters),
                    ep11.NewAttribute(C.CKA_VERIFY,true),
                    ep11.NewAttribute(C.CKA_DERIVE,true),
                    ep11.NewAttribute(C.CKA_PRIVATE,true),
                    ep11.NewAttribute(C.CKA_SENSITIVE,true),
                    ep11.NewAttribute(C.CKA_IBM_USE_AS_DATA,true),
                    ep11.NewAttribute(C.CKA_KEY_TYPE, C.CKK_ECDSA),
                    ep11.NewAttribute(C.CKA_VALUE_LEN,0),
        }*/
        DeriveKeyTemplate := ep11.Attributes{
                    C.CKA_EC_PARAMS:		ecParameters,
                    C.CKA_VERIFY:		true,
                    C.CKA_DERIVE:		true,
                    C.CKA_PRIVATE:		true,
                    C.CKA_EXTRACTABLE:		true,
                    C.CKA_SENSITIVE:		true,
                    C.CKA_IBM_USE_AS_DATA:	true,
                    C.CKA_KEY_TYPE: 		C.CKK_ECDSA,
	    	    C.CKA_VALUE_LEN:		0,
        }

	Params := ep11.ETHDeriveParams{Type:deriveType, ChildKeyIndex: childKeyIndex, KeyInfo : []byte(""), SigVersion : C.XCP_ETH_SIG_VERSION, Version : C.XCP_ETH_VERSION }

	NewKeyBytes, CheckSum, err :=  ep11.DeriveKey( target , 
                        ep11.Mech(C.CKM_IBM_ETH_DERIVE,ep11.NewETHDeriveParams(Params)) , 
                        baseKey,
                        DeriveKeyTemplate  )  

	if err != nil {
		panic(fmt.Errorf("Derived Child Key request error: %s", err))
	}

	return NewKeyBytes, CheckSum
}


func main() {

    target = ep11.HsmInit("3.19") 
	
    ecParameters, _ = asn1.Marshal(ep11.OIDNamedCurveSecp256k1)

    seed := make([]byte, hex.DecodedLen(len(os.Getenv("MASTERSEED"))))
    hex.Decode(seed, []byte(os.Getenv("MASTERSEED")))

    var Chaincode []byte
    var KeyInfo = make([]byte,C.XCP_EIP2333_KEYINFO_BYTES)
    var prevSk []byte
    var prevChaincode []byte

    path := bytes.Split([]byte(os.Args[1]),[]byte("/"))
 
    Sk , Chaincode := eip2333_deriveKey(C.CK_IBM_EIP2333_MASTERK, 0,  seed,KeyInfo)
 
    var index uint64
    for i:=1; i<len(path); i++ {
      		index ,_ = strconv.ParseUint(string(path[i]),10,64)
    	

    prevSk = Sk
    prevChaincode = Chaincode

    Sk , Chaincode = eip2333_deriveKey(C.CK_IBM_EIP2333_PRV2PRV, uint(index), Sk, Chaincode)   	
    }

    var pk []byte
    if len(path)>1 {
 		   pk , _ = eip2333_deriveKey(C.CK_IBM_EIP2333_PRV2PUB ,uint(index),  prevSk, prevChaincode)   	
    }
 
    fmt.Println("Derived Private Key: " +hex.EncodeToString(Sk)+"\n")

    if len(path)>1 {
    	    fmt.Println("Derived public Key: " +hex.EncodeToString(pk)+"\n")
	}

//    fmt.Println("Chaincode : " +hex.EncodeToString(Chaincode)+"\n")
  } 
