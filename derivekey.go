package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
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

var slip10DerivType = map[string]int{
    "PRV2PRV" :5,
    "PRV2PUB" :6,
    "PUB2PUB" :7,  // unsupported
    "MASTERK" :8,
}   


var ecParameters []byte 
var target  ep11.Target_t

func slip10_deriveKey(deriveType string, childKeyIndex uint, hardened bool, baseKey []byte, chainCode []byte) ([]byte, []byte) {

	if hardened {
		childKeyIndex += C.CK_IBM_BIP0032_HARDENED
	}
/*
        DeriveKeyTemplate := []*ep11.Attribute{
                    ep11.NewAttribute(C.CKA_EC_PARAMS,ecParameters),
                    ep11.NewAttribute(C.CKA_VERIFY,true),
                    ep11.NewAttribute(C.CKA_DERIVE,true),
                    ep11.NewAttribute(C.CKA_EXTRACTABLE,false),
                    ep11.NewAttribute(C.CKA_IBM_USE_AS_DATA,true),
                    ep11.NewAttribute(C.CKA_KEY_TYPE, C.CKK_ECDSA),
                    ep11.NewAttribute(C.CKA_VALUE_LEN,32),
        }
*/

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
                    C.CKA_SENSITIVE:		true,
                    C.CKA_IBM_USE_AS_DATA:	true,
                    C.CKA_KEY_TYPE: 		C.CKK_ECDSA,
                    C.CKA_VALUE_LEN:		0,
        }

	Params := ep11.BTCDeriveParams{Type:slip10DerivType[deriveType], ChildKeyIndex: childKeyIndex, ChainCode: chainCode, Version : C.XCP_BTC_VERSION,} 

	NewKeyBytes, CheckSum, err :=  ep11.DeriveKey( target , 
                        ep11.Mech(C.CKM_IBM_BTC_DERIVE,ep11.NewBTCDerviceParams(Params)), 
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
    var prevSk []byte
    var prevChaincode []byte

    path := bytes.Split([]byte(os.Args[1]),[]byte("/"))
 
    Sk , Chaincode := slip10_deriveKey("MASTERK", 0, false, seed,nil)
    CheckSumHex := make([]byte, hex.EncodedLen(len(Chaincode)))
 
  	var index uint64
  	var hardened bool
    for i:=1; i<len(path); i++ {
    	if path[i][len(path[i])-1] == []byte("h")[0] {
    		hardened = true
    		index , _= strconv.ParseUint(string(path[i][:len(path[i])-1]),10,64)
    	} else {
    		hardened = false
      		index ,_ = strconv.ParseUint(string(path[i]),10,64)
    	}

   		prevSk = Sk
    	prevChaincode = Chaincode

	    Sk , Chaincode = slip10_deriveKey("PRV2PRV", uint(index), hardened, Sk, Chaincode)   	
    }

    var pk []byte
    if len(path)>1 {
 		   pk , _ = slip10_deriveKey("PRV2PUB", uint(index), hardened, prevSk, prevChaincode)   	
    }
 
    sKeyHex := make([]byte, hex.EncodedLen(len(Sk)))
    hex.Encode(sKeyHex, Sk)
    fmt.Println("Derived Private Key: " +string(sKeyHex)+"\n")

    if len(path)>1 {
	    pKeyHex := make([]byte, hex.EncodedLen(len(pk)))
	    hex.Encode(pKeyHex, pk)
	    fmt.Println("Derived Public Key: " +string(pKeyHex)+"\n")
	}

	CheckSumHex = make([]byte, hex.EncodedLen(len(Chaincode)))
    hex.Encode(CheckSumHex, Chaincode)
   	fmt.Println("chain Code: " +string(CheckSumHex)+"\n")
  }
