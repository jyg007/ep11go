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
import "unsafe"
import "encoding/hex"
import "encoding/asn1"


const (
     // Maximum Key Size
        MAX_BLOB_SIZE = 8192
        MAX_CSUMSIZE = 64
)

type KeyBlob []byte  


// GenerateKey generates a secret key, creating a new key object.
func GenerateKey(target C.target_t, m []*Mechanism, temp []*Attribute) (KeyBlob, error)  {
        attrarena, t, tcount := cAttributeList(temp)
        defer attrarena.Free()
        mecharena, mech := cMechanism(m)
        defer mecharena.Free()

	Key  :=  make([]byte,MAX_BLOB_SIZE)
        CheckSum:= make([]byte,MAX_CSUMSIZE )
	
        keyC := C.CK_BYTE_PTR(unsafe.Pointer(&Key[0]))
        keyLenC := C.CK_ULONG(len(Key))
        checkSumC := C.CK_BYTE_PTR(unsafe.Pointer(&CheckSum[0]))
        checkSumLenC := C.CK_ULONG(len(CheckSum))

        rv := C.m_GenerateKey( mech, t, tcount, nil,0 , keyC, &keyLenC, checkSumC, &checkSumLenC, target )
        if rv != C.CKR_OK {
                  e1 := toError(rv)
		  
		  return nil, e1
        }
	Key = Key[:keyLenC]
	CheckSum = CheckSum[:checkSumLenC]

//	keySlice := unsafe.Slice((*byte)(unsafe.Pointer(keyC)), keyLenC)
	//	C.free(unsafe.Pointer(checkSumC))
/*	fmt.Println("Generated Key:", hex.EncodeToString(keySlice))
	fmt.Printf("Key Length: %d\n", uint64(keyLenC))
	checkSumSlice := unsafe.Slice((*byte)(unsafe.Pointer(checkSumC)), checkSumLenC)
/*        e1 := toError(e)
        if e1 == nil {
                return ObjectHandle(key), nil
        }
        return 0, e1*/
	return Key, nil
}


//func GenerateKeyPair(target C.target_t, m []*Mechanism, pk []*Attribute, sk []*Attribute) (KeyBlob, error)  {
func GenerateKeyPair(target C.target_t, m []*Mechanism, pk []*Attribute, sk []*Attribute)  (KeyBlob, KeyBlob , error) {
        attrarena1, t1, tcount1 := cAttributeList(pk)
        defer attrarena1.Free()
        attrarena2, t2, tcount2 := cAttributeList(sk)
        defer attrarena2.Free()
        mecharena, mech := cMechanism(m)
        defer mecharena.Free()
	
	privateKey  :=  make([]byte,MAX_BLOB_SIZE)
        privatekeyC := C.CK_BYTE_PTR(unsafe.Pointer(&privateKey[0]))
        privatekeyLenC := C.CK_ULONG(len(privateKey))
	publicKey  :=  make([]byte,MAX_BLOB_SIZE)
        publickeyC := C.CK_BYTE_PTR(unsafe.Pointer(&publicKey[0]))
        publickeyLenC := C.CK_ULONG(len(publicKey))
        
	rv := C.m_GenerateKeyPair( mech, t1, tcount1, t2,tcount2,nil,0 , privatekeyC, &privatekeyLenC, publickeyC, &publickeyLenC, target )
        if rv != C.CKR_OK {
                  e1 := toError(rv)
		  return nil,nil, e1
        }
	privateKey = privateKey[:privatekeyLenC]
	publicKey = publicKey[:publickeyLenC]

	return  publicKey, privateKey, nil
//	fmt.Println("Generated Private Key:", hex.EncodeToString(privateKey))
//	fmt.Println("Generated public Key:", hex.EncodeToString(publicKey))
}


func GenerateRandom(target C.target_t, length int) (KeyBlob, error)  {
	// Allocate memory for the random bytes
	randomData := make([]byte, length)
        rv := C.m_GenerateRandom( (*C.CK_BYTE)(unsafe.Pointer(&randomData[0])), C.CK_ULONG(length), target)

	// Check return value for success
	if rv != C.CKR_OK {
		return nil, fmt.Errorf("C_GenerateRandom failed with error code: 0x%X", uint(rv))
	}
	return randomData, nil
}



func main() { 
      target := hsminit(3,19) 
 
      keyTemplate := []*Attribute{
                NewAttribute(C.CKA_VALUE_LEN,16 ),
                NewAttribute(C.CKA_UNWRAP, false),
                NewAttribute(C.CKA_ENCRYPT, true),
      }

	for i:=0;i<10;i++ {
      k, _ :=GenerateRandom(target, 128)
      fmt.Println("Generated random 32 bytes Key:", hex.EncodeToString(k))
}

	var aeskey KeyBlob
	for i:=0;i<1;i++ {
        	aeskey, _ = GenerateKey(target,
                	[]*Mechanism{NewMechanism(C.CKM_AES_KEY_GEN, nil)},
	                keyTemplate)
		fmt.Println("Generated Key:", hex.EncodeToString(aeskey))
	}

	OIDNamedCurveSecp256k1 := asn1.ObjectIdentifier{1, 3, 132, 0, 10}

        ecParameters, err := asn1.Marshal(OIDNamedCurveSecp256k1)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate := []*Attribute{
		    NewAttribute(C.CKA_EC_PARAMS,ecParameters),
		    NewAttribute(C.CKA_VERIFY,true),
        }
	privateKeyECTemplate := []*Attribute{
		    NewAttribute(C.CKA_EC_PARAMS,ecParameters),
		    NewAttribute(C.CKA_SIGN,true),
		    NewAttribute(C.CKA_PRIVATE,true),
		    NewAttribute(C.CKA_SENSITIVE,true),
        }

	var pk, sk KeyBlob
	for i:=0;i<10;i++ {
       //   _,_ , _= GenerateKeyPair(target, []*Mechanism{NewMechanism(C.CKM_EC_KEY_PAIR_GEN, nil)}, publicKeyECTemplate,privateKeyECTemplate)
          pk, sk , _= GenerateKeyPair(target, []*Mechanism{NewMechanism(C.CKM_EC_KEY_PAIR_GEN, nil)}, publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("Generated public Key:", hex.EncodeToString(pk))
	fmt.Println("\n")
		}

}
