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
	MAX_BLOCK_SIZE = 256 / 8
)

type KeyBlob []byte  


//l##########################################################################################################################################################################################
//##########################################################################################################################################################################################
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

	return Key, nil
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func EncryptSingle(target C.target_t, m []*Mechanism, k KeyBlob, data []byte ) ([]byte, error) {
	mecharena, mech := cMechanism(m)
        defer mecharena.Free()
        keyC := C.CK_BYTE_PTR(unsafe.Pointer(&k[0]))
        keyLenC := C.CK_ULONG(len(k))
	dataC :=  C.CK_BYTE_PTR(unsafe.Pointer(&data[0]))
        datalenC :=  C.CK_ULONG(len(data))

        cipherLen := datalenC + MAX_BLOCK_SIZE
        cipherlenC := (C.CK_ULONG)(cipherLen)
        cipher := make([]byte, cipherLen)
        cipherC := (C.CK_BYTE_PTR)(unsafe.Pointer(&cipher[0]))

	rv := C.m_EncryptSingle(keyC, keyLenC, mech, dataC, datalenC, cipherC, &cipherlenC, target)
        if rv != C.CKR_OK {
                  e1 := toError(rv)
	 //   fmt.Printf("zeeue",e1)
		return nil,  e1
        }
        cipher = cipher[:cipherlenC]
	return cipher,nil
	//fmt.Println("Cipher:", hex.EncodeToString(cipher))
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func DecryptSingle(target C.target_t, m []*Mechanism, k KeyBlob, cipher []byte ) ([]byte, error) {
	mecharena, mech := cMechanism(m)
        defer mecharena.Free()
        keyC := C.CK_BYTE_PTR(unsafe.Pointer(&k[0]))
        keyLenC := C.CK_ULONG(len(k))
	cipherC :=  C.CK_BYTE_PTR(unsafe.Pointer(&cipher[0]))
        cipherlenC :=  C.CK_ULONG(len(cipher))

        plainLen := cipherlenC + MAX_BLOCK_SIZE
        plainlenC := (C.CK_ULONG)(plainLen)
        plain := make([]byte, plainLen)
        plainC := (C.CK_BYTE_PTR)(unsafe.Pointer(&plain[0]))

	rv := C.m_DecryptSingle(keyC, keyLenC, mech, cipherC, cipherlenC, plainC, &plainlenC, target)
    	if rv != C.CKR_OK {
                  e1 := toError(rv)
	 //   fmt.Printf("zeeue",e1)
		return nil,  e1
    	}
        plain = plain[:plainlenC]
	return plain,nil
	//fmt.Println("Cipher:", hex.EncodeToString(cipher))
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
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


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func SignSingle(target C.target_t, m []*Mechanism, sk KeyBlob, data []byte ) ([]byte , error) {
	mecharena, mech := cMechanism(m)
        defer mecharena.Free()
        privatekeyC := C.CK_BYTE_PTR(unsafe.Pointer(&sk[0]))
        privatekeyLenC := C.CK_ULONG(len(sk))
	dataC :=  C.CK_BYTE_PTR(unsafe.Pointer(&data[0]))
        datalenC :=  C.CK_ULONG(len(data))
	sig := make([]byte,MAX_BLOB_SIZE)
        sigC := C.CK_BYTE_PTR(unsafe.Pointer(&sig[0]))
        siglenC :=  C.CK_ULONG(len(sig))

	rv := C.m_SignSingle(privatekeyC, privatekeyLenC, mech, dataC, datalenC, sigC, &siglenC, target)
    	if rv != C.CKR_OK {
                  e1 := toError(rv)
		return nil,  e1
    	}
        sig = sig[:siglenC]
	return sig,nil
//	fmt.Println("Signature:", hex.EncodeToString(sig))
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func VerifySingle(target C.target_t, m []*Mechanism, pk KeyBlob, data []byte ,sig []byte) error {
	mecharena, mech := cMechanism(m)
        defer mecharena.Free()
        publickeyC := C.CK_BYTE_PTR(unsafe.Pointer(&pk[0]))
        publickeyLenC := C.CK_ULONG(len(pk))
	dataC :=  C.CK_BYTE_PTR(unsafe.Pointer(&data[0]))
        datalenC :=  C.CK_ULONG(len(data))
        sigC := C.CK_BYTE_PTR(unsafe.Pointer(&sig[0]))
        siglenC :=  C.CK_ULONG(len(sig))
	rv := C.m_VerifySingle(publickeyC, publickeyLenC, mech, dataC, datalenC, sigC,siglenC, target)
	if rv == 0  {
		return nil
	} else {
		return toError(rv)
	}
}


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func GenerateRandom(target C.target_t, length int) (KeyBlob, error)  {
	// Allocate memory for the random bytes
	randomData := make([]byte, length)
        rv := C.m_GenerateRandom( (*C.CK_BYTE)(unsafe.Pointer(&randomData[0])), C.CK_ULONG(length), target)

	// Check return value for success
	if rv != C.CKR_OK {
		return nil, toError(rv)
	}
	return randomData, nil
}


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := hsminit(3,19) 
 
      keyTemplate := []*Attribute{
                NewAttribute(C.CKA_VALUE_LEN,16 ),
                NewAttribute(C.CKA_UNWRAP, false),
                NewAttribute(C.CKA_ENCRYPT, true),
      }

	for i:=0;i<1;i++ {
      		k, _ :=GenerateRandom(target, 128)
      		fmt.Println("Generated random 32 bytes Key:", hex.EncodeToString(k))
	}
	fmt.Println()

	var aeskey KeyBlob
	var Cipher,plain []byte
        var err error
	for i:=0;i<1;i++ {
        	aeskey, _ = GenerateKey(target,
                	[]*Mechanism{NewMechanism(C.CKM_AES_KEY_GEN, nil)},
	                keyTemplate)
		fmt.Println("Generated Key:", hex.EncodeToString(aeskey))

	iv:= make([]byte,16)
        hex.Decode(iv,[]byte("3132333435360a"))
	Cipher,_ = EncryptSingle(target, 
			[]*Mechanism{NewMechanism(C.CKM_AES_CBC_PAD, iv)},
			aeskey ,
			[]byte("hello world hello world hello world"),
		)
	fmt.Println("Cipher:", hex.EncodeToString(Cipher))
        
	plain,err = DecryptSingle(target, 
			[]*Mechanism{NewMechanism(C.CKM_AES_CBC_PAD, iv)},
			aeskey ,
			Cipher,
		)
	if plain == nil {
		fmt.Println(err)
	} else {
		fmt.Println("Decrypted:", string(plain))
	}
	}



	fmt.Printf("\n\n\n")
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
	var  sig []byte
        pk, sk , _= GenerateKeyPair(target, []*Mechanism{NewMechanism(C.CKM_EC_KEY_PAIR_GEN, nil)}, publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("\n")
	fmt.Println("Generated public Key:", hex.EncodeToString(pk))

	sig,_ = SignSingle(target, []*Mechanism{NewMechanism(C.CKM_ECDSA,nil)},sk,[]byte("helloworld"))
	fmt.Println("Signature: ", hex.EncodeToString(sig))
 
        err = VerifySingle( target, []*Mechanism{NewMechanism(C.CKM_ECDSA,nil)},pk, []byte("helloworld"), sig)
	if err != nil   {
                        fmt.Println(err)
	}
        

	fmt.Printf("\n\n\n")
	OIDNamedCurveED25519 :=  asn1.ObjectIdentifier{1, 3, 101, 112}

        ecParameters, err = asn1.Marshal(OIDNamedCurveED25519)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate = []*Attribute{
		    NewAttribute(C.CKA_EC_PARAMS,ecParameters),
		    NewAttribute(C.CKA_VERIFY,true),
        }
	privateKeyECTemplate = []*Attribute{
		    NewAttribute(C.CKA_EC_PARAMS,ecParameters),
		    NewAttribute(C.CKA_SIGN,true),
		    NewAttribute(C.CKA_PRIVATE,true),
		    NewAttribute(C.CKA_SENSITIVE,true),
        }

        pk, sk , _= GenerateKeyPair(target, []*Mechanism{NewMechanism(C.CKM_EC_KEY_PAIR_GEN, nil)}, publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("\n")
	fmt.Println("Generated public Key:", hex.EncodeToString(pk))

	sig,_ = SignSingle(target, []*Mechanism{NewMechanism(C.CKM_IBM_ED25519_SHA512,nil)},sk,[]byte("helloworld"))
	fmt.Println("Signature: ", hex.EncodeToString(sig))
 
        err = VerifySingle( target, []*Mechanism{NewMechanism(C.CKM_IBM_ED25519_SHA512,nil)},pk, []byte("helloworld"), sig)
	if err != nil   {
                        fmt.Println(err)
	}



	fmt.Printf("\n\n\n")
	OIDBLS12_381ET := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 999, 3, 2}

        ecParameters, err = asn1.Marshal(OIDBLS12_381ET)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate = []*Attribute{
		    NewAttribute(C.CKA_EC_PARAMS,ecParameters),
		    NewAttribute(C.CKA_VERIFY,true), 
		    NewAttribute(C.CKA_IBM_USE_AS_DATA, true),
		    NewAttribute(C.CKA_KEY_TYPE, C.CKK_EC),

        }
	privateKeyECTemplate = []*Attribute{
		    NewAttribute(C.CKA_EC_PARAMS,ecParameters),
		    NewAttribute(C.CKA_SIGN,true),
		    NewAttribute(C.CKA_PRIVATE,true),
		    NewAttribute(C.CKA_SENSITIVE,true),
		    NewAttribute(C.CKA_IBM_USE_AS_DATA,true),
		    NewAttribute(C.CKA_KEY_TYPE, C.CKK_EC),

        }

        pk, sk , _= GenerateKeyPair(target, []*Mechanism{NewMechanism(C.CKM_EC_KEY_PAIR_GEN, nil)}, publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("\n")
	fmt.Println("Generated public Key:", hex.EncodeToString(pk))

	sig,_ = SignSingle(target, []*Mechanism{NewMechanism(C.CKM_IBM_ECDSA_OTHER,NewECSGParams(C.ECSG_IBM_BLS))},sk,[]byte("helloworld"))
	fmt.Println("Signature: ", hex.EncodeToString(sig))
 
        err = VerifySingle( target, []*Mechanism{NewMechanism(C.CKM_IBM_ECDSA_OTHER,NewECSGParams(C.ECSG_IBM_BLS))},pk, []byte("helloworld"), sig)
	if err != nil   {
                        fmt.Println(err)
	}



}
