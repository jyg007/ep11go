package ep11

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

/*
const (
     // Maximum Key Size
        MAX_BLOB_SIZE = 8192
        MAX_CSUMSIZE = 64
	MAX_BLOCK_SIZE = 256 / 8
)
*/
type KeyBlob []byte  

//l##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func GenerateKey(target C.target_t, m []*Mechanism, temp Attributes) (KeyBlob, error)  {
        attrarena, t, tcount := cAttributeList(ConvertToAttributeSlice(temp))
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
func GenerateKeyPair(target C.target_t, m []*Mechanism, pk Attributes, sk Attributes)  (KeyBlob, KeyBlob , error) {
        attrarena1, t1, tcount1 := cAttributeList(ConvertToAttributeSlice(pk))
        defer attrarena1.Free()
        attrarena2, t2, tcount2 := cAttributeList(ConvertToAttributeSlice(sk))
        defer attrarena2.Free()
        mecharena, mech := cMechanism(m)
        defer mecharena.Free()
	
	privateKey  :=  make([]byte,3*MAX_BLOB_SIZE)
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
func DeriveKey(target C.target_t, m []*Mechanism, bk KeyBlob, attr Attributes)  (KeyBlob, KeyBlob , error) {
	mecharena, mech := cMechanism(m)
        defer mecharena.Free()
        attrarena1, t1, tcount1 := cAttributeList(ConvertToAttributeSlice(attr))
        defer attrarena1.Free()

	var baseKeyC C.CK_BYTE_PTR
	var baseKeyLenC C.CK_ULONG
	if bk == nil {
        	baseKeyC =  nil
		baseKeyLenC = 0
	} else {
        	baseKeyC = C.CK_BYTE_PTR(unsafe.Pointer(&bk[0]))
        	baseKeyLenC = C.CK_ULONG(len(bk))
	}
	newKey  :=  make([]byte,MAX_BLOB_SIZE)
        newKeyC := C.CK_BYTE_PTR(unsafe.Pointer(&newKey[0]))
        newKeyLenC := C.CK_ULONG(len(newKey))
	cSum  :=  make([]byte,MAX_BLOB_SIZE)
        cSumC := C.CK_BYTE_PTR(unsafe.Pointer(&cSum[0]))
        cSumLenC := C.CK_ULONG(len(cSum))

	data := []byte{}
	var dataC C.CK_BYTE_PTR
        dataC = nil
	dataLenC := C.CK_ULONG(len(data))

	rv  := C.m_DeriveKey(mech, t1, tcount1,baseKeyC,baseKeyLenC,dataC,dataLenC,nil,0,newKeyC,&newKeyLenC,cSumC,&cSumLenC,target)

        if rv != C.CKR_OK {
                  e1 := toError(rv)
           	  fmt.Println(e1)
	          return nil,nil, e1
        }

        newKey = newKey[:newKeyLenC]
        cSum = cSum[:cSumLenC]
	//fmt.Println("Derive Key", hex.EncodeToString(newKey))
	//fmt.Println("Checksum:", hex.EncodeToString(cSum))
	return newKey, cSum, nil

    
}


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func SignSingle(target C.target_t, m []*Mechanism, sk KeyBlob, data []byte ) ([]byte , error) {
	mecharena, mech := cMechanism(m)
        defer mecharena.Free()
	var privatekeyC C.CK_BYTE_PTR
	var privatekeyLenC C.CK_ULONG
	if sk == nil {
        	privatekeyC =  nil
		privatekeyLenC = 0
	} else {
        	privatekeyC = C.CK_BYTE_PTR(unsafe.Pointer(&sk[0]))
	        privatekeyLenC = C.CK_ULONG(len(sk))
	}
	dataC :=  C.CK_BYTE_PTR(unsafe.Pointer(&data[0]))
        datalenC :=  C.CK_ULONG(len(data))
	sig := make([]byte,MAX_BLOB_SIZE)
        sigC := C.CK_BYTE_PTR(unsafe.Pointer(&sig[0]))
        siglenC :=  C.CK_ULONG(len(sig))

	rv := C.m_SignSingle(privatekeyC, privatekeyLenC, mech, dataC, datalenC, sigC, &siglenC, target)
    	if rv != C.CKR_OK {
                 e1 := toError(rv)
		 fmt.Println(e1)
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


//l##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func UnWrapKey(target C.target_t, m []*Mechanism, KeK KeyBlob, WrappedKey KeyBlob, temp Attributes) (KeyBlob, error)  {
        attrarena, t, tcount := cAttributeList(ConvertToAttributeSlice(temp))
        defer attrarena.Free()
        mecharena, mech := cMechanism(m)
        defer mecharena.Free()

	UnWrappedKey  :=  make([]byte,MAX_BLOB_SIZE)
        CSum:= make([]byte,MAX_CSUMSIZE )

        var macKeyC C.CK_BYTE_PTR
	macKeyC = nil
	macKeyLenC := C.CK_ULONG(0)

        unwrappedC := C.CK_BYTE_PTR(unsafe.Pointer(&UnWrappedKey[0]))
        unwrappedLenC := C.CK_ULONG(len(UnWrappedKey))

        wrappedC := C.CK_BYTE_PTR(unsafe.Pointer(&WrappedKey[0]))
        wrappedLenC := C.CK_ULONG(len(WrappedKey))

        keKC := C.CK_BYTE_PTR(unsafe.Pointer(&KeK[0]))
        keKLenC := C.CK_ULONG(len(KeK))
        cSumC := C.CK_BYTE_PTR(unsafe.Pointer(&CSum[0]))
        cSumLenC := C.CK_ULONG(len(CSum))

        rv := C.m_UnwrapKey(wrappedC, wrappedLenC, keKC, keKLenC, macKeyC, macKeyLenC, nil, 0, mech, t, tcount, unwrappedC, &unwrappedLenC, cSumC, &cSumLenC, target)

        if rv != C.CKR_OK {
                  e1 := toError(rv)
		  
		  return nil, e1
        }
	UnWrappedKey = UnWrappedKey[:unwrappedLenC]
	CSum = CSum[:cSumLenC]

	return UnWrappedKey, nil
}



//l##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func WrapKey(target C.target_t, m []*Mechanism, Key KeyBlob, KeK KeyBlob) (KeyBlob, error)  {
        mecharena, mech := cMechanism(m)
        defer mecharena.Free()

	WrappedKey  :=  make([]byte,MAX_BLOB_SIZE)
        wrappedC := C.CK_BYTE_PTR(unsafe.Pointer(&WrappedKey[0]))
        wrappedLenC := C.CK_ULONG(len(WrappedKey))

        var macKeyC C.CK_BYTE_PTR
	macKeyC = nil
	macKeyLenC := C.CK_ULONG(0)

        keyC := C.CK_BYTE_PTR(unsafe.Pointer(&Key[0]))
        keyLenC := C.CK_ULONG(len(Key))

        keKC := C.CK_BYTE_PTR(unsafe.Pointer(&KeK[0]))
        keKLenC := C.CK_ULONG(len(KeK))

        rv := C.m_WrapKey(keyC, keyLenC, keKC, keKLenC, macKeyC, macKeyLenC, mech, wrappedC, &wrappedLenC,  target)

        if rv != C.CKR_OK {
                  e1 := toError(rv)
		  
		  return nil, e1
        }
	WrappedKey = WrappedKey[:wrappedLenC]

	return WrappedKey, nil
}
