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
import "errors"
import "strings"

type KeyBlob []byte  

var LoginBlob C.CK_BYTE_PTR = nil
var LoginBlobLen C.CK_ULONG = 0


func SetLoginBlob(id []byte) {
	LoginBlob = C.CK_BYTE_PTR(unsafe.Pointer(&id[0]))
	LoginBlobLen = C.CK_ULONG(len(id))
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func GetMechanismList(target C.target_t) ( string, error)  {

	var counter C.CK_ULONG

        rv := C.m_GetMechanismList((C.CK_SLOT_ID)(0), nil, (C.CK_ULONG_PTR)(unsafe.Pointer(&counter)), target)
        if rv != C.CKR_OK {
                return  "", toError(rv)
        }       
	mlist := (*C.CK_MECHANISM_TYPE)(C.malloc(counter * C.size_t(unsafe.Sizeof(C.CK_MECHANISM_TYPE(0)))))
	if mlist == nil {
		return "",errors.New("Memory allocaiton failed")
	}
	defer C.free(unsafe.Pointer(mlist))
        rv = C.m_GetMechanismList((C.CK_SLOT_ID)(0), mlist, (C.CK_ULONG_PTR)(unsafe.Pointer(&counter)), target)
        if rv != C.CKR_OK {
                return  "", toError(rv)
        }
	// Convert C pointer to a Go slice
	mechanisms := (*[1 << 30]C.CK_MECHANISM_TYPE)(unsafe.Pointer(mlist))[:counter:counter]

	var result strings.Builder
	for _, mech := range mechanisms {
		result.WriteString( MechToName[MechanismValue(mech)]+" ")
	}
	return strings.TrimSpace(result.String()) , nil
}

//##########################################################################################################################################################################################
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


        rv := C.m_GenerateKey( mech, t, tcount, LoginBlob , LoginBlobLen , keyC, &keyLenC, checkSumC, &checkSumLenC, target )
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
				return nil,  e1
    	}
		  plain = plain[:plainlenC]
			return plain,nil
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func ReencryptSingle(target C.target_t, m_dec []*Mechanism, m_enc []*Mechanism, key_dec KeyBlob, key_enc KeyBlob, cipher_in []byte) ([]byte, error) {
			  mecharena_dec, mech_dec := cMechanism(m_dec)
        defer mecharena_dec.Free()
        key_decC := C.CK_BYTE_PTR(unsafe.Pointer(&key_dec[0]))
        key_decLenC := C.CK_ULONG(len(key_dec))

	      cipher_inC :=  C.CK_BYTE_PTR(unsafe.Pointer(&cipher_in[0]))
        cipher_inlenC :=  C.CK_ULONG(len(cipher_in))

        mecharena_enc, mech_enc := cMechanism(m_enc)
        defer mecharena_enc.Free()
        key_encC := C.CK_BYTE_PTR(unsafe.Pointer(&key_enc[0]))
        key_encLenC := C.CK_ULONG(len(key_enc))

 	      cipherLen :=  MAX_BLOCK_SIZE
        cipher := make([]byte, cipherLen)
        cipherLenC := (C.CK_ULONG)(cipherLen)
        cipherC := (C.CK_BYTE_PTR)(unsafe.Pointer(&cipher[0]))
	
 				rv := C.m_ReencryptSingle(key_decC, key_decLenC, key_encC, key_encLenC, mech_dec,mech_enc, cipher_inC, cipher_inlenC, cipherC, &cipherLenC, target)
	    	if rv != C.CKR_OK {
	         e1 := toError(rv)
					return nil,  e1
	    	}
	    	cipher = cipher[:cipherLenC]  
	    	return cipher, nil      
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
        
	rv := C.m_GenerateKeyPair( mech, t1, tcount1, t2,tcount2,LoginBlob,LoginBlobLen , privatekeyC, &privatekeyLenC, publickeyC, &publickeyLenC, target )
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

	rv  := C.m_DeriveKey(mech, t1, tcount1,baseKeyC,baseKeyLenC,dataC,dataLenC,LoginBlob,LoginBlobLen,newKeyC,&newKeyLenC,cSumC,&cSumLenC,target)

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

        rv := C.m_UnwrapKey(wrappedC, wrappedLenC, keKC, keKLenC, macKeyC, macKeyLenC, LoginBlob, LoginBlobLen, mech, t, tcount, unwrappedC, &unwrappedLenC, cSumC, &cSumLenC, target)

        if rv != C.CKR_OK {
                  e1 := toError(rv)
		  
		  return nil, e1
        }
	UnWrappedKey = UnWrappedKey[:unwrappedLenC]
	CSum = CSum[:cSumLenC]

	return UnWrappedKey, nil
}



//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func WrapKey(target C.target_t, m []*Mechanism, KeK KeyBlob, Key KeyBlob ) (KeyBlob, error)  {
  mecharena, mech := cMechanism(m)
  defer mecharena.Free()

  WrappedKey  :=  make([]byte,MAX_BLOB_SIZE)
  wrappedC := C.CK_BYTE_PTR(unsafe.Pointer(&WrappedKey[0]))
  wrappedLenC := C.CK_ULONG(len(WrappedKey))

  keKC := C.CK_BYTE_PTR(unsafe.Pointer(&KeK[0]))
  keKLenC := C.CK_ULONG(len(KeK))

  keyC := C.CK_BYTE_PTR(unsafe.Pointer(&Key[0]))
  keyLenC := C.CK_ULONG(len(Key))

  var macKeyC C.CK_BYTE_PTR
  macKeyC = nil
  macKeyLenC := C.CK_ULONG(0)

  rv := C.m_WrapKey(keyC, keyLenC, keKC, keKLenC,  macKeyC, macKeyLenC, mech, wrappedC, &wrappedLenC,  target)

  if rv != C.CKR_OK {
      e1 := toError(rv)
			return nil, e1
  }
  WrappedKey = WrappedKey[:wrappedLenC]

  return WrappedKey, nil
}

func isPrintable(b []byte) bool {
    for _, c := range b {
        if c < 32 || c > 126 {
            return false
        }
    }
    return true
}



//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func GetAttributeValue(target C.target_t,  Key KeyBlob, attrs Attributes ) (map[C.CK_ATTRIBUTE_TYPE]interface{}, error)  {
     attrarena, t, tcount := cAttributeList(ConvertToAttributeSlice(attrs))
     defer attrarena.Free()

     KeyC := (*C.uchar)(unsafe.Pointer(&Key[0]))
     KeyLenC := (C.size_t)(len(Key))

     // Need this for the passthrough case
     rv := C.m_GetAttributeValue(KeyC, KeyLenC, t, tcount, target)



     if rv != C.CKR_OK {
                return nil,toError(rv)
     }

    // Create result map
    result := make(map[C.CK_ATTRIBUTE_TYPE]interface{})

    for i := 0; i < int(tcount); i++ {
        attr := (*C.CK_ATTRIBUTE)(unsafe.Pointer(uintptr(unsafe.Pointer(t)) + uintptr(i)*unsafe.Sizeof(*t)))
        attrType := attr._type // or attr.type_, depending on binding

        if attr.pValue == nil || attr.ulValueLen == 0 {
            result[attrType] = nil
            continue
        }

        // Convert the C value to a Go []byte
        value := C.GoBytes(unsafe.Pointer(attr.pValue), C.int(attr.ulValueLen))
        result[attrType] = value
    }

    return result, nil
}	
