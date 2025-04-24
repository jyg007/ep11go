// Copyright 2013 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ep11

/*
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ep11.h>

static inline void putOAEPParams(CK_RSA_PKCS_OAEP_PARAMS_PTR params, CK_VOID_PTR pSourceData, CK_ULONG ulSourceDataLen)
{
	params->pSourceData = pSourceData;
	params->ulSourceDataLen = ulSourceDataLen;
}
*/
import "C"
import "unsafe"
import "encoding/binary" 
//import "encoding/hex" 
//import "encoding/asn1" 
import "fmt"

// GCMParams represents the parameters for the AES-GCM mechanism.
type GCMParams struct {
	arena
	params  *C.CK_GCM_PARAMS
	iv      []byte
	aad     []byte
	tagSize int
}

// NewGCMParams returns a pointer to AES-GCM parameters that can be used with the CKM_AES_GCM mechanism.
// The Free() method must be called after the operation is complete.
//
// Note that some HSMs, like CloudHSM, will ignore the IV you pass in and write their
// own. As a result, to support all libraries, memory is not freed
// automatically, so that after the EncryptInit/Encrypt operation the HSM's IV
// can be read back out. It is up to the caller to ensure that Free() is called
// on the GCMParams object at an appropriate time, which is after
//
// Encrypt/Decrypt. As an example:
//
//    gcmParams := pkcs11.NewGCMParams(make([]byte, 12), nil, 128)
//    p.ctx.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, gcmParams)},
//			aesObjHandle)
//    ct, _ := p.ctx.Encrypt(session, pt)
//    iv := gcmParams.IV()
//    gcmParams.Free()
//
func NewGCMParams(iv, aad []byte, tagSize int) *GCMParams {
	return &GCMParams{
		iv:      iv,
		aad:     aad,
		tagSize: tagSize,
	}
}

func cGCMParams(p *GCMParams) []byte {
	params := C.CK_GCM_PARAMS{
		ulTagBits: C.CK_ULONG(p.tagSize),
	}
	var arena arena
	if len(p.iv) > 0 {
		iv, ivLen := arena.Allocate(p.iv)
		params.pIv = C.CK_BYTE_PTR(iv)
		params.ulIvLen = ivLen
		params.ulIvBits = ivLen * 8
	}
	if len(p.aad) > 0 {
		aad, aadLen := arena.Allocate(p.aad)
		params.pAAD = C.CK_BYTE_PTR(aad)
		params.ulAADLen = aadLen
	}
	p.Free()
	p.arena = arena
	p.params = &params
	return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params))
}

// IV returns a copy of the actual IV used for the operation.
//
// Some HSMs may ignore the user-specified IV and write their own at the end of
// the encryption operation; this method allows you to retrieve it.
func (p *GCMParams) IV() []byte {
	if p == nil || p.params == nil {
		return nil
	}
	newIv := C.GoBytes(unsafe.Pointer(p.params.pIv), C.int(p.params.ulIvLen))
	iv := make([]byte, len(newIv))
	copy(iv, newIv)
	return iv
}

// Free deallocates the memory reserved for the HSM to write back the actual IV.
//
// This must be called after the entire operation is complete, i.e. after
// Encrypt or EncryptFinal. It is safe to call Free multiple times.
func (p *GCMParams) Free() {
	if p == nil || p.arena == nil {
		return
	}
	p.arena.Free()
	p.params = nil
	p.arena = nil
}

// NewPSSParams creates a CK_RSA_PKCS_PSS_PARAMS structure and returns it as a byte array for use with the CKM_RSA_PKCS_PSS mechanism.
func NewPSSParams(hashAlg, mgf, saltLength uint) []byte {
	p := C.CK_RSA_PKCS_PSS_PARAMS{
		hashAlg: C.CK_MECHANISM_TYPE(hashAlg),
		mgf:     C.CK_RSA_PKCS_MGF_TYPE(mgf),
		sLen:    C.CK_ULONG(saltLength),
	}
	return memBytes(unsafe.Pointer(&p), unsafe.Sizeof(p))
}

// OAEPParams can be passed to NewMechanism to implement CKM_RSA_PKCS_OAEP.
type OAEPParams struct {
	HashAlg    uint
	MGF        uint
	SourceType uint
	SourceData []byte
}

// NewOAEPParams creates a CK_RSA_PKCS_OAEP_PARAMS structure suitable for use with the CKM_RSA_PKCS_OAEP mechanism.
func NewOAEPParams(hashAlg, mgf, sourceType uint, sourceData []byte) *OAEPParams {
	return &OAEPParams{
		HashAlg:    hashAlg,
		MGF:        mgf,
		SourceType: sourceType,
		SourceData: sourceData,
	}
}

func cOAEPParams(p *OAEPParams, arena arena) ([]byte, arena) {
	params := C.CK_RSA_PKCS_OAEP_PARAMS{
		hashAlg: C.CK_MECHANISM_TYPE(p.HashAlg),
		mgf:     C.CK_RSA_PKCS_MGF_TYPE(p.MGF),
		source:  C.CK_RSA_PKCS_OAEP_SOURCE_TYPE(p.SourceType),
	}
	if len(p.SourceData) != 0 {
		buf, len := arena.Allocate(p.SourceData)
		// field is unaligned on windows so this has to call into C
		C.putOAEPParams(&params, buf, len)
	}
	return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params)), arena
}


// ECDH1DeriveParams can be passed to NewMechanism to implement CK_ECDH1_DERIVE_PARAMS.
type ECDH1DeriveParams struct {
	KDF           uint
	SharedData    []byte
	PublicData []byte
}

// NewECDH1DeriveParams creates a CK_ECDH1_DERIVE_PARAMS structure suitable for use with the CKM_ECDH1_DERIVE mechanism.
func NewECDH1DeriveParams(p ECDH1DeriveParams) []byte {
	var params C.CK_ECDH1_DERIVE_PARAMS
	if len(p.SharedData) == 0  {
		params = C.CK_ECDH1_DERIVE_PARAMS{
			kdf :  C.CK_EC_KDF_TYPE(p.KDF),
			ulSharedDataLen: C.CK_ULONG(0),
			pSharedData: C.CK_BYTE_PTR(nil),
			ulPublicDataLen: C.CK_ULONG(len(p.PublicData)),
			pPublicData: C.CK_BYTE_PTR(unsafe.Pointer(&p.PublicData[0])),
		}
	} else {
		params = C.CK_ECDH1_DERIVE_PARAMS{
			kdf :  C.CK_EC_KDF_TYPE(p.KDF),
			ulSharedDataLen: C.CK_ULONG(len(p.SharedData)),
			pSharedData:  C.CK_BYTE_PTR(unsafe.Pointer(&p.SharedData[0])),
			ulPublicDataLen: C.CK_ULONG(len(p.PublicData)),
			pPublicData: C.CK_BYTE_PTR(unsafe.Pointer(&p.PublicData[0])),
		}
	}
        return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params))
}
/*
func cECDH1DeriveParams(p *ECDH1DeriveParams, arena arena) ([]byte, arena) {
	params := C.CK_ECDH1_DERIVE_PARAMS{
		kdf: C.CK_EC_KDF_TYPE(p.KDF),
	}

	// SharedData MUST be null if key derivation function (KDF) is CKD_NULL
	if len(p.SharedData) != 0 {
		sharedData, sharedDataLen := arena.Allocate(p.SharedData)
		C.putECDH1SharedParams(&params, sharedData, sharedDataLen)
	}

	publicKeyData, publicKeyDataLen := arena.Allocate(p.PublicKeyData)
	C.putECDH1PublicParams(&params, publicKeyData, publicKeyDataLen)

	return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params)), arena
}

/*
type RSAAESKeyWrapParams struct {
	AESKeyBits uint
	OAEPParams OAEPParams
}

func cRSAAESKeyWrapParams(p *RSAAESKeyWrapParams, arena arena) ([]byte, arena) {
	var param []byte
	params := C.CK_RSA_AES_KEY_WRAP_PARAMS {
		ulAESKeyBits: C.CK_MECHANISM_TYPE(p.AESKeyBits),
	}

	param, arena = cOAEPParams(&p.OAEPParams, arena)
	if len(param) != 0 {
		buf, _ := arena.Allocate(param)
		C.putRSAAESKeyWrapParams(&params, buf)
	}
	return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params)), arena
}
*/
/*
type  ECSGParams struct {
	Type  C.int
}
*/
func NewECSGParams( t C.int) []byte {
    p := make([]byte, 4)
    binary.BigEndian.PutUint32(p, uint32(t))	
    return p
}


type BTCDeriveParams struct {
        Type                 int    
        ChildKeyIndex        uint     
        ChainCode            []byte   
        Version              int      
}

func NewBTCDerviceParams( p BTCDeriveParams)  []byte {
	var params C.CK_IBM_BTC_DERIVE_PARAMS
	if len(p.ChainCode) == 0  {
	params = C.CK_IBM_BTC_DERIVE_PARAMS{
		    _type:          C.CK_ULONG(p.Type),          // ✅ Convert to C.CK_ULONG
    		    childKeyIndex: C.CK_ULONG(p.ChildKeyIndex), // ✅ Convert to C.CK_ULONG
    		    pChainCode:    (C.CK_BYTE_PTR)(nil), // ✅ Allocate memory for ChainCode
    		    ulChainCodeLen: C.CK_ULONG(0),             // ✅ Convert to C.CK_ULONG
    	 	    version:       C.CK_ULONG(p.Version),       // ✅ Convert to C.CK_ULONG
}
	} else {
	// Allocate slices of length 4 for integer fields
	params = C.CK_IBM_BTC_DERIVE_PARAMS{
		    _type:          C.CK_ULONG(p.Type),          // ✅ Convert to C.CK_ULONG
    		    childKeyIndex: C.CK_ULONG(p.ChildKeyIndex), // ✅ Convert to C.CK_ULONG
//    		    pChainCode:    (*C.CK_BYTE)(C.calloc(C.size_t(len(p.ChainCode)),1)), // ✅ Allocate memory for ChainCode
    		    pChainCode:    C.CK_BYTE_PTR(unsafe.Pointer(&p.ChainCode[0])),
    		    ulChainCodeLen: C.CK_ULONG(len(p.ChainCode)),             // ✅ Convert to C.CK_ULONG
    	 	    version:       C.CK_ULONG(p.Version),       // ✅ Convert to C.CK_ULONG
}
}

// Convert struct to bytes
return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params))
}


type  ECAGGParams struct {
	Version 	uint
	Mode 		uint
	PerElementSize 	uint
	Elements	[]byte
}


func NewECAGGParams( p ECAGGParams) []byte {
   params := C.XCP_EC_AGGREGATE_PARAMS{
	    version: 		C.CK_ULONG(p.Version),
	    mode: 		C.CK_ULONG(p.Mode),
	    perElementSize: 	C.CK_ULONG(p.PerElementSize),
	    pElements:  	C.CK_BYTE_PTR(unsafe.Pointer(&p.Elements[0])),
            ulElementsLen: 	C.CK_ULONG(len(p.Elements)),
     }
    return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params))
}


type  KyberParams struct {
	Version 	uint
	Mode 		C.CK_IBM_KEM_MODE
	Kdf		uint
	Prepend		bool
	Cipher		[]byte
	SharedData	[]byte
	Blob		[]byte
}


func getBytePtr(b []byte) C.CK_BYTE_PTR {
    if len(b) == 0 {
        return nil // Avoid passing a pointer to an empty slice
    }
    return (*C.CK_BYTE)(unsafe.Pointer(&b[0]))
}


func boolToCKBBool(b bool) C.CK_BBOOL {
    if b {
        return C.CK_BBOOL(1) // True → 1
    }
    return C.CK_BBOOL(0) // False → 0
}

func NewKyberParams(p KyberParams) []byte {
	params := C.XCP_KYBER_KEM_PARAMS_t{
        version:         C.CK_ULONG(p.Version),
        mode:            C.CK_IBM_KEM_MODE(p.Mode),
        kdf:             C.CK_ULONG(p.Kdf),
        prepend:        C.CK_BBOOL(boolToCKBBool(p.Prepend)),
        pCipher:         getBytePtr(p.Cipher),
        ulCipherLen:     C.CK_ULONG(len(p.Cipher)),
        pSharedData:     getBytePtr(p.SharedData),
        ulSharedDataLen: C.CK_ULONG(len(p.SharedData)),
        pBlob:           getBytePtr(p.Blob),
        ulBlobLen:       C.CK_ULONG(len(p.Blob)),
    }
    return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params))
}



type ETHDeriveParams struct {
	Version 	uint
	SigVersion 	uint
	Type 		uint
        ChildKeyIndex   uint     
	KeyInfo		[]byte
}

func NewETHDeriveParams( p ETHDeriveParams) []byte {
   var params C.CK_IBM_ETH_DERIVE_PARAMS
	if len(p.KeyInfo) == 0  {
   params = C.CK_IBM_ETH_DERIVE_PARAMS{
	    version: 		C.CK_ULONG(p.Version),
	    sigVersion: 	C.CK_ULONG(p.SigVersion),
	    _type:          	C.CK_ULONG(p.Type),          // ✅ Convert to C.CK_ULONG
 	    childKeyIndex: 	C.CK_ULONG(p.ChildKeyIndex), // ✅ Convert to C.CK_ULONG
	    pKeyInfo:  		C.CK_BYTE_PTR(nil),
            ulKeyInfoLen: 	C.CK_ULONG(0),
     }
	} else {
  		 params = C.CK_IBM_ETH_DERIVE_PARAMS{
		    version: 		C.CK_ULONG(p.Version),
		    sigVersion: 	C.CK_ULONG(p.SigVersion),
		    _type:          	C.CK_ULONG(p.Type),          // ✅ Convert to C.CK_ULONG
	 	    childKeyIndex: 	C.CK_ULONG(p.ChildKeyIndex), // ✅ Convert to C.CK_ULONG
		    pKeyInfo:  		C.CK_BYTE_PTR(unsafe.Pointer(&p.KeyInfo[0])),
	            ulKeyInfoLen: 	C.CK_ULONG(len(p.KeyInfo)),
     }
     }
    if (params.ulKeyInfoLen > C.XCP_EIP2333_KEYINFO_BYTES) {
	    fmt.Printf("KeyInfo too long")
	    return nil
    }

    return memBytes(unsafe.Pointer(&params), unsafe.Sizeof(params))
}
/*
typedef struct CK_IBM_ETH_DERIVE_PARAMS {
        CK_ULONG version;
        CK_ULONG sigVersion;
        CK_ULONG type;
        CK_ULONG childKeyIndex;
        CK_BYTE_PTR pKeyInfo;
        CK_ULONG ulKeyInfoLen;
} CK_IBM_ETH_DERIVE_PARAMS;
*/
