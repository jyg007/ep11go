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


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInit("3.19") 
 
      keyTemplate := ep11.Attributes{
	      C.CKA_VALUE_LEN: 16 ,
                C.CKA_UNWRAP: false,
                C.CKA_ENCRYPT: true,
      }

	for i:=0;i<1;i++ {
      		k, _ :=ep11.GenerateRandom(target, 128)
      		fmt.Println("Generated random 32 bytes Key:", hex.EncodeToString(k))
	}
	fmt.Println()

	var aeskey ep11.KeyBlob
	var Cipher,plain []byte
        var err error

       	aeskey, _ = ep11.GenerateKey(target,
                	ep11.Mech(C.CKM_AES_KEY_GEN, nil),
	                keyTemplate)
	fmt.Println("Generated Key:", hex.EncodeToString(aeskey))
	
	iv:= make([]byte,16)
        hex.Decode(iv,[]byte("3132333435360a"))
	Cipher,_ = ep11.EncryptSingle(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			[]byte("hello world hello world hello world"),
		)
	fmt.Println("Cipher:", hex.EncodeToString(Cipher))
        
	plain,err = ep11.DecryptSingle(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			Cipher,
		)
	if plain == nil {
		fmt.Println(err)
	} else {
		fmt.Println("Decrypted:", string(plain))
	}


        seed := make([]byte, hex.DecodedLen(len("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")))
        hex.Decode(seed, []byte("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"))
        keyTemplate = ep11.Attributes{
                C.CKA_VALUE_LEN:16 ,
                C.CKA_UNWRAP: true,
                C.CKA_WRAP: true,
                C.CKA_ENCRYPT: true,
                C.CKA_DECRYPT: true,
                C.CKA_EXTRACTABLE: true,
         }
       	aeskey, _ = ep11.GenerateKey(target,
                	ep11.Mech(C.CKM_AES_KEY_GEN, nil),
	                keyTemplate)
	Cipher,_ = ep11.EncryptSingle(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			seed,
		)
        secretPlainLen := len(seed)

        if secretPlainLen != 64 {
                panic(fmt.Errorf("Invalid plain secret"))
        }

	unwrapKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:C.CKK_GENERIC_SECRET,
                C.CKA_VALUE_LEN:secretPlainLen ,
                C.CKA_UNWRAP:false,
                C.CKA_WRAP: false,
                C.CKA_SIGN: true,
                C.CKA_VERIFY: true,
                C.CKA_DERIVE: true,
                C.CKA_IBM_USE_AS_DATA: true,
                C.CKA_EXTRACTABLE: false,
         }
        

	var masterseed ep11.KeyBlob
	masterseed,err = ep11.UnWrapKey(target, 
			ep11.Mech(C.CKM_AES_CBC_PAD, iv),
			aeskey ,
			Cipher,
			unwrapKeyTemplate,
		)

	if err != nil {
                        fmt.Println(err)
	} else {
	        fmt.Println("\nSeed Blob:", hex.EncodeToString(masterseed))
	}


	fmt.Printf("\n\n\n")

        ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true,
        }
	privateKeyECTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_SIGN:true,
		    C.CKA_PRIVATE:true,
		    C.CKA_SENSITIVE:true,
        }

	var pk, sk ep11.KeyBlob
	var  sig []byte
        pk, sk , _= ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("\n")
	fmt.Println("Generated public Key:", hex.EncodeToString(pk))

	sig,_ = ep11.SignSingle(target, ep11.Mech(C.CKM_ECDSA,nil),sk,[]byte("helloworld"))
	fmt.Println("Signature: ", hex.EncodeToString(sig))
 
        err = ep11.VerifySingle( target, ep11.Mech(C.CKM_ECDSA,nil),pk, []byte("helloworld"), sig)
	if err != nil   {
                        fmt.Println(err)
	}
        

	fmt.Printf("\n\n\n")

        ecParameters, err = asn1.Marshal(ep11.OIDNamedCurveED25519)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate = ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true,
        }
	privateKeyECTemplate = ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_SIGN:true,
		    C.CKA_PRIVATE:true,
		    C.CKA_SENSITIVE:true,
        }

        pk, sk , _= ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("\n")

	sig,_ = ep11.SignSingle(target, ep11.Mech(C.CKM_IBM_ED25519_SHA512,nil),sk,[]byte("helloworld"))
	fmt.Println("Signature: ", hex.EncodeToString(sig))
 
        err = ep11.VerifySingle( target, ep11.Mech(C.CKM_IBM_ED25519_SHA512,nil),pk, []byte("helloworld"), sig)
	if err != nil   {
                        fmt.Println(err)
	}



	fmt.Printf("\n\n\n")
	OIDBLS12_381ET := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 999, 3, 2}

        ecParameters, err = asn1.Marshal(OIDBLS12_381ET)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate = ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true, 
		    C.CKA_IBM_USE_AS_DATA: true,
		    C.CKA_KEY_TYPE: C.CKK_EC,

        }
	privateKeyECTemplate = ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_SIGN:true,
		    C.CKA_PRIVATE:true,
		    C.CKA_SENSITIVE:true,
		    C.CKA_IBM_USE_AS_DATA:true,
		    C.CKA_KEY_TYPE: C.CKK_EC,

        }

        pk, sk , _= ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)

	fmt.Println("Generated Private Key:", hex.EncodeToString(sk))
	fmt.Println("\n")
	fmt.Println("Generated public Key:", hex.EncodeToString(pk))

	sig,_ = ep11.SignSingle(target, ep11.Mech(C.CKM_IBM_ECDSA_OTHER,ep11.NewECSGParams(C.ECSG_IBM_BLS)),sk,[]byte("helloworld"))
	fmt.Println("Signature: ", hex.EncodeToString(sig))
 
        err = ep11.VerifySingle( target, ep11.Mech(C.CKM_IBM_ECDSA_OTHER,ep11.NewECSGParams(C.ECSG_IBM_BLS)),pk, []byte("helloworld"), sig)
	if err != nil   {
                        fmt.Println(err)
	}


        ecParameters, _ = asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
	DeriveKeyTemplate := ep11.Attributes{
		    C.CKA_EC_PARAMS:ecParameters,
		    C.CKA_VERIFY:true,
		    C.CKA_DERIVE:true,
		    C.CKA_PRIVATE:true,
		    C.CKA_SENSITIVE:true,
		    C.CKA_IBM_USE_AS_DATA:true,
		    C.CKA_KEY_TYPE: C.CKK_ECDSA,
                    C.CKA_VALUE_LEN:0,

        }


	Params := ep11.BTCDeriveParams{Type: C.CK_IBM_SLIP0010_MASTERK, ChildKeyIndex: 0, ChainCode: nil, Version : 1,} 

	var NewKey,k2,ChainCode ep11.KeyBlob
NewKey, ChainCode, err =  ep11.DeriveKey(target , 
			ep11.Mech(C.CKM_IBM_BTC_DERIVE,ep11.NewBTCDerviceParams(Params)) , 
			masterseed,
			DeriveKeyTemplate  )  
        
	fmt.Println("\nMasterseed:", hex.EncodeToString(NewKey))
	fmt.Println("ChainCode:", hex.EncodeToString(ChainCode))

	Params = ep11.BTCDeriveParams{Type: C.CK_IBM_SLIP0010_PRV2PUB, ChildKeyIndex: 0, ChainCode: ChainCode, Version : 1,} 
k2, ChainCode, err =  ep11.DeriveKey(target , 
			ep11.Mech(C.CKM_IBM_BTC_DERIVE,ep11.NewBTCDerviceParams(Params)) , 
			NewKey,
			DeriveKeyTemplate  )  
        
	fmt.Println("\nChildpub:", hex.EncodeToString(k2))
	fmt.Println("ChainCode:", hex.EncodeToString(ChainCode))
}
