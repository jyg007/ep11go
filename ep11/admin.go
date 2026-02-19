package  ep11

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>

*/
import "C"
import (
        "fmt"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
    "crypto"
    "crypto/rsa"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
 "errors"
)

// Simplified types to match your internal IBM types
type AdminBlock struct {
        AdmFunctionId  []byte  `asn1:"octet"`
        Domain         []byte  `asn1:"octet"`
        ModuleIdentifier []byte `asn1:"octet"`
        TransactionCtr   []byte `asn1:"octet"`
        Payload          []byte `asn1:"octet"`
}

type AdminResponseBlock struct {
    AdmFunctionId    []byte `asn1:"octet"`
    Domain           []byte `asn1:"octet"`
    ModuleIdentifier []byte  `asn1:"octet"`
    TransactionCtr   []byte  `asn1:"octet"`
    ResponseCode     []byte `asn1:"octet"` // return value (CKR_...)
    Response         []byte  `asn1:"octet"`
}

// Increment16ByteCounter increments a 16-byte big-endian counter by 1
func Increment16ByteCounter(counter []byte) []byte {
    if len(counter) != 16 {
        panic("counter must be 16 bytes")
    }

    // Convert bytes to big.Int
    n := new(big.Int).SetBytes(counter)
    n.Add(n, big.NewInt(1)) // increment

    // Convert back to 16 bytes
    b := n.Bytes()
    if len(b) > 16 {
        panic("counter overflowed 16 bytes")
    }

    // Left-pad with zeros if necessary
    padded := append(bytes.Repeat([]byte{0}, 16-len(b)), b...)
    return padded
}

func NewAdminBlock(admFuncID, domain, moduleID, tcounter, payload []byte) ([]byte, error) {
    block := AdminBlock{
        AdmFunctionId:    admFuncID,
        Domain:           domain,
        ModuleIdentifier: moduleID,
        TransactionCtr:   tcounter,
        Payload:          payload,
    }

    // Marshal to ASN.1 DER
    derBytes, err := asn1.Marshal(block)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal AdminBlock: %w", err)
    }

    return derBytes, nil
}

type AdminAttribute struct {
    Attribute uint32
    Value     uint32
}

func GenerateAttributeBytes(attrs []AdminAttribute) []byte {
    buf := make([]byte, 0, len(attrs)*8) // each attribute = 8 bytes

    for _, a := range attrs {
        indexBytes := make([]byte, 4)
        valueBytes := make([]byte, 4)

        binary.BigEndian.PutUint32(indexBytes, a.Attribute)
        binary.BigEndian.PutUint32(valueBytes, a.Value)

        buf = append(buf, indexBytes...)
        buf = append(buf, valueBytes...)
    }

    return buf
}

// ASN.1 structures for SignerInfo
type AlgorithmIdentifier struct {
    Algorithm  asn1.ObjectIdentifier
    Parameters asn1.RawValue `asn1:"optional"`
}

type SignerInfo struct {
    Version             int
    SubjectKeyIdentifier []byte  `asn1:"tag:0"`
    DigestAlgorithm     AlgorithmIdentifier
    SignatureAlgorithm  AlgorithmIdentifier
    Signature           []byte
}

// Helper to compute SKI from RSA public key (PKCS#1)
type pkcs1PublicKey struct {
    N *big.Int
    E int
}

// Example OIDs
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
var oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
var asnNull = asn1.RawValue{Tag: 5, Class: 0}


// parseRSAPrivateKeyPEM parses a PEM-encoded RSA private key.
// Supports both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY").
func parseRSAPrivateKeyPEM(privBytes []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(privBytes)
    if block == nil {
        return nil, errors.New("failed to decode PEM block")
    }

    switch block.Type {
    case "RSA PRIVATE KEY":
        // PKCS#1
        return x509.ParsePKCS1PrivateKey(block.Bytes)
    case "PRIVATE KEY":
        // PKCS#8
        key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
        if err != nil {
            return nil, err
        }
        rsaKey, ok := key.(*rsa.PrivateKey)
        if !ok {
            return nil, errors.New("not an RSA private key")
        }
        return rsaKey, nil
    default:
        return nil, errors.New("unsupported PEM type: " + block.Type)
    }
}

// GenerateSignatures generates the raw concatenated SignerInfo bytes
func GenerateSignatures(privKeys [][]byte, cmdBlock []byte) ([]byte, error) {
    var rawSigs []byte
    hash := sha256.Sum256(cmdBlock)
    
    for _, privBytes := range privKeys {
        // Parse private key
 	priv, err := parseRSAPrivateKeyPEM(privBytes)
        if err != nil {
            return nil, fmt.Errorf("failed to parse private key: %w", err)
        }

        // Compute SKI from public key
        pubBytes, err := asn1.Marshal(pkcs1PublicKey{
            N: priv.PublicKey.N,
            E: priv.PublicKey.E,
        })
        if err != nil {
            return nil, fmt.Errorf("failed to marshal public key: %w", err)
        }
        ski := sha256.Sum256(pubBytes)

        // Sign the hash
        sig, err := priv.Sign(rand.Reader, hash[:], crypto.SHA256)
        if err != nil {
            return nil, fmt.Errorf("sign returned %w", err)
        }

        // Build SignerInfo ASN.1 structure
        si := SignerInfo{
            Version: 3,
            SubjectKeyIdentifier: ski[:],
            DigestAlgorithm: AlgorithmIdentifier{
                Algorithm:  oidSHA256,
                Parameters: asnNull,
            },
            SignatureAlgorithm: AlgorithmIdentifier{
                Algorithm:  oidSHA256WithRSA,
                Parameters: asnNull,
            },
            Signature: sig,
        }

        // Marshal SignerInfo to ASN.1 DER
        der, err := asn1.Marshal(si)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal SignerInfo: %w", err)
        }

        // Append to rawSigs
        rawSigs = append(rawSigs, der...)
    }
    return rawSigs, nil
}


func AdminCommand(target C.target_t, hsmDomain uint32, admCmd uint32, payload []byte, privKeys [][]byte) (AdminResponseBlock, error) {

	resp , err:= AdminQuery(target,hsmDomain, C.XCP_ADMQ_DOMADMIN)        
        if err != nil {    
		return AdminResponseBlock{}, fmt.Errorf("failed to query domain : %w", err)
        }

    	var p1 [4]byte
        binary.BigEndian.PutUint32(p1[:], admCmd)
	//fmt.Print(resp.TransactionCtr)
	//fmt.Println()

        block :=  AdminBlock{
        	AdmFunctionId:    p1[:],
	        Domain:           resp.Domain,
        	ModuleIdentifier: resp.ModuleIdentifier,
	        TransactionCtr:   Increment16ByteCounter(resp.TransactionCtr),
        	Payload:          payload,
    	}

    	derBytes, err := asn1.Marshal(block)
    	if err != nil {
        	return AdminResponseBlock{}, fmt.Errorf("failed to marshal AdminBlock: %w", err)
   	 }

   	// 4️⃣ Generate signatures if private keys are provided
    	var signatures []byte
    	if privKeys != nil && len(privKeys) > 0 {
        	signatures, err = GenerateSignatures(privKeys, derBytes)
        	if err != nil {
            		return AdminResponseBlock{}, fmt.Errorf("failed to generate signatures: %w", err)
        	}
    	}
	// 5️⃣ Call EP11admin with command and optional signatures
	response, err := EP11admin(target,derBytes, signatures)
        if err != nil {
          return AdminResponseBlock{},    fmt.Errorf("EP11admin call failed: %w", err)
        }

    	// 6️⃣ Parse response
    	var rspBlock AdminResponseBlock
    	_, err = asn1.Unmarshal(response, &rspBlock)

   	if err != nil {
        	 return AdminResponseBlock{},    fmt.Errorf("Failed to unmarshall response: %w", err)
	}

    	rc := binary.BigEndian.Uint32(rspBlock.ResponseCode)
    	if rc != 0 {
		return AdminResponseBlock{}, toError(C.CK_RV(rc))
    	} 
 
	return rspBlock, nil
}

func AdminQuery(target C.target_t, hsmDomain uint32, admCmd uint32) (AdminResponseBlock, error) {
    var p1 [4]byte
    var p2 [8]byte

    // Admin function ID (e.g. XCP_ADMQ_DOM_ATTRS, XCP_ADMQ_WK, etc.)
    binary.BigEndian.PutUint32(p1[:], admCmd)

    // Domain encoding: domain value in high 32 bits
    binary.BigEndian.PutUint64(p2[:], uint64(hsmDomain)<<32)

    block := AdminBlock{
        AdmFunctionId: p1[:],
        Domain:        p2[:],
    }

    derBytes, err := asn1.Marshal(block)
    if err != nil {
        return AdminResponseBlock{}, fmt.Errorf("failed to marshal AdminBlock: %w", err)
    }

    response, err := EP11admin(target, derBytes, nil)
    if err != nil {
        return AdminResponseBlock{},    fmt.Errorf("EP11admin call failed: %w", err)
    }

    var rspBlock AdminResponseBlock
    _, err = asn1.Unmarshal(response, &rspBlock)
    if err != nil {
          return AdminResponseBlock{},    fmt.Errorf("Failed to unmarshall response: %w", err)
    }

    rc := binary.BigEndian.Uint32(rspBlock.ResponseCode)
    if rc != 0 {
	return AdminResponseBlock{}, toError(C.CK_RV(rc))
    } 
 
    return rspBlock, nil

}

