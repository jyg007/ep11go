package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>
#include <openssl/evp.h>
#include <stdlib.h>

*/
import "C"
import "ep11go/ep11"
import (
	"encoding/binary"
	"fmt"
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"encoding/asn1"
    	"crypto/rand"
    	"crypto/rsa"
    	"crypto/x509"
    	"crypto"
    	"crypto/sha256"
    	"crypto/x509/pkix"
    	"math/big"
    	"time"
	"os"
        "strconv"
	"log"
)

func DomainMask(index, domain uint32) uint32 {
    if domain < index || domain >= index+32 {
        return 0
    }

    offset := uint(domain - index)
    return 1 << (31 - offset)
}


// build inner TLV: [type][id][data]
func buildTLV(t uint16, id uint32, data []byte) []byte {
        buf := new(bytes.Buffer)
        _ = binary.Write(buf, binary.BigEndian, t)
        _ = binary.Write(buf, binary.BigEndian, id)
        buf.Write(data)
        return buf.Bytes()
}

// ASN.1 length encoding (simple form)
func encLen(l int) []byte {
        if l < 128 {
                return []byte{byte(l)}
        }
        // simplified long form
        b := []byte{byte(0x80 | 4)}
        tmp := make([]byte, 4)
        binary.BigEndian.PutUint32(tmp, uint32(l))
        return append(b, tmp...)
}

// wrap OCTET STRING
func octetString(data []byte) []byte {
        return append(append([]byte{0x04}, encLen(len(data))...), data...)
}

// wrap SEQUENCE
func sequence(items [][]byte) []byte {
        var body bytes.Buffer
        for _, i := range items {
                body.Write(i)
        }
        return append(append([]byte{0x30}, encLen(body.Len())...), body.Bytes()...)
}


func buildexportrequest(cert []byte, domain uint32) []byte {

        // x001C = number of KPHs
        x001C := octetString(buildTLV(0x001C, 0x00000001, []byte{}))

        // x001D = certs
        x001D := octetString(buildTLV(0x001D, 0x00000000, cert))
//      x001D_2 := octetString(buildTLV(0x001D, 0x00000001, certs.Bytes()))
        x0003 := octetString(buildTLV(0x0003, DomainMask(0,domain), []byte{}))
        x001F := octetString(buildTLV(0x001F, 0x00000008, []byte{}))

        // full module state SEQUENCE
        out := sequence([][]byte{
                x001C,
                x0003,
                x001D,
//              x001D_2,
                x001F,
        })

       // fmt.Printf("%x\n", out)
       return out
}



type node struct {
	class       int
	isCompound  bool
	tag         int
	length      int
	headerLen   int
	valueOffset int
	totalLen    int
}

// decode your inner TLV
func decodeTLV(v []byte) (t uint16, id uint32, payload []byte, ok bool) {
	if len(v) < 6 {
		return 0, 0, nil, false
	}

	t = binary.BigEndian.Uint16(v[0:2])
	id = binary.BigEndian.Uint32(v[2:6])
	payload = v[6:]
	ok = true
	return
}


// parse ASN.1 TLV header
func parseNode(data []byte) (node, []byte, error) {
        if len(data) < 2 {
                return node{}, nil, fmt.Errorf("too short")
        }

        n := node{}

        first := data[0]
        n.class = int(first & 0xC0)
        n.isCompound = (first & 0x20) != 0
        n.tag = int(first & 0x1F)

        length := int(data[1])
        offset := 2

        // long form length
        if length&0x80 != 0 {
                numBytes := length & 0x7F
                length = 0
                for i := 0; i < numBytes; i++ {
                        length = (length << 8) | int(data[offset])
                        offset++
                }
        }

        n.length = length
        n.headerLen = offset
        n.valueOffset = offset
        n.totalLen = offset + length

        if len(data) < n.totalLen {
                return n, nil, fmt.Errorf("truncated data")
        }

        return n, data[n.totalLen:], nil
}


func dump2(data []byte) ([]byte, error) {
	for len(data) > 0 {
		n, rest, err := parseNode(data)
		if err != nil {
			return nil, err
		}

		if n.tag == 4 && !n.isCompound {
			value := data[n.valueOffset : n.valueOffset+n.length]
			t, _, payload, ok := decodeTLV(value)
			if ok && t == 0x0019 {
				return payload, nil
			}
		}

		value := data[n.valueOffset : n.valueOffset+n.length]

		if n.isCompound {
			payload, err := dump2(value)
			if err != nil {
				return nil, err
			}
			if payload != nil {
				return payload, nil
			}
		}

		data = rest
	}

	return nil, nil // not found
}

func dump(data []byte )  {
        for len(data) > 0 {
                n, rest, err := parseNode(data)
                if err != nil {
                        fmt.Println("ERR:", err)
                }

//                fmt.Printf("%sClass=%d Tag=%d Compound=%v Len=%d\n", indent, n.class, n.tag, n.isCompound, n.length)
		if n.tag == 4 && !n.isCompound {
			value := data[n.valueOffset : n.valueOffset+n.length]
			t, _ , payload, ok := decodeTLV(value)
			if ok && t == 0x0019 {
				fmt.Printf("%x\n", payload)
			}
		}

                value := data[n.valueOffset : n.valueOffset+n.length]

                if !n.isCompound {
                    //    fmt.Printf("%s  Value(hex): %x\n", indent, value)
                } else {
                        dump(value)
                }

                data = rest
        }
}


func wrapSPKI(spki []byte) ([]byte, *rsa.PublicKey, error) {
        // Parse SPKI directly
        pub, err := x509.ParsePKIXPublicKey(spki)
        if err != nil {
                return nil, nil, fmt.Errorf("failed parsing public key: %w", err)
        }

        rsaPub, ok := pub.(*rsa.PublicKey)
        if !ok {
                return nil, nil, fmt.Errorf("not an RSA public key")
        }

        // Generate signing key (issuer key)
        issuerKey, err := rsa.GenerateKey(rand.Reader, 4096)
        if err != nil {
                return nil, nil, fmt.Errorf("failed generating signing key: %w", err)
        }

        tmpl := &x509.Certificate{
                SerialNumber: big.NewInt(1),
                Subject: pkix.Name{
                        Organization: []string{"mycorp"},
                },
                DNSNames:              []string{"localhost"},
                NotBefore:             time.Now().Add(-time.Hour),
                NotAfter:              time.Now().Add(180 * 24 * time.Hour),
                IsCA:                  true,
                ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
                BasicConstraintsValid: true,
        }

        der, err := x509.CreateCertificate(
                rand.Reader,
                tmpl,
                tmpl,
                rsaPub,     // embedded public key
                issuerKey,  // signing key
        )
        if err != nil {
                return nil, nil, fmt.Errorf("failed creating certificate: %w", err)
        }

        return der, rsaPub, nil
}

func parsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    return x509.ParsePKCS1PrivateKey(block.Bytes)
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"tag:0,explicit,optional"`
}

type SignerIdentifier struct {
	IssuerAndSerialNumber IssuerAndSerialNumber `asn1:"optional"`
	// OR SubjectKeyIdentifier []byte `asn1:"tag:0,implicit,optional"`
}


type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber asn1.RawValue
}

type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type SignerInfo struct {
	Version            int
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"tag:0,implicit,set"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
}

type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	SignerInfos      []SignerInfo `asn1:"set"`
}
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}
var (
	oidSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidContentType            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)
var asnNull = asn1.RawValue{Tag: 5, Class: 0}

func BuildSignedData(
	payload []byte,           // importer public key DER
	signerCert *x509.Certificate,
	signerKey *rsa.PrivateKey,
) ([]byte, error) {

	// Digest payload
	hash := sha256.Sum256(payload)

oidDataDER, _ := asn1.Marshal(oidData)
//digestDER, _ := asn1.Marshal(hash[:])

signedAttrs := []Attribute{
    {
        Type: oidContentType,
        Values: []asn1.RawValue{
            {
                Class: asn1.ClassUniversal,
                Tag:   asn1.TagOID,
                Bytes: oidDataDER,
            },
        },
    },
    {
        Type: oidMessageDigest,
        Values: []asn1.RawValue{
            {
                Class: asn1.ClassUniversal,
                Tag:   asn1.TagOctetString,
                Bytes: hash[:], // OCTET STRING content, not DER
            },
        },
    },
}
	// DER encode signedAttrs (SET OF)
	signedAttrsDER, _ := asn1.MarshalWithParams(signedAttrs, "set")

	// Sign attributes
	attrHash := sha256.Sum256(signedAttrsDER)
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		signerKey,
		crypto.SHA256,
		attrHash[:],
	)
	if err != nil {
		return nil, err
	}
certRaw := asn1.RawValue{
    Class:      asn1.ClassContextSpecific,
    Tag:        0,
    IsCompound: true,
    Bytes:      signerCert.Raw,
}

eContentDER, _ := asn1.Marshal(payload)
eContentRaw := asn1.RawValue{
    Class:      asn1.ClassContextSpecific,
    Tag:        0, // [0] EXPLICIT
    IsCompound: true,
    Bytes:      eContentDER, // your marshaled payload
}


	sd := SignedData{
		Version: 1,
		DigestAlgorithms: []AlgorithmIdentifier{
			{
				Algorithm:  oidSHA256,
 Parameters: asn1.RawValue{
            Class:      asn1.ClassUniversal,
            Tag:        asn1.TagNull,
            IsCompound: false,
            Bytes:      nil,
        },
			},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: oidData,
 			EContent:     eContentRaw.FullBytes,
		},
		Certificates: certRaw,
		SignerInfos: []SignerInfo{
			{
				Version: 1,
				SID: IssuerAndSerialNumber{
					Issuer:       asn1.RawValue{FullBytes: signerCert.RawIssuer},
					SerialNumber: asn1.RawValue{Tag: asn1.TagInteger, Bytes: signerCert.SerialNumber.Bytes()},
				},
				DigestAlgorithm: AlgorithmIdentifier{
					Algorithm:  oidSHA256,
					Parameters: asn1.RawValue{Tag: asn1.TagNull},
				},
				SignedAttrs: signedAttrs,
				SignatureAlgorithm: AlgorithmIdentifier{
					Algorithm:  oidSHA256WithRSA,
					Parameters: asn1.RawValue{Tag: asn1.TagNull},
				},
				Signature: signature,
			},
		},
	}

	sdDER, _ := asn1.Marshal(sd)

	ci := ContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	}

	return asn1.Marshal(ci)
}


type WrappedKey struct {
	Version      int
        PublicKey  asn1.RawValue `asn1:"tag:0,optional"`
	Algorithm    AlgorithmIdentifier
	EncryptedKey []byte
}

func getexport( der []byte) {
	var obj WrappedKey

	_, err := asn1.Unmarshal(der, &obj)
	if err != nil {
		fmt.Fprintf(os.Stderr,"Error %v",err)
	}

	fmt.Println("SEQUENCE")
	fmt.Printf("  INTEGER %d\n", obj.Version)
	fmt.Println("  SEQUENCE")
	fmt.Printf("    OBJECT IDENTIFIER %s\n", obj.Algorithm.Algorithm.String())
	fmt.Printf("  OCTET STRING %x\n", obj.EncryptedKey)
}

func main() {
        if len(os.Args) != 4 {
                fmt.Fprintf(os.Stderr, "usage: %s <control-domain> <domain> <export certificates>\n", os.Args[0])
        }

        // 1) Control domain (e.g. "3.19")
        controlDomain := os.Args[1]

        // 2) Target domain (e.g. 16)
        domain64, err := strconv.ParseUint(os.Args[2], 10, 32)
        domain := uint32(domain64)
        if err != nil {
                fmt.Fprintf(os.Stderr, "invalid domain: %v\n", err)
                os.Exit(1)
        }

        target := ep11.HsmInit(controlDomain) 

	
// **********************************************************************************************************************
//    HSM DOMAIN Admin pub der + private key
// **********************************************************************************************************************
	args   := os.Args[4:]

	privadmin1Bytes, err := ep11.LoadKeyBytes(args)

// **********************************************************************************************************************
// **********************************************************************************************************************
/*
	var attr[4]byte
        binary.BigEndian.PutUint32(attr[:], C.XCP_IMPRKEY_RSA_4096)
	
	resp , err := ep11.AdminCommand(target,40, C.XCP_ADM_GEN_DOM_IMPORTER,attr[:],[][]byte{privadmin1Bytes})        
        if err != nil {    
            fmt.Println(err)
        }
*/
//	fmt.Printf("%x\n",resp.Response)
// **********************************************************************************************************************
// **********************************************************************************************************************
	//importKey,_ ,_:= wrapSPKI(resp.Response)
//	fmt.Printf("%x",importKey)
        certStr,_ :=hex.DecodeString(os.Args[3])
	req := buildexportrequest(certStr, domain)
	
	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_EXPORT_WK, req ,[][]byte{privadmin1Bytes})        

        if err != nil {    
            fmt.Println(err)
        }
	payload, err := dump2(resp.Response)
if err != nil {
	log.Fatal(err)
}

if payload != nil {
	fmt.Printf("Payload: %x\n", payload)
	getexport(payload)
}
//	getexport(dump(resp.Response))
	//fmt.Printf("%x\n",resp.Response)
	//fmt.Printf("%x\n",resp.ResponseCode)

}
