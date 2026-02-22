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
	"encoding/hex"
    	"crypto/rand"
    	"crypto/rsa"
    	"crypto/x509"
    	"crypto/x509/pkix"
	"crypto/sha256"
    	"math/big"
    	"time"
	"os"
        "strconv"
	"log"
)

func printSKIs(payload []byte) {
    const skiSize = 32
    count := len(payload) / skiSize

    fmt.Printf("Detected %d full SKIs (SHA-256):\n", count)

    for i := 0; i < count; i++ {
        start := i * skiSize
        end := start + skiSize
        fmt.Printf("Admin %d SKI: %x\n", i+1, payload[start:end])
    }

    // Check for trailing data (if the payload was 92 instead of 96)
    if len(payload)%skiSize != 0 {
        remainder := payload[count*skiSize:]
        fmt.Printf("Trailing/Partial Data (%d bytes): %x\n", len(remainder), remainder)
    }
}


func adminAttrName(index uint32) string {
    switch index {
    case 1:
        return "XCP_ADMINT_SIGN_THR"
    case 2:
        return "XCP_ADMINT_REVOKE_THR"
    case 3:
        return "XCP_ADMINT_PERMS"
    case 4:
        return "XCP_ADMINT_MODE"
    case 5:
        return "XCP_ADMINT_STD"
    case 6:
        return "XCP_ADMINT_PERMS_EXT01"
    case 7:
        return "XCP_ADMINT_GEN_KTYPES"
    case 8:
        return "XCP_ADMINT_ECC_KTYPES"
    case 9:
        return "XCP_ADMINT_DIL_KTYPES"
    case 10:
        return "XCP_ADMINT_ADM_COMPL"
    default:
        return fmt.Sprintf("UNKNOWN_%d", index)
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
                KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
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

func main() {
        if len(os.Args) < 3 {
                fmt.Fprintf(os.Stderr,
                        "usage: %s <control-domain> <domain> --key-file <file>] [--key-hex <hex>],\n",
                        os.Args[0],
                )
                os.Exit(1)
        }

        controlDomain := os.Args[1]

        domain64, err := strconv.ParseUint(os.Args[2], 10, 32)
        if err != nil {
                log.Fatalf("invalid domain: %v", err)
        }
        domain := uint32(domain64)

        target := ep11.HsmInit(controlDomain)

        args   := os.Args[3:]
        privadmin1Bytes, err := ep11.LoadKeyBytes(args)
        if err != nil {
                  log.Fatal(err)
                  return
        }
	skiBytes, err := ep11.LoadSKIBytes(args)
                if err != nil {
                        log.Fatal(err)
        }

	// MEK to import
	mekhex := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

// **********************************************************************************************************************
// SET ATTRIBUTES - IMPRINTNG
// **********************************************************************************************************************
	attrs := []ep11.AdminAttribute{
        	{Attribute: C.XCP_ADMINT_SIGN_THR , Value: 1}, 
        	{Attribute: C.XCP_ADMINT_REVOKE_THR, Value: 1},
        	{Attribute: C.XCP_ADMINT_PERMS, Value: uint32(C.XCP_ADMP_WK_RANDOM | C.XCP_ADMP_WK_IMPORT | C.XCP_ADMP_WK_EXPORT | C.XCP_ADMP_WK_1PART | C.XCP_ADMP_1SIGN | C.XCP_ADMP_CHG_1SIGN | C.XCP_ADMP_CP_1SIGN | C.XCP_ADMP_CHG_SIGN_THR | C.XCP_ADMP_CHG_REVOKE_THR )}, 
    	}

	attrsBytes	:= ep11.GenerateAttributeBytes(attrs)

	resp , err := ep11.AdminCommand(target,domain, C.XCP_ADM_DOM_SET_ATTR,attrsBytes,[][]byte{privadmin1Bytes})        
        if err != nil {    
            fmt.Println(err)
        }

// **********************************************************************************************************************
// **********************************************************************************************************************
	var attr[4]byte
        binary.BigEndian.PutUint32(attr[:], C.XCP_IMPRKEY_RSA_4096)
	
	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_GEN_DOM_IMPORTER,attr[:],[][]byte{privadmin1Bytes})        
        if err != nil {    
	    
            fmt.Println(err)
        }
	fmt.Println()

// **********************************************************************************************************************
// **********************************************************************************************************************
        _, importKey, err := wrapSPKI(resp.Response)

	mek, _ := hex.DecodeString(mekhex)
	mkvp := sha256.Sum256(append([]byte{1},mek ...))

	encmek, err := rsa.EncryptPKCS1v15(rand.Reader, importKey, mek)
        fmt.Printf("mkvp        %x\n",mkvp)

	signedmek , err := ep11.SignKeyPart(target,domain, encmek,  skiBytes, privadmin1Bytes)
 	if err != nil {    
            fmt.Println(err)
        }

	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_IMPORT_WK, signedmek,nil)        
        if err != nil {    
            fmt.Println(err)
        }
//	fmt.Printf("new pending mkxp %x\n",resp.Response)

              
// **********************************************************************************************************************
// **********************************************************************************************************************
   
	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_COMMIT_WK,resp.Response[:32] ,[][]byte{privadmin1Bytes})        
        if err != nil {    
            fmt.Println(err)
        }
//	fmt.Printf("committed mkvp %x\n",resp.Response)
	
	resp , err = ep11.AdminCommand(target,domain, C.XCP_ADM_FINALIZE_WK,mkvp[:],nil)        
        if err != nil {    
            fmt.Println(err)
        }
	fmt.Printf("active mkvp %x\n",resp.Response)

}
