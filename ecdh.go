package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "os"
import "encoding/asn1"
import "encoding/hex"
import "ep11go/ep11"


type ecdhInfo struct {
        bitLen     int
        curveIDStr string
        curveID    asn1.ObjectIdentifier
        mechanism  uint
}

// ecPubKeyASN defines the ECDSA public key ASN1 encoding structure for GREP11
type ecPubKeyASN struct {
        Ident ecKeyIdentificationASN
        Point asn1.BitString
}


// ecKeyIdentificationASN defines the ECDSA priviate/public key identifier for GREP11
type ecKeyIdentificationASN struct {
        KeyType asn1.ObjectIdentifier
        Curve   asn1.ObjectIdentifier
}

// GetECPointFromSPKI extracts a coordinate bit array (EC point) from the public key in SPKI format
func GetECPointFromSPKI(spki []byte) ([]byte, error) {
        decode := &ecPubKeyASN{}
        _, err := asn1.Unmarshal(spki, decode)
        if err != nil {
                return nil, fmt.Errorf("failed unmarshaling public key: [%s]", err)
        }
        return decode.Point.Bytes, nil
}

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
       target := ep11.HsmInit("3.19") 

       alicesk,_ := hex.DecodeString(os.Args[1])
       bobecpk ,_:= hex.DecodeString(os.Args[2])

       ecdhCurves := []ecdhInfo{
                {224, "OIDNamedCurveP224", ep11.OIDNamedCurveP224, C.CKM_ECDH1_DERIVE},
                {256, "OIDNamedCurveP256", ep11.OIDNamedCurveP256, C.CKM_ECDH1_DERIVE},
                {384, "OIDNamedCurveP384", ep11.OIDNamedCurveP384, C.CKM_ECDH1_DERIVE},
                {528, "OIDNamedCurveP521", ep11.OIDNamedCurveP521, C.CKM_ECDH1_DERIVE},
                {256, "OIDNamedCurveSecp256k1", ep11.OIDNamedCurveSecp256k1, C.CKM_ECDH1_DERIVE},
                {256, "OIDNamedCurveX25519", ep11.OIDNamedCurveX25519, C.CKM_IBM_EC_X25519},
                {448, "OIDNamedCurveX448", ep11.OIDNamedCurveX448, C.CKM_IBM_EC_X448},
        }

       DeriveKeyTemplate := ep11.Attributes{
                C.CKA_CLASS:     C.CKO_SECRET_KEY,
                C.CKA_KEY_TYPE:  C.CKK_GENERIC_SECRET,
                C.CKA_VALUE_LEN: ecdhCurves[1].bitLen  / 8,
                C.CKA_IBM_USE_AS_DATA: true,
       }

        // Extract Bob's EC coordinates
        bobECCoordinates, err := GetECPointFromSPKI(bobecpk)
        if err != nil {
                panic(fmt.Errorf("Bob's EC key cannot obtain coordinates: %s", err))
        }

	Params := ep11.ECDH1DeriveParams{KDF: C.CKD_IBM_HYBRID_NULL, PublicData: bobECCoordinates} 

        aliceDerivekey, _, err :=  ep11.DeriveKey( target , 
                        ep11.Mech(ecdhCurves[1].mechanism,ep11.NewECDH1DeriveParams(Params)), 
                        alicesk ,
                        DeriveKeyTemplate  )  

        if err != nil {
                panic(fmt.Errorf("Derived Child Key request error: %s", err))
        }
        fmt.Printf("\nDerived AES key: %x\n\n",aliceDerivekey)
}
