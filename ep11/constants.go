package ep11

import "encoding/asn1"

const (
        // Maximum Key Size
        MAX_BLOB_SIZE = 8192

        MAX_CSUMSIZE = 64

        // Max block size of block ciphers
        MAX_BLOCK_SIZE = 256 / 8
        AES_BLOCK_SIZE = 16
        DES_BLOCK_SIZE = 8

        // Max digest output bytes
        MAX_DIGEST_BYTES = 512 / 8 

        // MAX_DIGEST_STATE_BYTES is the maximum size of wrapped digest state blobs
        //   -- Section 10.1 Function descriptions, EP11 design Document
        MAX_DIGEST_STATE_BYTES = 1024
        MAX_CRYPT_STATE_BYTES  = 8192

        CK_UNAVAILABLE_INFORMATION uint64 = 0xFFFFFFFFFFFFFFFF
)

var (

	// The following variables are standardized elliptic curve definitions
	OIDNamedCurveP224      = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	OIDNamedCurveP256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDNamedCurveP384      = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDNamedCurveP521      = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	OIDNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	OIDNamedCurveX25519    = asn1.ObjectIdentifier{1, 3, 101, 110}
	OIDNamedCurveX448      = asn1.ObjectIdentifier{1, 3, 101, 111}
	OIDNamedCurveED25519   = asn1.ObjectIdentifier{1, 3, 101, 112}
	OIDNamedCurveED448     = asn1.ObjectIdentifier{1, 3, 101, 113}

	// The following variables are regular brainpool elliptic curve definitions
	OIDBrainpoolP160r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 1}
	OIDBrainpoolP192r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 3}
	OIDBrainpoolP224r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 5}
	OIDBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	OIDBrainpoolP320r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 9}
	OIDBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}

	// The following variables are twisted brainpool elliptic curve definitions
	OIDBrainpoolP160t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 2}
	OIDBrainpoolP192t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 4}
	OIDBrainpoolP224t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 6}
	OIDBrainpoolP256t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 8}
	OIDBrainpoolP320t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 10}
	OIDBrainpoolP384t1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 12}

	// Public key object identifiers
	OIDECPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OIDRSAPublicKey = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDDSAPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}     // RFC 3279, 2.3.2  DSA Signature Keys
	OIDDHPublicKey  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1} // PKCS#3, 9. Object identifier

	// Supported Dilithium round 2 strengths with SHAKE-256 as PRF
	OIDDilithiumHigh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 1, 6, 5}
	OIDDilithium87   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 1, 8, 7}

	// Supported Dilithium round 3 strengths with SHAKE-256 as PRF
	OIDDilithiumR3Weak  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 4, 4}
	OIDDilithiumR3Rec   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 6, 5}
	OIDDilithiumR3VHigh = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 7, 8, 7}

	// Supported Kyber round 2 strengths with SHAKE-128 as PRF
	OIDKyberR2Rec  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 5, 3, 3}
	OIDKyberR2High = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 5, 4, 4}

	// Supported BLS12-381 OIDs
	OIDBLS12_381ET = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 2, 267, 999, 3, 2}
)
