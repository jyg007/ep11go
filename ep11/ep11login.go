package  ep11

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>
#include <openssl/evp.h>
#include <stdlib.h>

*/
import "C"
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"crypto/aes"
	"errors"
	"unsafe"
)


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################


const (
	XCP_LOGIN_ALG_F2021  = 2
	XCP_LOGIN_IMPR_EC_P521 = 2
	// AES wrapping key length
	XCP_WK_BYTES = 32 // 256-bit AES key

	// salt used in PIN blob rewrapping
	XCP_SESSION_SALT_BYTES = 128 / 8 // 16 bytes

	// transaction counter
	XCP_SESSION_TCTR_BYTES = 128 / 8 // 16 bytes

	// AES/KW MAC
	XCP_SESSION_MAC1_BYTES = 64 / 8 // 8 bytes

	// full v1 (FIPS/2021) PIN blob size
	XCP_PINBLOB_V1_BYTES = XCP_WK_BYTES + XCP_SESSION_SALT_BYTES + XCP_SESSION_MAC1_BYTES // 32+16+8=56
	EP11_PINBLOB_MARKER_OFS = 4
	EP11_PINBLOB_V1_MARKER = 0xab

	FNID_LoginExtended  = 43
	FNID_LogoutExtended = 44
)
var OIDIBMmiscEP11SessionInfo = []byte{
    0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0x02, 0x82, 0x0b, 0x87, 0x67, 0x04, 0x01,
}

// nonce structure
type nonceT struct {
	SlotID  uint32
	Purpose [12]byte
}

// aes256KWPEncrypt implements AES-256 key wrap with padding (RFC 5649)
func aes256KWPEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// RFC 5649 padding: pad to multiple of 8 bytes
	n := len(plaintext)
	padLen := 8 - (n % 8)
	if padLen == 8 {
		padLen = 0
	}
	padded := make([]byte, n+padLen)
	copy(padded, plaintext)
	// padding bytes are zeros (per RFC 5649)

	// A = initial register = 64-bit default IV for RFC 5649
	A := []byte{0xA6, 0x59, 0x59, 0xA6, 0x00, 0x00, 0x00, byte(n)}

	// R blocks: divide padded plaintext into 64-bit blocks
	rCount := len(padded) / 8
	R := make([][]byte, rCount)
	for i := 0; i < rCount; i++ {
		R[i] = padded[i*8 : (i+1)*8]
	}

	// 6 * n rounds
	for j := 0; j < 6; j++ {
		for i := 0; i < rCount; i++ {
			// B = AES(K, A | R[i])
			B := make([]byte, 16)
			copy(B[:8], A)
			copy(B[8:], R[i])
			block.Encrypt(B, B)

			// A = MSB(64, B) ^ t, t = (n*j)+i+1
			t := uint64((rCount*j + i + 1))
			for k := 0; k < 8; k++ {
				A[k] = B[k] ^ byte(t>>(56-8*k))
			}

			// R[i] = LSB(64, B)
			copy(R[i], B[8:])
		}
	}

	// concatenate A || R[0] || R[1] ...
	ciphertext := make([]byte, 8+rCount*8)
	copy(ciphertext, A)
	for i := 0; i < rCount; i++ {
		copy(ciphertext[8+i*8:], R[i])
	}

	return ciphertext, nil
}

// helper to convert uint64 t to 8-byte big-endian
func uint64ToBytes(t uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, t)
	return b
}


// aes256KWPDecrypt performs RFC5649 AES-256 key unwrap with padding
func aes256KWPDecrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256 key must be 32 bytes")
	}

	if len(ciphertext) < 16 || len(ciphertext)%8 != 0 {
		return nil, errors.New("invalid ciphertext length")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	n := (len(ciphertext) / 8) - 1

	// A || R[1]..R[n]
	A := make([]byte, 8)
	copy(A, ciphertext[:8])

	R := make([][]byte, n)
	for i := 0; i < n; i++ {
		R[i] = make([]byte, 8)
		copy(R[i], ciphertext[8+i*8:])
	}

	// RFC5649 unwrap rounds (reverse order)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)

			B := make([]byte, 16)

			// (A ^ t) || R[i]
			for k := 0; k < 8; k++ {
				B[k] = A[k] ^ byte(t>>(56-8*k))
			}
			copy(B[8:], R[i])

			block.Decrypt(B, B)

			copy(A, B[:8])
			copy(R[i], B[8:])
		}
	}

	// RFC5649 integrity check
	if A[0] != 0xA6 || A[1] != 0x59 || A[2] != 0x59 || A[3] != 0xA6 {
		return nil, errors.New("KWP integrity check failed")
	}

	msgLen := binary.BigEndian.Uint32(A[4:8])

	// concatenate R blocks
	out := make([]byte, n*8)
	for i := 0; i < n; i++ {
		copy(out[i*8:], R[i])
	}

	if int(msgLen) > len(out) {
		return nil, errors.New("invalid recovered length")
	}

	return out[:msgLen], nil
}



// derivePinblobKey mirrors derive_pinblob_key() from C
func derivePinblobKey(pinblob []byte, pin []byte) ([]byte, error) {

	if len(pinblob) != 48 {
		return nil, errors.New("pinblob length invalid")
	}

	// Optional: marker check if you have it defined
	// if pinblob[EP11_PINBLOB_MARKER_OFS] != EP11_PINBLOB_V1_MARKER {
	//	return nil, errors.New("pinblob marker invalid")
	// }

	h := sha256.New()

	var tmp4 [4]byte

	// BE32(1)
	binary.BigEndian.PutUint32(tmp4[:], 1)
	h.Write(tmp4[:])

	// BE32(3)
	binary.BigEndian.PutUint32(tmp4[:], 3)
	h.Write(tmp4[:])

	// PIN
	h.Write(pin)

	// BE8(0)
	h.Write([]byte{0})

	// s = pinblob + XCP_WK_BYTES, length 16
	h.Write(pinblob[C.XCP_WK_BYTES : C.XCP_WK_BYTES+16])

	key := h.Sum(nil)

	if len(key) != 32 {
		return nil, errors.New("SHA256 returned wrong size")
	}

	return key, nil
}


// ECDHDerive derives a shared secret from our private key and the peer's public key.
// This mirrors EVP_PKEY_derive in C.
func ECDHDerive(priv *ecdsa.PrivateKey, peerPub *ecdsa.PublicKey) ([]byte, error) {
	if priv.Curve != peerPub.Curve {
		return nil, fmt.Errorf("curve mismatch between private and peer public key")
	}

	// ECDH: shared point = peerPub * priv.D
	x, _ := priv.Curve.ScalarMult(peerPub.X, peerPub.Y, priv.D.Bytes())

	// Return x-coordinate as the shared secret
	// This is exactly what OpenSSL does for EVP_PKEY_derive with EC
	secret := x.Bytes()

	// Ensure secret has fixed length (padded to curve size in bytes)
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	if len(secret) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(secret):], secret)
		secret = padded
	}

	return secret, nil
}

// berDecodeSequence parses a DER SEQUENCE from input.
// Returns:
// - data: the payload of the SEQUENCE
// - fieldLen: total bytes consumed (tag + length + payload)
// - error if decoding fails
func berDecodeSequence(input []byte) (data []byte, fieldLen int, err error) {
    if len(input) < 2 {
        return nil, 0, fmt.Errorf("input too short")
    }
    if input[0] != 0x30 { // SEQUENCE tag
        return nil, 0, fmt.Errorf("not a SEQUENCE")
    }

    var length int
    var headerLen int

    if input[1]&0x80 == 0 { // short form
        length = int(input[1] & 0x7F)
        headerLen = 2
    } else { // long form
        lengthOctets := int(input[1] & 0x7F)
        switch lengthOctets {
        case 1:
            if len(input) < 3 {
                return nil, 0, fmt.Errorf("input too short for 1-length octet")
            }
            length = int(input[2])
            headerLen = 3
        case 2:
            if len(input) < 4 {
                return nil, 0, fmt.Errorf("input too short for 2-length octets")
            }
            length = int(input[2])<<8 | int(input[3])
            headerLen = 4
        case 3:
            if len(input) < 5 {
                return nil, 0, fmt.Errorf("input too short for 3-length octets")
            }
            length = int(input[2])<<16 | int(input[3])<<8 | int(input[4])
            headerLen = 5
        default:
            return nil, 0, fmt.Errorf("length octets > 3 not supported")
        }
    }

    if headerLen+length > len(input) {
        return nil, 0, fmt.Errorf("sequence length mismatch")
    }

    data = input[headerLen : headerLen+length]
    fieldLen = headerLen + length
    return data, fieldLen, nil
}

// berDecodeOctetString parses a DER OCTET STRING from input.
// Returns:
// - data: the contents of the OCTET STRING
// - fieldLen: total bytes consumed (tag + length + payload)
// - error if decoding fails
func berDecodeOctetString(input []byte) (data []byte, fieldLen int, err error) {
    if len(input) < 2 {
        return nil, 0, fmt.Errorf("input too short")
    }
    if input[0] != 0x04 { // OCTET STRING tag
        return nil, 0, fmt.Errorf("not an OCTET STRING")
    }

    var length int
    var headerLen int

    if input[1]&0x80 == 0 { // short form
        length = int(input[1] & 0x7F)
        headerLen = 2
    } else { // long form
        lengthOctets := int(input[1] & 0x7F)
        switch lengthOctets {
        case 1:
            if len(input) < 3 {
                return nil, 0, fmt.Errorf("input too short for 1-length octet")
            }
            length = int(input[2])
            headerLen = 3
        case 2:
            if len(input) < 4 {
                return nil, 0, fmt.Errorf("input too short for 2-length octets")
            }
            length = int(input[2])<<8 | int(input[3])
            headerLen = 4
        case 3:
            if len(input) < 5 {
                return nil, 0, fmt.Errorf("input too short for 3-length octets")
            }
            length = int(input[2])<<16 | int(input[3])<<8 | int(input[4])
            headerLen = 5
        default:
            return nil, 0, fmt.Errorf("length octets > 3 not supported")
        }
    }

    if headerLen+length > len(input) {
        return nil, 0, fmt.Errorf("octet string length mismatch")
    }

    data = input[headerLen : headerLen+length]
    fieldLen = headerLen + length
    return data, fieldLen, nil
}


// Go version of get_login_importer_key
func getLoginImporterKey(target Target_t) (ski [C.XCP_CERTHASH_BYTES]byte, tcounter [C.XCP_ADMCTR_BYTES]byte, ecPub *ecdsa.PublicKey , err error) {

	var res [C.XCP_LOGIN_IMPR_MAX_SIZE]byte
	resLen := C.CK_ULONG(len(res))
        rv := C.m_get_xcp_info(C.CK_VOID_PTR(unsafe.Pointer(&res)), &resLen, C.CK_IBM_XCPQ_LOGIN_IMPORTER, C.XCP_LOGIN_ALG_F2021, C.target_t(target))
	//fmt.Printf("Raw m_get_xcp_info data: %x\n", res[:resLen])
        if (rv != C.CKR_OK) {
                fmt.Printf("Failed to query domain information m_get_xcp_info rc: 0x%lx",  rv)
		err = ToError(uint64(rv))

                return 
        }

	data, _, err := berDecodeSequence(res[:])
	if err != nil {
		fmt.Println("berDecodeSequence failed:", err)
		return 
	}

	var skiField, spki, cnt []byte

	skiField, fieldLen, err := berDecodeOctetString(data)
	if err != nil {
		fmt.Println("berDecodeOctetString (SKI) failed:", err)
		return 
	}
	data = data[fieldLen:]

	spki, fieldLen,  err = berDecodeOctetString(data)
	if err != nil {
		fmt.Println("berDecodeOctetString (SPKI) failed:", err)
		return
	}
	data = data[fieldLen:]

	cnt, fieldLen,  err = berDecodeOctetString(data)
	if err != nil {
		fmt.Println("berDecodeOctetString (TCounter) failed:", err)
		return
	}
	data = data[fieldLen:]

	if len(skiField) != C.XCP_CERTHASH_BYTES {
		fmt.Printf("SKI length unexpected: %d != %d\n", len(skiField), C.XCP_CERTHASH_BYTES)
		err = ToError(uint64(C.CKR_BUFFER_TOO_SMALL))
		return
	}
	copy(ski[:], skiField)

	if len(cnt) > C.XCP_ADMCTR_BYTES {
		fmt.Printf("Counter length too large: %d > %d\n", len(cnt), C.XCP_ADMCTR_BYTES)
		return
	}
	copy(tcounter[C.XCP_ADMCTR_BYTES-len(cnt):], cnt)

	// parse SPKI DER to *ecdsa.PublicKey
	pubKey, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		fmt.Println("Failed to parse SPKI:", err)
		return
	}

	var ok bool
	ecPub,ok  = pubKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("SPKI is not ECDSA public key")
		return 
	}

	return 
}

// KDFSP80056CSHA256 derives a 256-bit AES key from the shared secret and local EC private key
func KDFSP80056CSHA256(priv *ecdsa.PrivateKey, secret []byte) ([]byte, error) {
	// Get local public key x-coordinate
	xBytes := priv.PublicKey.X.Bytes()

	// Ensure x-coordinate is padded to curve byte size
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	if len(xBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xBytes):], xBytes)
		xBytes = padded
	}

	h := sha256.New()

	// Append counter (1) in big-endian
	be32 := make([]byte, 4)
	binary.BigEndian.PutUint32(be32, 1)
	h.Write(be32)

	// Append algorithmID (1) in big-endian
	h.Write(be32) // same as C code

	// Append shared secret
	h.Write(secret)

	// Append x-coordinate of local public key
	h.Write(xBytes)

	// Finalize SHA256
	key := h.Sum(nil)

	if len(key) != 32 {
		return nil, fmt.Errorf("unexpected key length: %d", len(key))
	}

	return key, nil
}

// berEncodeSequence encodes a byte slice as a BER SEQUENCE
func berEncodeSequence(data []byte) ([]byte, error) {
	dataLen := len(data)
	var buf bytes.Buffer

	buf.WriteByte(0x30) // SEQUENCE tag

	switch {
	case dataLen < 128:
		buf.WriteByte(byte(dataLen))
	case dataLen < 256:
		buf.WriteByte(0x81)
		buf.WriteByte(byte(dataLen))
	case dataLen < (1 << 16):
		buf.WriteByte(0x82)
		buf.WriteByte(byte(dataLen >> 8))
		buf.WriteByte(byte(dataLen))
	case dataLen < (1 << 24):
		buf.WriteByte(0x83)
		buf.WriteByte(byte(dataLen >> 16))
		buf.WriteByte(byte(dataLen >> 8))
		buf.WriteByte(byte(dataLen))
	default:
		return nil, fmt.Errorf("berEncodeSequence: data too large")
	}

	buf.Write(data)
	return buf.Bytes(), nil
}

// berEncodeOctetString encodes a byte slice as a BER primitive OCTET STRING
func berEncodeOctetString(data []byte) ([]byte, error) {
	dataLen := len(data)
	var buf bytes.Buffer

	buf.WriteByte(0x04) // OCTET STRING tag

	switch {
	case dataLen < 128:
		buf.WriteByte(byte(dataLen))
	case dataLen < 256:
		buf.WriteByte(0x81)
		buf.WriteByte(byte(dataLen))
	case dataLen < (1 << 16):
		buf.WriteByte(0x82)
		buf.WriteByte(byte(dataLen >> 8))
		buf.WriteByte(byte(dataLen))
	case dataLen < (1 << 24):
		buf.WriteByte(0x83)
		buf.WriteByte(byte(dataLen >> 16))
		buf.WriteByte(byte(dataLen >> 8))
		buf.WriteByte(byte(dataLen))
	default:
		return nil, fmt.Errorf("berEncodeOctetString: data too large")
	}

	buf.Write(data)
	return buf.Bytes(), nil
}

// CreateLoginRecipient builds a BER-encoded LoginRecipient structure
// ski: peer's SKI (XCP_CERTHASH_BYTES)
// ecPriv: local EC private key
// If lengthOnly is true, returns only the length without allocating the buffer
func createLoginRecipient(ski []byte, ecPriv *ecdsa.PrivateKey, lengthOnly bool) ([]byte, error) {
    if len(ski) != C.XCP_CERTHASH_BYTES {
        return nil, fmt.Errorf("invalid SKI length: got %d, expected %d", len(ski), C.XCP_CERTHASH_BYTES)
    }

    // 1. Version (uint32, big-endian)
    version := make([]byte, 4)
    binary.BigEndian.PutUint32(version, 1)

    // 2. Encode SPKI from EC private key
    spki := []byte{}
    if !lengthOnly {
        spkiDer, err := x509.MarshalPKIXPublicKey(&ecPriv.PublicKey)
        if err != nil {
            return nil, fmt.Errorf("failed to marshal SPKI: %w", err)
        }
        spki = spkiDer
    }

    // 3. BER encode each OCTET STRING
    v1OS, err := berEncodeOctetString(version)
    if err != nil {
        return nil, fmt.Errorf("berEncodeOctetString (version) failed: %w", err)
    }

    skiOS, err := berEncodeOctetString(ski)
    if err != nil {
        return nil, fmt.Errorf("berEncodeOctetString (SKI) failed: %w", err)
    }

    spkiOS, err := berEncodeOctetString(spki)
    if err != nil {
        return nil, fmt.Errorf("berEncodeOctetString (SPKI) failed: %w", err)
    }

    // 4. Concatenate the components
    dataLen := len(v1OS) + len(skiOS) + len(spkiOS)
    var data []byte
    if !lengthOnly {
        data = make([]byte, 0, dataLen)
        data = append(data, v1OS...)
        data = append(data, skiOS...)
        data = append(data, spkiOS...)
    }

    // 5. BER encode the whole SEQUENCE
    seq, err := berEncodeSequence(data)
    if err != nil {
        return nil, fmt.Errorf("berEncodeSequence failed: %w", err)
    }

    return seq, nil
}



// CreateLoginExtendedInfo constructs the extended login info sequence
func CreateLoginExtendedInfo(ski []byte, ecPrivKey interface{}) ([]byte, error) {
	var err error
	//lengthOnly := false // we always allocate a buffer in Go

ecPriv, ok := ecPrivKey.(*ecdsa.PrivateKey)
if !ok {
    return nil, fmt.Errorf("ecPrivKey is not *ecdsa.PrivateKey")
}

	// 1. Encode recipient info (stub, in C it's create_login_recipient)
	recipient, err := createLoginRecipient(ski, ecPriv,false)
	if err != nil {
		return nil, fmt.Errorf("createLoginRecipient failed: %w", err)
	}

	// 2. Encode version
	versOS, err := berEncodeOctetString(OIDIBMmiscEP11SessionInfo)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString (VERSION) failed: %w", err)
	}

	// 3. Encode algorithm (loginAlg as big-endian)
	algBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(algBytes,  C.XCP_LOGIN_ALG_F2021)
	algOS, err := berEncodeOctetString(algBytes)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString (ALG) failed: %w", err)
	}

	// 4. Encode parent session ID (may be nil)
	var parentID []byte	
	if parentID == nil {
		parentID = make([]byte, C.XCP_WK_BYTES)
	}
	parentOS, err := berEncodeOctetString(parentID)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString (PARENT) failed: %w", err)
	}

	// 5. Encode recipient
	recipientOS, err := berEncodeOctetString(recipient)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString (RECIPIENT) failed: %w", err)
	}

	// 6. Encode attributes and context (empty)
	attrOS, err := berEncodeOctetString([]byte{})
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString (ATTRS) failed: %w", err)
	}

	ctxOS, err := berEncodeOctetString([]byte{})
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString (CONTEXT) failed: %w", err)
	}

	// 7. Concatenate all components
	data := bytes.Join([][]byte{versOS, algOS, parentOS, recipientOS, attrOS, ctxOS}, nil)

	// 8. Wrap in SEQUENCE
	return berEncodeSequence(data)
}


// stubbed function: do_LoginExtended
func doLoginExtended( FNoperation int, pin []byte, target Target_t) ([]byte, error) {

	// prepare nonce
	var n nonceT
	n.SlotID = 4
	copy(n.Purpose[:], []byte("FIPS-session"))
	nonceBytes := (*[unsafe.Sizeof(n)]byte)(unsafe.Pointer(&n))[:]

	//fmt.Printf("Called doLoginExtended with pin=%s, nonce=%x\n", pin, nonce)
	// stub: fill pinBlob with fake data

	curve := elliptic.P521()
	localECPrivKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
                  fmt.Errorf("ecdsa.GenerateKey failed: %w", err)
		  return nil, err
        }

	var peerSKI [C.XCP_CERTHASH_BYTES]byte
	var tCounter [C.XCP_ADMCTR_BYTES]byte
	sharedSecret := make([]byte, 256)
	sharedKey := make([]byte, 32)

	// 1. Get the login importer key
	peerSKI, tCounter, peerECPubKey, err := getLoginImporterKey(target)
	if err != nil {
	    return nil, fmt.Errorf("getLoginImporterKey failed: %w", err)
	}

	//fmt.Printf("tcounter: %x\n", tCounter[:])
	//fmt.Printf("peerSKI: %x\n", peerSKI[:])
	// 2. ECDH derive shared secret
	sharedSecret, err = ECDHDerive(localECPrivKey, peerECPubKey)
	if err != nil {
	    return nil, fmt.Errorf("ecdhDerive failed: %w", err)
	}

	// 3. Key derivation using SP800-56c SHA-256
	sharedKey, err = KDFSP80056CSHA256(localECPrivKey, sharedSecret )
	if err != nil {
	    return nil, fmt.Errorf("kdfSP800_56cSHA256 failed: %w", err)
	}
	//fmt.Printf("sharedKey: %x\n", sharedKey) 
   
        extendedInfo, err := CreateLoginExtendedInfo(peerSKI[:], localECPrivKey)
	if err != nil {
	    fmt.Printf("createLoginExtendedInfo failed: %v\n", err)
	    return nil, err // equivalent to 'goto done' in C
	}

	// extendedInfo now contains the BER-encoded extended login info
	// fmt.Printf("Extended info (%d bytes): %x\n", len(extendedInfo), extendedInfo)
	incrementTCounter(tCounter[:])

	paddedPin, err := CreatePaddedPIN(pin, tCounter[:], FNoperation)
	if err != nil {
	    // Equivalent of "goto done;" in C
	    return nil, fmt.Errorf("createPaddedPIN failed: %w", err)
	}

	// paddedPin now contains the BER-encoded PIN
	//paddedPinLen := len(paddedPin)
	//fmt.Printf("Padded PIN (%d bytes): %x\n", paddedPinLen, paddedPin)
	//encPaddedPin, err := EncryptPaddedPINOpenSSL(sharedKey,paddedPin )
	encPaddedPin, err := aes256KWPEncrypt(sharedKey,paddedPin )
	if err != nil {
	    return nil, fmt.Errorf("EncryptPaddedPIN failed: %w", err)
	}

	// Call the C function
	var encPinBlob [C.XCP_PINBLOB_V1_BYTES]C.CK_BYTE
	encPinBlobLen := C.CK_ULONG(len(encPinBlob))

	switch(FNoperation) {
	case FNID_LoginExtended:
		// Call m_LoginExtended
		rc := C.m_LoginExtended(
			(*C.CK_BYTE)(&encPaddedPin[0]), C.CK_ULONG(len(encPaddedPin)),
	        	(*C.uchar)(unsafe.Pointer(&nonceBytes[0])), C.size_t(len(nonceBytes)),
	                (*C.uchar)(unsafe.Pointer(&extendedInfo[0])), C.size_t(len(extendedInfo)),
			(*C.uchar)(unsafe.Pointer(&encPinBlob[0])), &encPinBlobLen,
    			C.target_t(target),
		)
		if rc != C.CKR_OK {
			fmt.Printf("login extended failed")
			return  nil, ToError(uint64(rc))
		}
	case FNID_LogoutExtended:
		rc := C.m_LogoutExtended(
			(*C.CK_BYTE)(&encPaddedPin[0]), C.CK_ULONG(len(encPaddedPin)),
	        	(*C.uchar)(unsafe.Pointer(&nonceBytes[0])), C.size_t(len(nonceBytes)),
	                (*C.uchar)(unsafe.Pointer(&extendedInfo[0])), C.size_t(len(extendedInfo)),
    			C.target_t(target),
		)
		if rc != C.CKR_OK {
			fmt.Printf("logout extended failed")
			return  nil, ToError(uint64(rc))
		}
		return nil, nil
	}

	encryptedPINBlob := C.GoBytes(unsafe.Pointer(&encPinBlob[0]), C.int(encPinBlobLen))
	//fmt.Printf("Encrypted PIN blob: %x\n", encryptedPINBlob)

	clearPinblob, err := aes256KWPDecrypt(sharedKey,encryptedPINBlob)
	if err != nil {
		return nil, err
	}
//	fmt.Printf("Decrypted PIN blob: %x\n",clearPinblob )

	pinBlobKey, err := derivePinblobKey(clearPinblob, pin)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("Decrypted pinblobkey: %x\n", pinBlobKey)

	encPinblob, err := encryptPinblob(clearPinblob,pinBlobKey )
	if err != nil {
		return nil, err
	}	
//	fmt.Printf("session key: %x\n",encPinblob)

	return encPinblob ,nil
}

func incrementTCounter(tcounter []byte) {
    for i := len(tcounter) - 1; i >= 0; i-- {
        tcounter[i]++
        if tcounter[i] != 0 {
            break
        }
    }

    // Optional debug
    //fmt.Printf("TCounter after increment: %x\n", tcounter)
}


// Matches aes_256_wrap_pad_encrypt_len()
func aes256WrapPadEncryptLen(clearLen int) int {
	encLen := clearLen
	if clearLen%8 != 0 {
		encLen += 8 - (clearLen % 8)
	}
	return encLen + 8
}

// Go equivalent of encrypt_pinblob()
func encryptPinblob(pinblob []byte, key []byte) ([]byte, error) {

	if len(key) != 32 {
		return nil, errors.New("AES key must be 32 bytes")
	}

	needed := aes256WrapPadEncryptLen(len(pinblob))

	// RFC5649 encryption
	enc, err := aes256KWPEncrypt(key, pinblob)
	if err != nil {
		return nil, err
	}

	if len(enc) != needed {
		return nil, errors.New("unexpected encrypted size")
	}

	// === C post-processing ===

	// op_pinblob[EP11_PINBLOB_MARKER_OFS] = EP11_PINBLOB_V1_MARKER
	enc[EP11_PINBLOB_MARKER_OFS] = EP11_PINBLOB_V1_MARKER

	// if (op_pinblob[0] == 0x30) op_pinblob[0] = 0xcc;
	if enc[0] == 0x30 {
		enc[0] = 0xcc
	}

	return enc, nil
}


// CreatePaddedPIN constructs a padded PIN structure as a BER-encoded SEQUENCE.
// - pin: user PIN bytes
// - tcounter: transaction counter (big-endian, e.g., 16 bytes)
// - funcID: function ID (e.g., LoginExtended/LogoutExtended)
// Returns the BER-encoded PIN bytes or an error.
func CreatePaddedPIN(pin []byte, tcounter []byte, funcID int) ([]byte, error) {
	if len(tcounter) != C.XCP_ADMCTR_BYTES {
		return nil, fmt.Errorf("tcounter length must be %d bytes", C.XCP_ADMCTR_BYTES)	}

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, 1)

	fnID := make([]byte, 4)
	binary.BigEndian.PutUint32(fnID, uint32(funcID))

	// 1. Encode each OCTET STRING
	versOS, err := berEncodeOctetString(version)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString(version) failed: %w", err)
	}

	fnIDOS, err := berEncodeOctetString(fnID)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString(fnID) failed: %w", err)
	}

	counterOS, err := berEncodeOctetString(tcounter)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString(tcounter) failed: %w", err)
	}

	pinOS, err := berEncodeOctetString(pin)
	if err != nil {
		return nil, fmt.Errorf("berEncodeOctetString(pin) failed: %w", err)
	}

	// 2. Concatenate all fields
	data := append([]byte{}, versOS...)
	data = append(data, fnIDOS...)
	data = append(data, counterOS...)
	data = append(data, pinOS...)

	// 3. Wrap in SEQUENCE
	seq, err := berEncodeSequence(data)
	if err != nil {
		return nil, fmt.Errorf("berEncodeSequence failed: %w", err)
	}

	return seq, nil
}


func EP11Login( pin []byte, target Target_t) ([]byte, error) {
	return doLoginExtended(FNID_LoginExtended, pin, target)
}


func EP11Logout( pin []byte, target Target_t) ( error) {
	_,err := doLoginExtended(FNID_LogoutExtended, pin, target)
	return err
}

