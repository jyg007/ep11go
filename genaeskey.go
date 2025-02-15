package main

import (
	"fmt"
	"log"
	"github.com/miekg/pkcs11"
)

const (
	pkcs11LibPath = "/usr/lib64/opencryptoki/libopencryptoki.so" // Update this to your PKCS#11 library path
)

func main() {
	// Initialize PKCS#11
	p := pkcs11.New(pkcs11LibPath)
	if p == nil {
		log.Fatal("Failed to load PKCS#11 library")
	}
	err := p.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize PKCS#11 module: %v", err)
	}
	defer p.Finalize()
	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		log.Fatalf("Failed to get slot list: %v", err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("Failed to open session: %v", err)
	}
	defer p.CloseSession(session)

	// Login (replace "your-pin" with the actual user PIN)
	err = p.Login(session, pkcs11.CKU_USER, "87654321")
	if err != nil {
		log.Fatalf("Failed to log in: %v", err)
	}
	defer p.Logout(session)

	// Generate AES Key
	keyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "MyjygAESKey"), // Add a label for listing
                pkcs11.NewAttribute(pkcs11.CKA_ID, []byte("aze23-ze24")),  // Set a unique ID
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32), // 256-bit AES key
	}

	handle, err := p.GenerateKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}, keyTemplate)
	if err != nil {
		log.Fatalf("Failed to generate AES key: %v", err)
	}

	fmt.Printf("AES Key generated successfully, handle: %v\n", handle)
}
