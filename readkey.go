package main

import (
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

func main() {
	module := "/usr/lib64/opencryptoki/libopencryptoki.so" // Use correct module for Grep11
	p := pkcs11.New(module)
	if p == nil {
		log.Fatal("Failed to initialize PKCS#11 module")
	}
	defer p.Destroy()

	err := p.Initialize()
	if err != nil {
		log.Fatalf("Initialize error: %v", err)
	}
	defer p.Finalize()

	slots, err := p.GetSlotList(true)
	if err != nil || len(slots) == 0 {
		log.Fatalf("No available slots: %v", err)
	}

	session, err := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("OpenSession error: %v", err)
	}
	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, "87654321") // Replace with your PIN
	if err != nil {
		log.Fatalf("Login error: %v", err)
	}
	defer p.Logout(session)

	// Find the key object
	err = p.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte("MyAESKey")),
	})
	if err != nil {
		log.Fatalf("FindObjectsInit error: %v", err)
	}

	handles, _, err := p.FindObjects(session, 1)
	p.FindObjectsFinal(session)
	if err != nil || len(handles) == 0 {
		log.Fatalf("Key not found")
	}

	keyHandle := handles[0]
	fmt.Println("🔹 Key found! Handle:", keyHandle)
/*
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	


	keyBlob, err := p.GetAttributeValue(session, keyHandle, attributes)
	if err != nil {
		log.Fatalf("GetAttributeValue error: %v", err)
	}
*/
fmt.Println("Key Blob Dump:")
		fmt.Printf("%02X", keyHandle)



	p.Finalize()
}

