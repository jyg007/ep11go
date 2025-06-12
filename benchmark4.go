package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import	"strconv"
import	 "sync"
import	 "time"
import "encoding/asn1"
import "ep11go/ep11"
import  "crypto/sha256"
import "os"

type SafeCounter struct {
	mu sync.Mutex
	nb  int64
}

var COUNTER  SafeCounter



func start(c chan int) {

         target := ep11.HsmInit("3.19") 
	 ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveED25519)
       //ecParameters, err := asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
        if err != nil {
               panic(fmt.Errorf("Unable to encode parameter OID: %s", err))
        }

	publicKeyECTemplate := ep11.Attributes{
                    C.CKA_EC_PARAMS:ecParameters,
                    C.CKA_VERIFY:true,
        }
	privateKeyECTemplate := ep11.Attributes{
                    C.CKA_SIGN:true,
                    C.CKA_PRIVATE:true,
        }

	_, sk , _ := ep11.GenerateKeyPair(target, ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil), publicKeyECTemplate,privateKeyECTemplate)
		if err != nil {
			panic(fmt.Errorf("Sign error: %s", err))
		}

    fmt.Print("+")




    for {

		// Sign data

		signData := sha256.Sum256([]byte("This data needs to be signed"))
//                _, err := ep11.SignSingle(target, ep11.Mech(C.CKM_ECDSA,nil),sk,signData[:])
                _, err := ep11.SignSingle(target, ep11.Mech(C.CKM_IBM_ED25519_SHA512,nil),sk,signData[:])

		if err != nil {
			panic(fmt.Errorf("Sign error: %s", err))
		}


 		//*****************************************************************
	

 		COUNTER.mu.Lock()
 		COUNTER.nb++
 		COUNTER.mu.Unlock()
        

	}
	c <- 2

}


func counter(t int) {
	var prev int64 = 0
	var current int64

	for {
		interval := time.Duration(t) * time.Second
		time.Sleep(interval)	
 		COUNTER.mu.Lock()
 		current=COUNTER.nb
 		COUNTER.mu.Unlock()
 		//fmt.Printf("%d - %d\n",(current-prev)/int64(t),(current-prev)/int64(t)*3)
 		fmt.Printf("%d \n",(current-prev)/int64(t))
 		
 		prev=current
	}	
}


func main() {

	var elapsed int = 5

	if len(os.Args) < 2 {
		fmt.Println("Usage: bencmark <thread nb> <elasped time - optional>")
		return
	}

	thread_nb, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Erreur : La valeur doit être un entier")
		return
	}

	if len(os.Args) == 3  {
		elapsed, err = strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Println("Erreur : La valeur doit être un entier")
			return
		}
	}
	
	c := make(chan int)
	go counter(elapsed)
	for i:=0;i<thread_nb;i++ {
		time.Sleep(1*time.Second)
		go start(c)
	}
	time.Sleep(1*time.Second)
	fmt.Println("")

	_,_ = <-c
	fmt.Println("hello")
}
