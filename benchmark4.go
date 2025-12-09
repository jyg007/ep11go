package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import	 "sync"
import	 "time"
import "encoding/asn1"
import "ep11go/ep11"
import  "crypto/sha256"
import "flag"
import "strings" 

type SafeCounter struct {
	mu sync.Mutex
	nb  int64
}

var COUNTER  SafeCounter
var (
    threadsFlag = flag.Int("threads", 1, "Number of worker threads")
    elapsedFlag = flag.Int("elapsed", 5, "Counter interval in seconds")
    curveFlag   = flag.String("curve", "secp256k1", "Curve to use: secp256k1 or ed25519")
    cardsFlag   = flag.String("cards", "03.19", "Space-separated list of adapter.domain pairs")
)


func start(c chan int) {

       target := ep11.HsmInit(*cardsFlag)
 var ecParameters []byte
    var err error
    var mechSign []*ep11.Mechanism

    switch *curveFlag {
    case "secp256k1":
        // EC: secp256k1
        ecParameters, err = asn1.Marshal(ep11.OIDNamedCurveSecp256k1)
        if err != nil {
            panic(fmt.Errorf("Unable to encode secp256k1 OID: %s", err))
        }
        mechSign = ep11.Mech(C.CKM_ECDSA, nil)

    case "ed25519":
        // ED25519: no EC-params, different mechanism
        ecParameters, err = asn1.Marshal(ep11.OIDNamedCurveED25519)
        if err != nil {
            panic(fmt.Errorf("Unable to encode ed25519 OID: %s", err))
        }
        mechSign = ep11.Mech(C.CKM_IBM_ED25519_SHA512, nil)

    default:
        panic("Unknown curve: use --curve secp256k1 or --curve ed25519")
    }

    // Templates
    publicKeyECTemplate := ep11.Attributes{
        C.CKA_EC_PARAMS: ecParameters,
        C.CKA_VERIFY:    true,
    }
    privateKeyECTemplate := ep11.Attributes{
        C.CKA_SIGN:    true,
        C.CKA_PRIVATE: true,
    }

    _, sk, _ := ep11.GenerateKeyPair(
        target,
        ep11.Mech(C.CKM_EC_KEY_PAIR_GEN, nil),
        publicKeyECTemplate,
        privateKeyECTemplate,
    )

    fmt.Print("+")

    for {
        digest := sha256.Sum256([]byte("This data needs to be signed"))

        _, err := ep11.SignSingle(target, mechSign, sk, digest[:])
        if err != nil {
            panic(fmt.Errorf("Sign error: %s", err))
        }

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
    flag.Parse() // must come FIRST
  if *threadsFlag <= 0 {
        fmt.Println("Threads must be greater than 0")
        return
    }

    if *elapsedFlag <= 0 {
        fmt.Println("Elapsed time must be greater than 0")
        return
    }
    // Sanity check cards string
    if strings.TrimSpace(*cardsFlag) == "" {
        fmt.Println("Cards list cannot be empty")
        return
    }

	 c := make(chan int)
	go counter(*elapsedFlag)
	for i:=0;i<*threadsFlag;i++ {
		time.Sleep(1*time.Second)
		go start(c)
	}
	time.Sleep(1*time.Second)
	fmt.Println("")

	_,_ = <-c
	fmt.Println("done")
}
