package main

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ep11.h>
*/
import "C"
import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"ep11go/ep11"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: program <numKeys> [numThreads]")
		return
	}

	numKeys, err := strconv.Atoi(os.Args[1])
	if err != nil || numKeys <= 0 {
		fmt.Println("Invalid number of keys. Please provide a positive integer.")
		return
	}

	numThreads := 8 // default
	if len(os.Args) >= 3 {
		t, err := strconv.Atoi(os.Args[2])
		if err == nil && t > 0 {
			numThreads = t
		}
	}

	target := ep11.HsmInit("3.19")

	keyTemplate := ep11.Attributes{
		C.CKA_VALUE_LEN: 16,
		C.CKA_UNWRAP:   false,
		C.CKA_ENCRYPT:  true,
	}

	// Generate AES keys
	aeskeys := make([]ep11.KeyBlob, numKeys)
	startTime := time.Now()
	for i := 0; i < numKeys; i++ {
		aeskey, _ ,_:= ep11.GenerateKey(target, ep11.Mech(C.CKM_AES_KEY_GEN, nil), keyTemplate)
		aeskeys[i] = aeskey
	}
	generationTime := time.Since(startTime)
	fmt.Printf("Time taken to generate %d keys: %v\n", numKeys, generationTime)

	// -------------------------------
	// Reencipher keys in batches
	// -------------------------------
	startTime = time.Now()

	var wg sync.WaitGroup
	batchSize := numKeys / numThreads
	if batchSize == 0 {
		batchSize = 1
	}

	for w := 0; w < numThreads; w++ {
		start := w * batchSize
		end := start + batchSize
		if w == numThreads-1 {
			end = numKeys // last worker handles remaining keys
		}
		wg.Add(1)
		go func(keys []ep11.KeyBlob) {
			defer wg.Done()
			for _, k := range keys {
				_, err := ep11.Reencipher(target, k)
				if err != nil {
					fmt.Printf("Reencipher error: %v\n", err)
				}
			}
		}(aeskeys[start:end])
	}

	wg.Wait()
	reencipherTime := time.Since(startTime)
	fmt.Printf("Time taken to reencipher %d keys using %d threads: %v\n", numKeys, numThreads, reencipherTime)
}

