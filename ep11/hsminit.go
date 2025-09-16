package ep11

/*
#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define XCPTGTMASK_SET_DOM(mask, domain)       ((mask)[((domain)/8)] |=   (1 << (7-(domain)%8)))
#include <ep11.h>
*/
import "C"
import "fmt"
import "log"
import "os"
import "encoding/hex"
import "strconv"
import "strings"

// Equivalent function for XCPTGTMASK_SET_DOM
func XCPTGTMASK_SET_DOM(mask *[32]C.uchar, domain int) {
    mask[domain / 8 ] |= (1 << (7 - (domain % 8)))
}

type Target_t = C.target_t

func HsmInit(input string) Target_t {
    rc := C.m_init()
    if rc != C.XCP_OK {
            log.Fatalf("ep11 init error")
	    return 0
    }
    var target  C.target_t  = C.XCP_TGT_INIT
    var module C.struct_XCP_Module

    module.version=C.XCP_MOD_VERSION
	pairs := strings.Fields(input)
	for _, pair := range pairs {
		parts := strings.Split(pair, ".")
		if len(parts) != 2 {
			log.Printf("Invalid format: %s", pair)
			continue
		}
		adapter, err1 := strconv.Atoi(parts[0])
		domain, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			log.Printf("Invalid numbers in: %s", pair)
			continue
		}
		fmt.Printf("Initializing adapter %02d and domain %02d\n", adapter, domain)
    		module.module_nr = C.uint(adapter)

		for i := range module.domainmask {
 		     module.domainmask[i] = 0
    		}
    		XCPTGTMASK_SET_DOM(&module.domainmask, domain)
    		module.flags |= C.XCP_MFL_VIRTUAL | C.XCP_MFL_PROBE | C.XCP_MFL_MODULE
		rc := C.m_add_module(&module, &target)
       		if rc != C.CKR_OK {
                	fmt.Println(toError(C.CK_ULONG(rc)))
			return 0
        	}
          //    fmt.Printf("Module Initialiation Return Code: %d\n",rc)
	}
     	hexString := os.Getenv("EP11LOGIN")
	if hexString != "" {
		// Decode hex string to bytes
		blob, err := hex.DecodeString(hexString)
		if err != nil {
			fmt.Println("Failed to decode ep11 login blob string:", err)
		} else {
		// Call SetLoginBlob with the decoded value
		SetLoginBlob(blob)
		}
    	}
    return target
}
