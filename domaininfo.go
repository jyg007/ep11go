package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki 
#include <stdint.h>
#include <ep11.h>
#include <stdlib.h>

*/
import "C"
import "ep11go/ep11"
import (
	"fmt"
	"os"
	"unsafe"
	"log"
)

//##########################################################################################################################################################################################
//##########################################################################################################################################################################################

func main() {
  hsmTarget := os.Getenv("EP11_IBM_TARGET_HSM")
    if hsmTarget == "" {
         log.Fatalf("EP11_IBM_TARGET_HSM not set")
    }
    target := ep11.HsmInit(hsmTarget)
 

       var domain_info C.CK_IBM_DOMAIN_INFO
        domain_info_len := C.CK_ULONG(unsafe.Sizeof(domain_info))

        rv := C.m_get_xcp_info(C.CK_VOID_PTR(unsafe.Pointer(&domain_info)), &domain_info_len, C.CK_IBM_XCPQ_DOMAIN, 0, C.target_t(target))
        if (rv != C.CKR_OK) {
        	fmt.Printf(
			"Failed to query domain information m_get_xcp_info rc: 0x%x\n",
			uint64(rv),
		)
		return
	}

	fmt.Printf("CK_IBM_DOMAIN_INFO:\n")
	fmt.Printf("  domain     : %d (0x%x)\n",
		uint64(domain_info.domain),
		uint64(domain_info.domain))

	fmt.Printf("  wk         : %x\n",
		C.GoBytes(
			unsafe.Pointer(&domain_info.wk[0]),
			C.XCP_KEYCSUM_BYTES,
		))

	fmt.Printf("  nextwk     : %x\n",
		C.GoBytes(
			unsafe.Pointer(&domain_info.nextwk[0]),
			C.XCP_KEYCSUM_BYTES,
		))

	fmt.Printf("  flags      : %d (0x%x)\n",
		uint64(domain_info.flags),
		uint64(domain_info.flags))

	fmt.Printf("  mode       : %x\n",
		C.GoBytes(
			unsafe.Pointer(&domain_info.mode[0]),
			8,
		))

	fmt.Printf("  size       : %d bytes\n", domain_info_len)
}


