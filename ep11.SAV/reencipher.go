package ep11

/*

typedef struct XCPadmresp XCPadmresp_T;

#cgo LDFLAGS: -lep11
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ep11.h>
#include <ep11adm.h>
*/
import "C"
import "fmt"
import "unsafe"

func Reencipher(target C.target_t, Key KeyBlob )  (KeyBlob, error)  {


        var domain_info C.CK_IBM_DOMAIN_INFO
	domain_info_len := C.CK_ULONG(unsafe.Sizeof(domain_info))

	rv := C.m_get_xcp_info(C.CK_VOID_PTR(unsafe.Pointer(&domain_info)), &domain_info_len, C.CK_IBM_XCPQ_DOMAIN, 0, target)
        if (rv != C.CKR_OK) {
                fmt.Printf("Failed to query domain information m_get_xcp_info rc: 0x%lx",  rv)
          	return nil, toError(rv)
        }

	var  lrb,rb C.XCPadmresp_T
        rb.domain = C.uint(domain_info.domain);
        lrb.domain = C.uint(domain_info.domain);

        req:=  make([]byte,MAX_BLOB_SIZE)
        reqC := C.CK_BYTE_PTR(unsafe.Pointer(&req[0]))

        resp:=  make([]byte,MAX_BLOB_SIZE)
        respC := C.CK_BYTE_PTR(unsafe.Pointer(&resp[0]))
        respLenC := C.CK_ULONG(len(resp))

	keyC := C.CK_BYTE_PTR(unsafe.Pointer(&Key[0]))
        keyLenC := C.CK_ULONG(len(Key))

	req_len := C.xcpa_cmdblock(reqC, MAX_BLOB_SIZE, C.XCP_ADM_REENCRYPT,&rb, nil,keyC , keyLenC)
     	if (req_len < 0) {
            return nil, toError(C.CKR_FUNCTION_FAILED)
        }

	var zero C.CK_ULONG = 0
	rc := C.m_admin(respC, &respLenC, nil, &zero, reqC, C.CK_ULONG(req_len), nil , 0, target)

	if (rc != C.CKR_OK || respLenC == 0) {
            	fmt.Printf("reencryption failed: %d %d\n",  rc, respLenC)
		fmt.Println(toError(rc))
          	return nil, toError(rc)
         }

	 if (C.xcpa_internal_rv(respC, respLenC, &lrb, &rc) < 0) {
               fmt.Printf ("reencryption response malformed: 0x%lx\n", rc)
              return nil, toError(C.CKR_FUNCTION_FAILED)
         }
         if (keyLenC != lrb.pllen) {
                 fmt.Printf("reencryption blob size changed. Blob len: 0x%lx | NewBlob Len: 0x%lx | Response: 0x%lx |  Request: 0x%lx\n", keyLenC, lrb.pllen, respLenC, req_len)
                 return nil, toError(C.CKR_FUNCTION_FAILED)
         }
	
	NewKey := C.GoBytes(unsafe.Pointer(lrb.payload), C.int(lrb.pllen))
	
    	return NewKey,nil
}
