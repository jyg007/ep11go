package main

/*
#cgo CFLAGS: -I/usr/include/ep11 -I/usr/include/opencryptoki

#include <stdint.h>
#include <ep11.h>
*/
import "C"
import "fmt"
import "os"
import "encoding/hex"
import "ep11go/ep11"

func main() { 
       target := ep11.HsmInit("3.19") 
       key := make([]byte, hex.DecodedLen(len(os.Args[1])))
       hex.Decode(key, []byte(os.Args[1]))


       attributeList := ep11.Attributes{
             C.CKA_KEY_TYPE: C.CKK_GENERIC_SECRET,
             C.CKA_EXTRACTABLE: false,
	                 C.CKA_PUBLIC_KEY_INFO: nil ,  
        }

      res, rc  := ep11.GetAttributeValue(target, key, attributeList)


        if rc!= nil   {
                        fmt.Println(rc)
        } else {
	 	for k, v := range res {
 		   if valBytes, ok := v.([]byte); ok {
		        fmt.Printf("Key: %d, Value (hex): %x\n", k, valBytes)
	//	        fmt.Printf("Key: %d, Value (string): %s\n", k, string(valBytes))
		    } else {
		        fmt.Printf("Key: %d, Value: %v\n", k, v)
	    }
    }
    }
}
