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
import "fmt"
import "ep11go/ep11"


//##########################################################################################################################################################################################
//##########################################################################################################################################################################################
func main() { 
      target := ep11.HsmInitNonVirtual("3.19") 
 
      m, _ := ep11.GetMechanismList(target)
      fmt.Printf(m)
}
