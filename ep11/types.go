package ep11


/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11.h"

CK_ULONG Index(CK_ULONG_PTR array, CK_ULONG i)
{
	return array[i];
}

static inline void putAttributePval(CK_ATTRIBUTE_PTR a, CK_VOID_PTR pValue)
{
	a->pValue = pValue;
}

static inline void putMechanismParam(CK_MECHANISM_PTR m, CK_VOID_PTR pParameter)
{
	m->pParameter = pParameter;
}
*/
import "C"

import "time"
import "unsafe"
import "fmt"

type Attribute struct {
	Type  uint
	Value []byte
}

// memBytes returns a byte slice that references an arbitrary memory area
func memBytes(p unsafe.Pointer, len uintptr) []byte {
        const maxIndex int32 = (1 << 31) - 1
        return (*([maxIndex]byte))(p)[:len:len]
}



func uintToBytes(x uint64) []byte {
	ul := C.CK_ULONG(x)
	return C.GoBytes(unsafe.Pointer(&ul), C.int(unsafe.Sizeof(ul)))
}


type arena []unsafe.Pointer

func (a *arena) Allocate(obj []byte) (C.CK_VOID_PTR, C.CK_ULONG) {
	cobj := C.calloc(C.size_t(len(obj)), 1)
	*a = append(*a, cobj)
	C.memmove(cobj, unsafe.Pointer(&obj[0]), C.size_t(len(obj)))
	return C.CK_VOID_PTR(cobj), C.CK_ULONG(len(obj))
}

func (a arena) Free() {
	for _, p := range a {
		C.free(p)
	}
}


// Error represents an PKCS#11 error.
type Error uint

func (e Error) Error() string {
	return fmt.Sprintf("pkcs11: 0x%X: %s", uint(e), strerror[uint(e)])
}

func toError(e C.CK_RV) error {
	if e == C.CKR_OK {
		return nil
	}
	return Error(e)
}

// NewAttribute allocates a Attribute and returns a pointer to it.
// Note that this is merely a convenience function, as values returned
// from the HSM are not converted back to Go values, those are just raw
// byte slices.
func NewAttribute(typ uint, x interface{}) *Attribute {
	// This function nicely transforms *to* an attribute, but there is
	// no corresponding function that transform back *from* an attribute,
	// which in PKCS#11 is just an byte array.
	a := new(Attribute)
	a.Type = typ
	if x == nil {
		return a
	}
	switch v := x.(type) {
	case bool:
		if v {
			a.Value = []byte{1}
		} else {
			a.Value = []byte{0}
		}
	case int:
		a.Value = uintToBytes(uint64(v))
	case int16:
		a.Value = uintToBytes(uint64(v))
	case int32:
		a.Value = uintToBytes(uint64(v))
	case int64:
		a.Value = uintToBytes(uint64(v))
	case uint:
		a.Value = uintToBytes(uint64(v))
	case uint16:
		a.Value = uintToBytes(uint64(v))
	case uint32:
		a.Value = uintToBytes(uint64(v))
	case uint64:
		a.Value = uintToBytes(uint64(v))
	case string:
		a.Value = []byte(v)
	case []byte:
		a.Value = v
	case time.Time: // for CKA_DATE
		a.Value = cDate(v)
	default:
		panic("pkcs11: unhandled attribute type")
	}
	return a
}


func cDate(t time.Time) []byte {
	b := make([]byte, 8)
	year, month, day := t.Date()
	y := fmt.Sprintf("%4d", year)
	m := fmt.Sprintf("%02d", month)
	d1 := fmt.Sprintf("%02d", day)
	b[0], b[1], b[2], b[3] = y[0], y[1], y[2], y[3]
	b[4], b[5] = m[0], m[1]
	b[6], b[7] = d1[0], d1[1]
	return b
}


func Mech(mechType uint, params []byte) []*Mechanism {
    return []*Mechanism{
        {
            Mechanism: mechType,
            Parameter: params,
        },
    }
}


// Mechanism holds an mechanism type/value combination.
type Mechanism struct {
	Mechanism uint
	Parameter []byte
	generator interface{}
}

/*
// NewMechanism returns a pointer to an initialized Mechanism.
func NewMechanism(mech uint, x interface{}) *Mechanism {
	m := new(Mechanism)
	m.Mechanism = mech
	if x == nil {
		return m
	}

	switch p := x.(type) {
//	case *GCMParams, *OAEPParams, *ECDH1DeriveParams:
	case *GCMParams, *OAEPParams :
		// contains pointers; defer serialization until cMechanism
		m.generator = p
	case []byte:
		//fmt.Printf("**********************")
		//fmt.Printf("%d",len(p))
		m.Parameter = p
	default:
		panic("parameter must be one of type: []byte, *GCMParams, *OAEPParams, *ECDH1DeriveParams")
	}

	return m
}
*/


// cAttribute returns the start address and the length of an attribute list.
func cAttributeList(a []*Attribute) (arena, C.CK_ATTRIBUTE_PTR, C.CK_ULONG) {
	var arena arena
	if len(a) == 0 {
		return nil, nil, 0
	}
	pa := make([]C.CK_ATTRIBUTE, len(a))
	for i, attr := range a {
		pa[i]._type = C.CK_ATTRIBUTE_TYPE(attr.Type)
		if len(attr.Value) != 0 {
			buf, len := arena.Allocate(attr.Value)
			// field is unaligned on windows so this has to call into C
			C.putAttributePval(&pa[i], buf)
			pa[i].ulValueLen = len
		}
	}
	return arena, &pa[0], C.CK_ULONG(len(a))
}

func cMechanism(mechList []*Mechanism) (arena, *C.CK_MECHANISM) {
	if len(mechList) != 1 {
		panic("expected exactly one mechanism")
	}
	mech := mechList[0]
	cmech := &C.CK_MECHANISM{mechanism: C.CK_MECHANISM_TYPE(mech.Mechanism)}
	// params that contain pointers are allocated here
	param := mech.Parameter
	var arena arena
	switch p := mech.generator.(type) {
	case *GCMParams:
		// uses its own arena because it has to outlive this function call (yuck)
		param = cGCMParams(p)
	case *OAEPParams:
		param, arena = cOAEPParams(p, arena)
//	case *ECDH1DeriveParams:
//		param, arena = cECDH1DeriveParams(p, arena)
	}
	if len(param) != 0 {
		buf, len := arena.Allocate(param)
		// field is unaligned on windows so this has to call into C
		C.putMechanismParam(cmech, buf)
		cmech.ulParameterLen = len
	}
	return arena, cmech
}


type Attributes map[uint]interface{}

func ConvertToAttributeSlice(attrs Attributes) []*Attribute {
	var attrSlice []*Attribute
	for key, value := range attrs {
		attrSlice = append(attrSlice, NewAttribute(key, value))
	}
	return attrSlice
}

