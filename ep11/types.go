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


// allocation tracks a single C allocation and its size, so Free can
// zero the memory (it may have held key material, PINs, IVs, etc.)
// before releasing it back to the allocator.
type allocation struct {
	ptr  unsafe.Pointer
	size C.size_t
}

type arena []allocation

// Allocate copies obj into newly calloc'd C memory and returns a pointer/length
// pair suitable for PKCS#11 structures. Returns a nil pointer and 0 length for
// an empty obj rather than dereferencing obj[0].
//
// Note: on calloc failure this panics rather than returning an error, to avoid
// changing the function's external signature (and every call site that depends
// on it). Callers that need graceful OOM handling should recover() around the
// operation that allocates the arena.
func (a *arena) Allocate(obj []byte) (C.CK_VOID_PTR, C.CK_ULONG) {
	if len(obj) == 0 {
		return nil, 0
	}
	size := C.size_t(len(obj))
	cobj := C.calloc(size, 1)
	if cobj == nil {
		panic("pkcs11: calloc failed (out of memory)")
	}
	*a = append(*a, allocation{ptr: cobj, size: size})
	C.memmove(cobj, unsafe.Pointer(&obj[0]), size)
	return C.CK_VOID_PTR(cobj), C.CK_ULONG(len(obj))
}

// Free zeroes and releases every allocation made through this arena, then
// clears the arena so a subsequent Free() call (e.g. a stray defer after an
// early return, or a copied arena value) is a safe no-op instead of a
// double-free.
func (a *arena) Free() {
	if a == nil {
		return
	}
	for _, x := range *a {
		if x.ptr != nil && x.size > 0 {
			C.memset(x.ptr, 0, x.size)
		}
		C.free(x.ptr)
	}
	*a = nil
}


// Error represents an PKCS#11 error.
type Error uint64

func (e Error) Error() string {
	return fmt.Sprintf("pkcs11: 0x%X: %s", uint64(e), strerror[uint64(e)])
}

func toError(e C.CK_RV) error {
	if e == C.CKR_OK {
		return nil
	}
	return Error(e)
}

// In ep11 package
func ToError(rv uint64) error {
    if rv == C.CKR_OK {
        return nil
    }
    return fmt.Errorf("CKR error: 0x%x", rv)
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
			//fmt.Println(len)
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

