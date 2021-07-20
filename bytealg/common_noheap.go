// +build noheap

package bytealg

import (
	"reflect"
	"unsafe"
)

// Taken from kortschak's simple implementation @ https://groups.google.com/g/golang-nuts/c/Zsfk-VMd_fU
//go:inline
func bytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

//go:inline
func String(b []byte) string {
	return bytesToString(b)
}

//go:inline
func FromString(s string) []byte {
	return stringToBytes(s)
}

// ianlancetaylors suggested implementation. Does not seem to
// work on tested AVR board.
//go:inline
func unsafeGetBytes(s string) []byte {
	return (*[100]byte)(unsafe.Pointer(
		(*reflect.StringHeader)(unsafe.Pointer(&s)).Data),
	)[:len(s):len(s)]
}

// This definetely breaks the capacity field but it's ok
// we are not using the heap if tag noheap is used...
//go:inline
func unsafeByteCast(s string) []byte {
	return (*[300]byte)(unsafe.Pointer(&s))[:len(s):len(s)]
}

var Equal = equal

type _string struct {
	ptr    *byte
	length uintptr
}

type _bytes struct {
	ptr    *byte
	length uintptr
	cap    uintptr
}

// Convert a string to a []byte slice.
// From tinygo implementation.
//go:inline
func stringToBytes(x string) (slice []byte) {
	s := (*_string)(unsafe.Pointer(&x))
	return *(*[]byte)(unsafe.Pointer(&_bytes{ptr: s.ptr, length: s.length, cap: s.length}))
}

// Create a string from a []byte slice.
func stringFromBytes(b []byte) string {
	x := (*_bytes)(unsafe.Pointer(&b))
	return *(*string)(unsafe.Pointer(&_string{ptr: x.ptr, length: x.length}))
}
