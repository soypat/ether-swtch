// +build !noheap

package bytealg

import "bytes"

// String converts b byte slice to string.
// Differs from built-in string() when calling with
// noheap build tag.
//go:inline
func String(b []byte) string {
	return string(b)
}

//go:inline
func FromString(s string) []byte {
	return []byte(s)
}

var Equal = bytes.Equal
