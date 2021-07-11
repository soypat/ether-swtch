// +build !avr
// +build !noheap

package swtch

import (
	"fmt"
	"io"
)

func IsEOF(err error) bool {
	return err == io.EOF
}

func u32toa(u uint32) string {
	return fmt.Sprintf("%d", u)
}

func _logStringer(msg string, s fmt.Stringer) {
	_log(msg + s.String())
}

// local string concatenation primitive which
// can be replaced with a no-heap version for weeding
// out heap allocations in this package.
func strcat(s ...string) (out string) {
	if len(s) == 0 {
		return ""
	}
	for i := range s {
		out += s[i]
	}
	return out
}
