// +build !avr
// +build !noheap

package lax

import (
	"fmt"
	"io"
	"time"
)

func IsEOF(err error) bool {
	return err == io.EOF
}

func U32toa(u uint32) string {
	return fmt.Sprintf("%d", u)
}

func LogStringer(msg string, s fmt.Stringer) {
	Log(msg + s.String())
}

// local string concatenation primitive which
// can be replaced with a no-heap version for weeding
// out heap allocations in this package.
func Strcat(s ...string) (out string) {
	if len(s) == 0 {
		return ""
	}
	for i := range s {
		out += s[i]
	}
	return out
}

func spinLoopContent() {
	time.Sleep(time.Microsecond)
}
