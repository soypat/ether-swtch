// +build avr
// +build !noheap

package swtch

import (
	"fmt"
	"strconv"
	"time"
)

func IsEOF(err error) bool {
	if err != nil {
		return err.Error() == "EOF"
	}
	return false
}

func u32toa(u uint32) string {
	return strconv.Itoa(int(u))
}

func _logStringer(msg string, s fmt.Stringer) {
	_log(msg)
}

func strcat(s ...string) (out string) {
	if len(s) == 0 {
		return ""
	}
	for i := range s {
		out += s[i]
	}
	return out
}

func spinLoopContent() {
	time.Sleep(10 * time.Millisecond)
}
