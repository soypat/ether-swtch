// +build avr
// +build !noheap

package lax

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

func U32toa(u uint32) string {
	return strconv.Itoa(int(u))
}

func LogStringer(msg string, s fmt.Stringer) {
	Log(msg)
}

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
	time.Sleep(10 * time.Millisecond)
}
