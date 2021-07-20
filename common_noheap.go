// +build noheap

package swtch

import (
	"github.com/soypat/ether-swtch/bytealg"
	"time"
)

func IsEOF(err error) bool {
	if err != nil {
		return err.Error() == "EOF"
	}
	return false
}

func u32toa(val uint32) string {
	return uitoa(uint(val))
}

// logging is no-op in no heap
func _log(string, ...[]byte)           {}
func _logStringer(string, interface{}) {}

var uibuf [20]byte // big enough for 64bit value base 10

// Convert unsigned integer to decimal string.
func uitoa(val uint) string {
	return "0"
	if val == 0 { // avoid string allocation
		uibuf[0] = '0'
		return bytealg.String(uibuf[:1])
	}

	i := len(uibuf) - 1
	for val >= 10 {
		q := val / 10
		uibuf[i] = byte('0' + val - q*10)
		i--
		val = q
	}
	uibuf[i] = byte('0' + val)

	return bytealg.String(uibuf[i:])
}

func strcat(s ...string) string {
	return ""
}

func spinLoopContent() {
	time.Sleep(10 * time.Millisecond)
}
