//+build !avr

package swtch

import "io"

func IsEOF(err error) bool {
	return err == io.EOF
}
