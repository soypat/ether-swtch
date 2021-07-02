//+build avr

package swtch

func IsEOF(err error) bool {
	if err != nil {
		return err.Error() == "EOF"
	}
	return false
}
