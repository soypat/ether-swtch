// +build !noheap

package lax

import "github.com/soypat/ether-swtch/hex"

// Serial Debug flag. Enables printing of log
var (
	SDB bool
	// When SDB and SDBTrace are enabled only string message is printed.
	SDBTrace bool
)

// debug serial print. If SDB is set to false then it is not compiled unless compiler cannot determine
// SDB does not change. Datas are logged as hex string.
func Log(msg string, datas ...[]byte) {
	if SDB {
		print(Strcat("swtch:", msg))
		if !SDBTrace {
			for d := range datas {
				print(" 0x")
				hex.PrintBytes(datas[d])
			}
		}
		println()
	}
}
