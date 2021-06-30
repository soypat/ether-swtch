package swtch

import "github.com/soypat/ether-swtch/hex"

// Serial Debug flag. Enables printing of log
var SDB bool

// debug serial print. If SDB is set to false then it is not compiled unless compiler cannot determine
// SDB does not change
func _log(msg string, datas ...[]byte) {
	if SDB {
		print("swtch:" + msg)
		for d := range datas {
			print(" 0x")
			hex.PrintBytes(datas[d])
		}
		println()
	}
}
