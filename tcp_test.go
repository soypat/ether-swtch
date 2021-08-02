package swtch

import (
	"testing"

	"github.com/soypat/ether-swtch/grams"
	"github.com/soypat/ether-swtch/hex"
)

func TestTCPFlags(t *testing.T) {
	var flagfield uint16 = grams.TCPHEADER_FLAG_SYN | grams.TCPHEADER_FLAG_ACK
	p0in := &packet{dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
	00 3c 2c da 40 00 40 06 8a 1c c0 a8 01 70 c0 a8
	01 05 e6 28 00 50 3e ab 64 f7 00 00 00 00 a0 02
	fa f0 bf 4c 00 00 02 04 05 b4 04 02 08 0a 08 a2
	77 3f 00 00 00 00 01 03 03 07`))}
	_, _, tcp0, _ := parseHTTPPacket(p0in)
	tcp1 := *tcp0
	tcp2 := tcp1
	s1 := tcp1.Set()
	s1.Flags(flagfield)
	errs := assertEqualTCP(&tcp1, &tcp2)
	if len(errs) != 1 {
		t.Errorf("expected flag to change exactly one field, got %s", errs)
	}
	if tcp1.Flags() != flagfield {
		t.Errorf("expected flag field to be set to %x, got %x", flagfield, tcp1.Flags())
	}
}

func TestTCPOffset(t *testing.T) {
	tcp := &grams.TCP{}
	set := tcp.Set()
	for _, v := range []uint8{1, 0, 2, 3, 4, 5, 0, 6, 7, 0, 8, 9, 10, 15, 0, 14} {
		set.Offset(v)
		if tcp.Offset() != v {
			t.Errorf("offset set failed for %d", v)
		}
		if tcp.Flags() != 0 {
			t.Errorf("offset %d set flags: %s", v, tcp.StringFlags())
		}
	}

}
