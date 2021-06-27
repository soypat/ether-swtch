package swtch

import (
	"io"
	"net"
	"testing"

	"github.com/soypat/ether-swtch/hex"
)

func TestMarshalSYNACKPacket(t *testing.T) {

	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
00 3c 2c da 40 00 40 06 8a 1c c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 64 f7 00 00 00 00 a0 02
fa f0 bf 4c 00 00 02 04 05 b4 04 02 08 0a 08 a2
77 3f 00 00 00 00 01 03 03 07`)),
		},
	}
	connTx := NewTCPConn(rwconn, nil, mac)
	err := connTx.Decode()
	if err != io.EOF && err != nil {
		t.Fatal(err) // cannot procede without unmarshalling contents
	}
	// Prevent modification of frame by skipping default tcpSetCtl routine.
	connTx.start = etherCtl
	err = connTx.Encode()
	if err != nil {
		t.Error(err)
	}
	// Data sent will be decoded.
	var readbackconn = &readbacktest{
		packet: packet{
			dataOnWire: rwconn.sent(),
		},
	}
	connRx := NewTCPConn(readbackconn, nil, mac)
	err = connRx.Decode()
	if err != io.EOF && err != nil {
		t.Fatal(err) // cannot procede without unmarshalling contents
	}
	// swap ACK and SEQ back.
	localSeq := connRx.TCP.Ack()
	set := connRx.TCP.Set()
	set.Ack(connRx.TCP.Seq())
	set.Seq(localSeq)
	if errs := assertEqualEthernet(connRx.Ethernet, connTx.Ethernet); errs != nil {
		t.Fatalf("Ethernet Rx!=Tx: %v", errs)
	}
	if errs := assertEqualIPv4(connRx.IPv4, connTx.IPv4); errs != nil {
		t.Fatalf("IPv4 Rx!=Tx: %v", errs)
	}
	if errs := assertEqualTCP(connRx.TCP, connTx.TCP); errs != nil {
		t.Fatalf("TCP Rx!=Tx: %v", errs)
	}
}
