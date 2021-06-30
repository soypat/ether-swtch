package swtch

import (
	"io"
	"testing"

	"github.com/soypat/net"

	"github.com/soypat/ether-swtch/hex"
)

func TestTCPStabilityMarshalUnmarshal(t *testing.T) {
	defaultMAC := net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var tests = []struct {
		name        string
		mac         net.HardwareAddr
		tcpSubframe Frame
		data        []byte
	}{
		{
			name: "TCP [SYN,ACK]",
			mac:  defaultMAC,
			data: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
				00 3c 2c da 40 00 40 06 8a 1c c0 a8 01 70 c0 a8
				01 05 e6 28 00 50 3e ab 64 f7 00 00 00 00 a0 02
				fa f0 bf 4c 00 00 02 04 05 b4 04 02 08 0a 08 a2
				77 3f 00 00 00 00 01 03 03 07`)),
		},
		{
			name: "TCP [ACK]",
			mac:  defaultMAC,
			data: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
				00 28 2c dd 40 00 40 06 8a 2d c0 a8 01 70 c0 a8
				01 05 e6 28 00 50 3e ab 66 5c 00 00 0c f7 50 10
				f8 64 83 e0 00 00`)),
		},
		{
			name: "TCP [FIN,ACK]",
			mac:  defaultMAC,
			data: hex.Decode([]byte(` de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
			00 28 2c de 40 00 40 06 8a 2c c0 a8 01 70 c0 a8
			01 05 e6 28 00 50 3e ab 66 5c 00 00 0c f7 50 11
			f8 64 83 e0 00 00`)),
		},
	}
	for _, test := range tests {
		name := test.name
		rwconn := &readbacktest{
			packet: packet{dataOnWire: test.data},
		}
		connTx := NewTCPConn(rwconn, nil, defaultMAC)
		err := connTx.Decode()
		if err != io.EOF && err != nil {
			t.Fatal(err) // cannot procede without unmarshalling contents
		}
		// Prevent modification of frame by skipping default tcpSetCtl routine.
		connTx.start = etherCtl
		err = connTx.SendResponse()
		if err != nil {
			t.Error(err)
		}
		// Data sent will be decoded.
		var readbackconn = &readbacktest{
			packet: packet{
				dataOnWire: rwconn.sent(),
			},
		}
		connRx := NewTCPConn(readbackconn, nil, defaultMAC)
		err = connRx.Decode()
		if err != io.EOF && err != nil {
			t.Fatal(name, err) // cannot procede without unmarshalling contents
		}
		// swap ACK and SEQ back.
		localSeq := connRx.TCP.Ack()
		set := connRx.TCP.Set()
		set.Ack(connRx.TCP.Seq())
		set.Seq(localSeq)
		if errs := assertEqualEthernet(connTx.Ethernet, connRx.Ethernet); errs != nil {
			t.Errorf("%s: Ethernet Tx!=Rx: %v", name, errs)
		}
		if errs := assertEqualIPv4(connTx.IPv4, connRx.IPv4); errs != nil {
			t.Errorf("%s: IPv4 Tx!=Rx: %v", name, errs)
		}
		if errs := assertEqualTCP(connTx.TCP, connRx.TCP); errs != nil {
			t.Errorf("%s: TCP Tx!=Rx: %v", name, errs)
		}
	}
}
