package swtch

import (
	"bytes"
	"testing"

	"github.com/soypat/net"

	"github.com/soypat/ether-swtch/hex"
)

func TestUnmarshalSYNPacket(t *testing.T) {
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
	conn := NewTCPConn(rwconn, nil, mac)
	err := conn.Decode()
	if !IsEOF(err) {
		t.Errorf("expected io.EOF err, got %q", err)
	}
	// Ethernet frame checks
	ether := conn.Ethernet
	switch {
	case !bytes.Equal(ether.Destination(), mac):
		t.Error("ethernet: destination MAC address")
	case !bytes.Equal(ether.Source(), []byte{0x28, 0xd2, 0x44, 0x9a, 0x2f, 0xf3}):
		t.Error("ethernet: source MAC address")
	case ether.EtherType() != EtherTypeIPv4:
		t.Error("ethernet: etherType")
	case ether.IsVLAN():
		t.Error("ethernet: VLAN")
	}

	// IP frame checks
	ip := conn.IPv4
	switch {
	case ip.Version() != 0x45:
		t.Error("ipv4: version field")
	case ip.TotalLength() != 60:
		t.Error("ipv4: total length")
	case ip.ID() != 0x2cda:
		t.Error("ipv4: ID")
	case !ip.Flags().DontFragment() || ip.Flags().FragmentOffset() != 0 || ip.Flags().MoreFragments():
		t.Error("ipv4: flags")
	case ip.TTL() != 64:
		t.Error("ipv4: TTL")
	case ip.Protocol() != IPHEADER_PROTOCOL_TCP:
		t.Error("ipv4: expected TCP protocol")
	case ip.Checksum() != 0x8A1C:
		t.Error("ipv4: checksum")
	case !bytes.Equal(ip.Source(), []byte{192, 168, 1, 112}):
		t.Error("ipv4: source address")
	case !bytes.Equal(ip.Destination(), []byte{192, 168, 1, 5}):
		t.Error("ipv4: destination address")
	}

	// TCP Frame checks (no options)
	tcp := conn.TCP
	switch {
	case tcp.Source() != 58920:
		t.Error("tcp: source port")
	case tcp.Destination() != 80:
		t.Error("tcp: dest. port")
	case tcp.Ack() != 0x3EAB64F7: // Client Seq is server Ack.
		t.Error("tcp: (local) acknowledgement number")
	case tcp.Seq() != 0:
		t.Error("tcp: (local) sequence number")
	case tcp.Offset() != 10:
		t.Error("tcp: data offset")
	case tcp.StringFlags() != "[SYN]":
		t.Error("tcp: flag(s) " + tcp.StringFlags())
	case tcp.WindowSize() != 64240:
		t.Error("tcp: window size")
	case tcp.Checksum() != 0xbf4c:
		t.Error("tcp: checksum")
	case tcp.UrgentPtr() != 0:
		t.Error("tcp: urgent pointer")
	}
}

func TestUnmarshalACKPacket(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
00 28 2c db 40 00 40 06 8a 2f c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 64 f8 00 00 0a 01 50 10
fa f0 9d 00 00 00`)),
		},
	}
	conn := NewTCPConn(rwconn, nil, mac)
	err := conn.Decode()
	if !IsEOF(err) {
		t.Errorf("expected io.EOF err, got %q", err)
	}
	// Ethernet frame checks
	ether := conn.Ethernet
	switch {
	case !bytes.Equal(ether.Destination(), mac):
		t.Error("ethernet: destination MAC address")
	case !bytes.Equal(ether.Source(), []byte{0x28, 0xd2, 0x44, 0x9a, 0x2f, 0xf3}):
		t.Error("ethernet: source MAC address")
	case ether.EtherType() != EtherTypeIPv4:
		t.Error("ethernet: etherType")
	case ether.IsVLAN():
		t.Error("ethernet: VLAN")
	}

	// IP frame checks
	ip := conn.IPv4
	switch {
	case ip.Version() != 0x45:
		t.Error("ipv4: version field")
	case ip.TotalLength() != 40:
		t.Error("ipv4: total length")
	case ip.ID() != 0x2CDB:
		t.Error("ipv4: ID")
	case !ip.Flags().DontFragment() || ip.Flags().FragmentOffset() != 0 || ip.Flags().MoreFragments():
		t.Error("ipv4: flags")
	case ip.TTL() != 64:
		t.Error("ipv4: TTL")
	case ip.Protocol() != IPHEADER_PROTOCOL_TCP:
		t.Error("ipv4: expected TCP protocol")
	case ip.Checksum() != 0x8A2F:
		t.Error("ipv4: checksum")
	case !bytes.Equal(ip.Source(), []byte{192, 168, 1, 112}):
		t.Error("ipv4: source address")
	case !bytes.Equal(ip.Destination(), []byte{192, 168, 1, 5}):
		t.Error("ipv4: destination address")
	}

	// TCP Frame checks (no options)
	tcp := conn.TCP
	absSeq := 2560 // absolute sequence number of frame for this particular packet
	switch {
	case tcp.Source() != 58920:
		t.Error("tcp: source port")
	case tcp.Destination() != 80:
		t.Error("tcp: dest. port")
	case tcp.Ack() != 0x3EAB64F8: // Client Seq is server Ack.
		t.Error("tcp: (local) acknowledgement number")
	case tcp.Seq()-uint32(absSeq) != 1:
		t.Error("tcp: (local) sequence number")
	case tcp.Offset() != 5:
		t.Error("tcp: data offset")
	case tcp.StringFlags() != "[ACK]":
		t.Error("tcp: flag(s) " + tcp.StringFlags())
	case tcp.WindowSize() != 64240:
		t.Error("tcp: window size")
	case tcp.Checksum() != 0x9d00:
		t.Error("tcp: checksum")
	case tcp.UrgentPtr() != 0:
		t.Error("tcp: urgent pointer")
	}
}

func TestUnmarshalPSHACKRequest(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00 
01 8c 2c dc 40 00 40 06 88 ca c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 64 f8 00 00 0a 01 50 18
fa f0 85 44 00 00 47 45 54 20 2f 20 48 54 54 50
2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 31 39 32 2e
31 36 38 2e 31 2e 35 0d 0a 55 73 65 72 2d 41 67
65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30
20 28 58 31 31 3b 20 55 62 75 6e 74 75 3b 20 4c
69 6e 75 78 20 78 38 36 5f 36 34 3b 20 72 76 3a
38 37 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30
30 31 30 31 20 46 69 72 65 66 6f 78 2f 38 37 2e
30 0d 0a 41 63 63 65 70 74 3a 20 74 65 78 74 2f
68 74 6d 6c 2c 61 70 70 6c 69 63 61 74 69 6f 6e
2f 78 68 74 6d 6c 2b 78 6d 6c 2c 61 70 70 6c 69
63 61 74 69 6f 6e 2f 78 6d 6c 3b 71 3d 30 2e 39
2c 69 6d 61 67 65 2f 77 65 62 70 2c 2a 2f 2a 3b
71 3d 30 2e 38 0d 0a 41 63 63 65 70 74 2d 4c 61
6e 67 75 61 67 65 3a 20 65 6e 2d 55 53 2c 65 6e
3b 71 3d 30 2e 35 0d 0a 41 63 63 65 70 74 2d 45
6e 63 6f 64 69 6e 67 3a 20 67 7a 69 70 2c 20 64
65 66 6c 61 74 65 0d 0a 43 6f 6e 6e 65 63 74 69
6f 6e 3a 20 6b 65 65 70 2d 61 6c 69 76 65 0d 0a
55 70 67 72 61 64 65 2d 49 6e 73 65 63 75 72 65
2d 52 65 71 75 65 73 74 73 3a 20 31 0d 0a 43 61
63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6d 61 78
2d 61 67 65 3d 30 0d 0a 0d 0a`)),
		},
	}
	conn := NewTCPConn(rwconn, nil, mac)
	err := conn.Decode()
	if !IsEOF(err) && err != nil {
		t.Errorf("expected io.EOF or nil when parsing http with no HTTP frame err, got %q", err)
	}
	// Ethernet frame checks
	ether := conn.Ethernet
	switch {
	case !bytes.Equal(ether.Destination(), mac):
		t.Error("ethernet: destination MAC address")
	case !bytes.Equal(ether.Source(), []byte{0x28, 0xd2, 0x44, 0x9a, 0x2f, 0xf3}):
		t.Error("ethernet: source MAC address")
	case ether.EtherType() != EtherTypeIPv4:
		t.Error("ethernet: etherType")
	case ether.IsVLAN():
		t.Error("ethernet: VLAN")
	}

	// IP frame checks
	ip := conn.IPv4
	switch {
	case ip.Version() != 0x45:
		t.Error("ipv4: version field")
	case ip.TotalLength() != 396:
		t.Error("ipv4: total length")
	case ip.ID() != 0x2CDC:
		t.Error("ipv4: ID")
	case !ip.Flags().DontFragment() || ip.Flags().FragmentOffset() != 0 || ip.Flags().MoreFragments():
		t.Error("ipv4: flags")
	case ip.TTL() != 64:
		t.Error("ipv4: TTL")
	case ip.Protocol() != IPHEADER_PROTOCOL_TCP:
		t.Error("ipv4: expected TCP protocol")
	case ip.Checksum() != 0x88CA:
		t.Error("ipv4: checksum")
	case !bytes.Equal(ip.Source(), []byte{192, 168, 1, 112}):
		t.Error("ipv4: source address")
	case !bytes.Equal(ip.Destination(), []byte{192, 168, 1, 5}):
		t.Error("ipv4: destination address")
	}

	// TCP Frame checks (no options)
	tcp := conn.TCP
	absSeq := 2560 // absolute sequence number of frame for this particular packet
	switch {
	case tcp.Source() != 58920:
		t.Error("tcp: source port")
	case tcp.Destination() != 80:
		t.Error("tcp: dest. port")
	case tcp.Ack() != 0x3EAB64F8: // Client Seq is server Ack.
		t.Error("tcp: (local) acknowledgement number")
	case tcp.Seq()-uint32(absSeq) != 1:
		t.Error("tcp: (local) sequence number")
	case tcp.Offset() != 5:
		t.Error("tcp: data offset")
	case tcp.StringFlags() != "[PSH,ACK]":
		t.Error("tcp: flag(s) " + tcp.StringFlags())
	case tcp.WindowSize() != 64240:
		t.Error("tcp: window size")
	case tcp.Checksum() != 0x8544:
		t.Error("tcp: checksum")
	case tcp.UrgentPtr() != 0:
		t.Error("tcp: urgent pointer")
	}
}

func TestUnmarshalACK2Packet(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
00 28 2c dd 40 00 40 06 8a 2d c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 66 5c 00 00 0c f7 50 10
f8 64 83 e0 00 00`)),
		},
	}
	conn := NewTCPConn(rwconn, nil, mac)
	err := conn.Decode()
	if !IsEOF(err) {
		t.Errorf("expected io.EOF err, got %q", err)
	}
	// Ethernet frame checks
	ether := conn.Ethernet
	switch {
	case !bytes.Equal(ether.Destination(), mac):
		t.Error("ethernet: destination MAC address")
	case !bytes.Equal(ether.Source(), []byte{0x28, 0xd2, 0x44, 0x9a, 0x2f, 0xf3}):
		t.Error("ethernet: source MAC address")
	case ether.EtherType() != EtherTypeIPv4:
		t.Error("ethernet: etherType")
	case ether.IsVLAN():
		t.Error("ethernet: VLAN")
	}

	// IP frame checks
	ip := conn.IPv4
	switch {
	case ip.Version() != 0x45:
		t.Error("ipv4: version field")
	case ip.TotalLength() != 40:
		t.Error("ipv4: total length")
	case ip.ID() != 0x2CDD:
		t.Error("ipv4: ID")
	case !ip.Flags().DontFragment() || ip.Flags().FragmentOffset() != 0 || ip.Flags().MoreFragments():
		t.Error("ipv4: flags")
	case ip.TTL() != 64:
		t.Error("ipv4: TTL")
	case ip.Protocol() != IPHEADER_PROTOCOL_TCP:
		t.Error("ipv4: expected TCP protocol")
	case ip.Checksum() != 0x8A2D:
		t.Error("ipv4: checksum")
	case !bytes.Equal(ip.Source(), []byte{192, 168, 1, 112}):
		t.Error("ipv4: source address")
	case !bytes.Equal(ip.Destination(), []byte{192, 168, 1, 5}):
		t.Error("ipv4: destination address")
	}

	// TCP Frame checks (no options)
	tcp := conn.TCP
	switch {
	case tcp.Source() != 58920:
		t.Error("tcp: source port")
	case tcp.Destination() != 80:
		t.Error("tcp: dest. port")
	case tcp.Ack() != 0x3EAB665C: // Client Seq is server Ack.
		t.Error("tcp: (local) acknowledgement number")
	case tcp.Seq() != 3319:
		t.Error("tcp: (local) sequence number")
	case tcp.Offset() != 5:
		t.Error("tcp: data offset")
	case tcp.StringFlags() != "[ACK]":
		t.Error("tcp: flag(s) " + tcp.StringFlags())
	case tcp.WindowSize() != 63588:
		t.Error("tcp: window size")
	case tcp.Checksum() != 0x83e0:
		t.Error("tcp: checksum")
	case tcp.UrgentPtr() != 0:
		t.Error("tcp: urgent pointer")
	}
}

func TestUnmarshalFINACKPacket(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
00 28 2c de 40 00 40 06 8a 2c c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 66 5c 00 00 0c f7 50 11
f8 64 83 e0 00 00`)),
		},
	}
	conn := NewTCPConn(rwconn, nil, mac)
	err := conn.Decode()
	if !IsEOF(err) {
		t.Errorf("expected io.EOF err, got %q", err)
	}
	// Ethernet frame checks
	ether := conn.Ethernet
	switch {
	case !bytes.Equal(ether.Destination(), mac):
		t.Error("ethernet: destination MAC address")
	case !bytes.Equal(ether.Source(), []byte{0x28, 0xd2, 0x44, 0x9a, 0x2f, 0xf3}):
		t.Error("ethernet: source MAC address")
	case ether.EtherType() != EtherTypeIPv4:
		t.Error("ethernet: etherType")
	case ether.IsVLAN():
		t.Error("ethernet: VLAN")
	}

	// IP frame checks
	ip := conn.IPv4
	switch {
	case ip.Version() != 0x45:
		t.Error("ipv4: version field")
	case ip.TotalLength() != 40:
		t.Error("ipv4: total length")
	case ip.ID() != 0x2CDE:
		t.Error("ipv4: ID")
	case !ip.Flags().DontFragment() || ip.Flags().FragmentOffset() != 0 || ip.Flags().MoreFragments():
		t.Error("ipv4: flags")
	case ip.TTL() != 64:
		t.Error("ipv4: TTL")
	case ip.Protocol() != IPHEADER_PROTOCOL_TCP:
		t.Error("ipv4: expected TCP protocol")
	case ip.Checksum() != 0x8A2C:
		t.Error("ipv4: checksum")
	case !bytes.Equal(ip.Source(), []byte{192, 168, 1, 112}):
		t.Error("ipv4: source address")
	case !bytes.Equal(ip.Destination(), []byte{192, 168, 1, 5}):
		t.Error("ipv4: destination address")
	}

	// TCP Frame checks (no options)
	tcp := conn.TCP
	switch {
	case tcp.Source() != 58920:
		t.Error("tcp: source port")
	case tcp.Destination() != 80:
		t.Error("tcp: dest. port")
	case tcp.Ack() != 0x3EAB665C: // Client Seq is server Ack.
		t.Error("tcp: (local) acknowledgement number")
	case tcp.Seq() != 3319:
		t.Error("tcp: (local) sequence number")
	case tcp.Offset() != 5:
		t.Error("tcp: data offset")
	case tcp.StringFlags() != "[FIN,ACK]":
		t.Error("tcp: flag(s) " + tcp.StringFlags())
	case tcp.WindowSize() != 63588:
		t.Error("tcp: window size")
	case tcp.Checksum() != 0x83e0:
		t.Error("tcp: checksum")
	case tcp.UrgentPtr() != 0:
		t.Error("tcp: urgent pointer")
	}
}

type readbacktest struct {
	packet
	written []byte
}

func (r *readbacktest) Write(b []byte) (uint16, error) {
	r.written = append(r.written, b...)
	return uint16(len(b)), nil
}

func (r *readbacktest) Reset() error {
	r.written = nil
	r.packet.dataOnWire = nil
	return nil
}

func (r *readbacktest) NextPacket() (Reader, error) { return &r.packet, nil }

func (r *readbacktest) Flush() error { return nil }

// sent Returns data written to the buffer
func (r *readbacktest) sent() []byte { return r.written }
