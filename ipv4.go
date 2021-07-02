package swtch

import (
	"encoding/binary"

	"github.com/soypat/net"

	"github.com/soypat/ether-swtch/bytealg"
	"github.com/soypat/ether-swtch/rfc791"
)

// IP state machine logic.

func ipv4Ctl(c *Conn) Trigger {
	_log("ip4Ctl")
	if errTrig := ipv4IO(c); errTrig != nil {
		return errTrig
	}
	switch c.IPv4.Protocol() {
	case IPHEADER_PROTOCOL_TCP:
		if c.TCP == nil {
			break
		}
		return tcpCtl
	}
	return triggerError(ErrUnknownIPProtocol)
}

// set IPv4 response fields.
func ipv4Set(c *Conn) Trigger {
	_log("ip4Set")
	bytealg.Swap(c.IPv4.Source(), c.IPv4.Destination())
	switch c.IPv4.Protocol() {
	case IPHEADER_PROTOCOL_TCP:
		if c.TCP == nil {
			return triggerError(ErrNoProtocol)
		}
		c.IPv4.Plen = c.TCP.FrameLength()
		return nil
	}
	return triggerError(ErrUnknownIPProtocol)
}

func ipv4IO(c *Conn) Trigger {
	var n uint16
	var err error
	if c.read {
		// should read all the data
		n, err = c.packet.Read(c.IPv4.Data[:])
		c.n += n
		_log("ip4:decode", c.IPv4.Data[:n])
		if err != nil {
			return triggerError(err)
		}
		return nil
	}
	_log("ip4:send", c.IPv4.Data[:n])
	// Set TotalLength field. IPv4's payload must have been set beforehand.
	binary.BigEndian.PutUint16(c.IPv4.Data[2:4], c.IPv4.FrameLength())
	// set checksum field to zero to calculate new RFC791 checksum.
	c.IPv4.Data[10] = 0
	c.IPv4.Data[11] = 0
	checksum := rfc791.New()
	checksum.Write(c.IPv4.Data[:])
	binary.BigEndian.PutUint16(c.IPv4.Data[10:12], checksum.Sum())
	n, err = c.conn.Write(c.IPv4.Data[:])
	c.n += n
	if err != nil {
		return triggerError(err)
	}
	return nil
}

// IP header data.

const (
	IPHEADER_FLAG_DONTFRAGMENT  = 0x4000
	IPHEADER_FLAG_MOREFRAGMENTS = 0x8000
	IPHEADER_VERSION_4          = 0x45
	IPHEADER_PROTOCOL_TCP       = 6
)

// See https://hpd.gasmi.net/ to decode Hex Frames

// TODO Handle IGMP
// Frame example: 01 00 5E 00 00 FB 28 D2 44 9A 2F F3 08 00 46 C0 00 20 00 00 40 00 01 02 41 04 C0 A8 01 70 E0 00 00 FB 94 04 00 00 16 00 09 04 E0 00 00 FB 00 00 00 00 00 00 00 00 00 00 00 00 00 00

// TODO Handle LLC Logical Link Control
// Frame example: 05 62 70 73 D7 10 80 04 6C 00 02 00 00 04 00 00 10 20 41 70 00 00 00 0E 00 00 00 19 40 40 00 01 16 4E E9 B0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

// Set Plen on every response.
type IPv4 struct {
	Data [20]byte
	// Payload length in number of octets. Needed to calculate Total Length field.
	Plen uint16
}

func (ip *IPv4) Version() uint8      { return ip.Data[0] }
func (ip *IPv4) IHL() uint8          { return ip.Data[1] }
func (ip *IPv4) TotalLength() uint16 { return binary.BigEndian.Uint16(ip.Data[2:4]) }
func (ip *IPv4) ID() uint16          { return binary.BigEndian.Uint16(ip.Data[4:6]) }
func (ip *IPv4) Flags() IPFlags      { return IPFlags(binary.BigEndian.Uint16(ip.Data[6:8])) }
func (ip *IPv4) TTL() uint8          { return ip.Data[8] }
func (ip *IPv4) Protocol() uint8     { return ip.Data[9] }
func (ip *IPv4) Checksum() uint16    { return binary.BigEndian.Uint16(ip.Data[10:12]) }

// Source IPv4 Address
func (ip *IPv4) Source() net.IP { return ip.Data[12:16] }

// Destination IPv4 Address
func (ip *IPv4) Destination() net.IP { return ip.Data[16:20] }

func (ip *IPv4) FrameLength() uint16 {
	const addrlen uint16 = 4 // IPv4 size.
	headlen := 12 + 2*addrlen
	return headlen + ip.Plen
}

func (ip *IPv4) String() string {
	return "IPv4 " + ip.Source().String() + "->" + ip.Destination().String()
}

type IPFlags uint16

func (f IPFlags) DontFragment() bool     { return f&IPHEADER_FLAG_DONTFRAGMENT != 0 }
func (f IPFlags) MoreFragments() bool    { return f&IPHEADER_FLAG_MOREFRAGMENTS != 0 }
func (f IPFlags) FragmentOffset() uint16 { return uint16(f) & 0x1fff }
