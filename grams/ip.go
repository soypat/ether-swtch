package grams

import (
	"encoding/binary"
	"net"

	"github.com/soypat/ether-swtch/lax"
)

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
type IPv4 [20]byte

func (ip *IPv4) Version() uint8 { return ip[0] }
func (ip *IPv4) IHL() uint8     { return ip[1] }

// TotalLength IPv4 field indicating the combined length of the IP header and payload length in octets.
func (ip *IPv4) TotalLength() uint16 { return binary.BigEndian.Uint16(ip[2:4]) }
func (ip *IPv4) ID() uint16          { return binary.BigEndian.Uint16(ip[4:6]) }
func (ip *IPv4) Flags() IPFlags      { return IPFlags(binary.BigEndian.Uint16(ip[6:8])) }
func (ip *IPv4) TTL() uint8          { return ip[8] }
func (ip *IPv4) Protocol() uint8     { return ip[9] }
func (ip *IPv4) Checksum() uint16    { return binary.BigEndian.Uint16(ip[10:12]) }

// Source IPv4 Address
func (ip *IPv4) Source() net.IP { return ip[12:16] }

// Destination IPv4 Address
func (ip *IPv4) Destination() net.IP { return ip[16:20] }

// Framelength is an alias for IP's Total length field.
func (ip *IPv4) FrameLength() uint16 {
	return ip.TotalLength()
}

func (ip *IPv4) String() string {
	return lax.Strcat("IPv4 ", ip.Source().String(), "->", ip.Destination().String())
}

type IPFlags uint16

func (f IPFlags) DontFragment() bool     { return f&IPHEADER_FLAG_DONTFRAGMENT != 0 }
func (f IPFlags) MoreFragments() bool    { return f&IPHEADER_FLAG_MOREFRAGMENTS != 0 }
func (f IPFlags) FragmentOffset() uint16 { return uint16(f) & 0x1fff }

func (ip *IPv4) Set() IPv4Set { return IPv4Set{ip} }

// IPv4Set is a helper struct to set fields of IPv4 data buffer.
type IPv4Set struct {
	ip *IPv4
}

func (s IPv4Set) Reset() {
	*(s.ip) = IPv4{} // may optimize to memset. up to compiler.
}

func (s IPv4Set) Version(v uint8)         { s.ip[0] = v }
func (s IPv4Set) IHL(ihl uint8)           { s.ip[1] = ihl }
func (s IPv4Set) TotalLength(plen uint16) { binary.BigEndian.PutUint16(s.ip[2:4], plen) }
func (s IPv4Set) ID(id uint16)            { binary.BigEndian.PutUint16(s.ip[4:6], id) }
func (s IPv4Set) Flags(ORFlags uint16)    { binary.BigEndian.PutUint16(s.ip[6:8], ORFlags) }
func (s IPv4Set) TTL(ttl uint8)           { s.ip[8] = ttl }
func (s IPv4Set) Protocol(p uint8)        { s.ip[9] = p }
func (s IPv4Set) Checksum(c uint16)       { binary.BigEndian.PutUint16(s.ip[10:12], c) }

// Source sets the source IPv4 Address
func (s IPv4Set) Source(ip net.IP) { copy(s.ip[12:16], ip) }

// Destination sets the destination IPv4 Address
func (s IPv4Set) Destination(ip net.IP) { copy(s.ip[16:20], ip) }
