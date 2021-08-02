package grams

import (
	"encoding/binary"
	"net"

	"github.com/soypat/ether-swtch/bytealg"
	"github.com/soypat/ether-swtch/hex"
	"github.com/soypat/ether-swtch/lax"
)

var (
	// Broadcast is a special hardware address which indicates a Frame should
	// be sent to every device on a given LAN segment.
	Broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	None      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

// An EtherType is a value used to identify an upper layer protocol
// encapsulated in a Frame.
//
// A list of IANA-assigned EtherType values may be found here:
// http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml.
type EtherType uint16

// Common EtherType values frequently used in a Frame.
const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeIPv6 EtherType = 0x86DD

	// EtherTypeVLAN and EtherTypeServiceVLAN are used as 802.1Q Tag Protocol
	// Identifiers (TPIDs).
	EtherTypeVLAN        EtherType = 0x8100
	EtherTypeServiceVLAN EtherType = 0x88a8
	// minPayload is the minimum payload size for an Ethernet frame, assuming
	// that no 802.1Q VLAN tags are present.
	minPayload = 46
)

// A Frame is an IEEE 802.3 Ethernet II frame.  A Frame contains information
// such as source and destination hardware addresses, zero or more optional
// 802.1Q VLAN tags, an EtherType, and payload data.
type Ethernet [16]byte

func (f *Ethernet) String() string {
	var vlanstr string
	if f.IsVLAN() {
		vlanstr = "(VLAN)"
	}
	return lax.Strcat("dst: ", f.Destination().String(), ", ",
		"src: ", f.Source().String(), ", ",
		"etype: ", bytealg.String(append(hex.Byte(byte(f.EtherType()>>8)), hex.Byte(byte(f.EtherType()))...)), vlanstr)
}

func (f *Ethernet) Destination() net.HardwareAddr {
	return f[0:6]
}
func (f *Ethernet) Source() net.HardwareAddr {
	return f[6:12]
}

func (f *Ethernet) EtherType() EtherType {
	return EtherType(binary.BigEndian.Uint16(f[12:]))
}

func (f *Ethernet) IsVLAN() bool { return f.EtherType() == EtherTypeVLAN }

type VLANTag uint16

func (f *Ethernet) VLAN() VLANTag {
	if !f.IsVLAN() {
		return 0
	}
	return VLANTag(binary.BigEndian.Uint16(f[14:16]))
}

func (v VLANTag) Identifier() uint16 {
	return 0xfff & uint16(v)
}

func (v VLANTag) CFI() bool {
	return 0x1000&uint16(v) != 0
}

func (v VLANTag) Priority() uint8 {
	return uint8(v >> 13)
}

func (f *Ethernet) Set() EthernetSet {
	return EthernetSet{eth: f}
}

type EthernetSet struct {
	eth *Ethernet
}

func (e EthernetSet) Reset() {
	*(e.eth) = Ethernet{}
}

func (e EthernetSet) Destination(MAC net.HardwareAddr) { copy(e.eth.Destination(), MAC) }
func (e EthernetSet) Source(MAC net.HardwareAddr)      { copy(e.eth.Source(), MAC) }

func (e EthernetSet) EtherType(et EtherType) {
	binary.BigEndian.PutUint16(e.eth[12:14], uint16(et))
}
