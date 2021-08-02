package grams

import (
	"net"

	"github.com/soypat/ether-swtch/lax"
)

/* ARP Frame (Address resolution protocol)
see https://www.youtube.com/watch?v=aamG4-tH_m8

Legend:
	HW:    Hardware
	AT:    Address type
	AL:    Address Length
	AoS:   Address of sender
	AoT:   Address of Target
	Proto: Protocol (below is ipv4 example)
0      2          4       5          6         8       14          18       24          28
| HW AT | Proto AT | HW AL | Proto AL | OP Code | HW AoS | Proto AoS | HW AoT | Proto AoT |
|  2B   |  2B      |  1B   |  1B      | 2B      |   6B   |    4B     |  6B    |   4B
| ethern| IP       |macaddr|          |ask|reply|                    |for op=1|
| = 1   |=0x0800   |=6     |=4        | 1 | 2   |       known        |=0      |
*/

type ARPv4 [28]byte

func (a *ARPv4) HWTarget() net.HardwareAddr {
	return a[18:24]
}
func (a *ARPv4) ProtoTarget() net.IP {
	return a[24:28]
}
func (a *ARPv4) HWSender() net.HardwareAddr {
	return a[8:14]
}
func (a *ARPv4) ProtoSender() net.IP {
	return a[14:18]
}

// HWSize Hardware addresss size
func (a *ARPv4) HWSize() uint8 { return a[4] }

// ProtoSize Protocol address size (IPv4 is 4, should always return 4)
func (a *ARPv4) ProtoSize() uint8 { return a[5] }

func (a *ARPv4) FrameLength() uint16 { return uint16(len(a)) }

func (a *ARPv4) String() string {
	// if bytes are only 0, then it is an ARP request
	if bytesAreAll(a.HWTarget(), 0) {
		return lax.Strcat("ARP ", a.HWSender().String(), "->",
			"who has ", a.ProtoTarget().String(), "?", " Tell ", a.ProtoSender().String())
	}
	return lax.Strcat("ARP ", a.HWSender().String(), "->",
		"I have ", a.ProtoSender().String(), "! Tell ", a.ProtoTarget().String(), ", aka ", a.HWTarget().String())
}

func (a *ARPv4) Set() ARPv4Set {
	return ARPv4Set{ARP: a}
}

type ARPv4Set struct {
	ARP *ARPv4
}

func (a ARPv4Set) Reset() {
	*(a.ARP) = ARPv4{}
}

func (a *ARPv4Set) HWTarget(MAC net.HardwareAddr) {
	copy(a.ARP[18:24], MAC)
}
func (a *ARPv4Set) ProtoTarget(ip net.IP) {
	copy(a.ARP[24:28], ip)
}
func (a *ARPv4Set) HWSender(MAC net.HardwareAddr) {
	copy(a.ARP[8:14], MAC)
}
func (a *ARPv4Set) ProtoSender(ip net.IP) {
	copy(a.ARP[14:18], ip)
}

// HWSize Hardware addresss size
func (a *ARPv4Set) HWSize(s uint8) { a.ARP[4] = s }

// ProtoSize Protocol address size (IPv4 is 4, should always return 4)
func (a *ARPv4Set) ProtoSize(s uint8) { a.ARP[5] = s }

// bytesAreAll returns true if b is composed of only unit bytes
func bytesAreAll(b []byte, unit byte) bool {
	for i := range b {
		if b[i] != unit {
			return false
		}
	}
	return true
}
