package swtch

import (
	"bytes"
	"fmt"
)

func assertEqualEthernet(a, b *Ethernet) (errs []error) {
	if !bytes.Equal(a.Destination(), b.Destination()) {
		errs = append(errs, fmt.Errorf("destination MAC %s != %s", a.Destination(), b.Destination()))
	}
	if !bytes.Equal(a.Source(), b.Source()) {
		errs = append(errs, fmt.Errorf("source MAC %s != %s", a.Source(), b.Source()))
	}
	if a.EtherType() != b.EtherType() {
		errs = append(errs, fmt.Errorf("ethertype %#x != %#x", a.EtherType(), b.EtherType()))
	}
	if a.IsVLAN() != b.IsVLAN() {
		errs = append(errs, fmt.Errorf("VLAN %t != %t", a.IsVLAN(), b.IsVLAN()))
	}
	return errs
}

func assertEqualIPv4(a, b *IPv4) (errs []error) {
	if a.Version() != b.Version() {
		errs = append(errs, fmt.Errorf("version %#x != %#x", a.Version(), b.Version()))
	}
	if a.TotalLength() != b.TotalLength() {
		errs = append(errs, fmt.Errorf("totallength %d != %d", a.TotalLength(), b.TotalLength()))
	}
	if a.ID() != b.ID() {
		errs = append(errs, fmt.Errorf("ID %#x != %#x", a.ID(), b.ID()))
	}
	if a.Flags() != b.Flags() {
		errs = append(errs, fmt.Errorf("flag %#x != %#x", a.Flags(), b.Flags()))
	}
	if a.TTL() != b.TTL() {
		errs = append(errs, fmt.Errorf("ttl %d != %d", a.TTL(), b.TTL()))
	}
	if a.Checksum() != b.Checksum() {
		errs = append(errs, fmt.Errorf("checksum %#x != %#x", a.Checksum(), b.Checksum()))
	}
	if !bytes.Equal(a.Source(), b.Source()) {
		errs = append(errs, fmt.Errorf("source ip %d != %d", a.Source(), b.Source()))
	}
	if !bytes.Equal(a.Destination(), b.Destination()) {
		errs = append(errs, fmt.Errorf("destination ip %d != %d", a.Destination(), b.Destination()))
	}
	return errs
}

func assertEqualTCP(a, b *TCP) (errs []error) {
	if a.Source() != b.Source() {
		errs = append(errs, fmt.Errorf("source port %d != %d", a.Source(), b.Source()))
	}
	if a.Destination() != b.Destination() {
		errs = append(errs, fmt.Errorf("dest. port %d != %d", a.Destination(), b.Destination()))
	}
	if a.Seq() != b.Seq() {
		errs = append(errs, fmt.Errorf("seq no. %d != %d", a.Seq(), b.Seq()))
	}
	if a.Ack() != b.Ack() {
		errs = append(errs, fmt.Errorf("ack no. %d != %d", a.Ack(), b.Ack()))
	}
	if a.Offset() != b.Offset() {
		errs = append(errs, fmt.Errorf("data offset %d (%d) != %d (%d)", a.Offset()*4, a.Offset(), b.Offset()*4, b.Offset()))
	}
	if a.StringFlags() != b.StringFlags() {
		errs = append(errs, fmt.Errorf("flags %s != %s", a.StringFlags(), b.StringFlags()))
	}
	if a.WindowSize() != b.WindowSize() {
		errs = append(errs, fmt.Errorf("window size %d != %d", a.WindowSize(), b.WindowSize()))
	}
	if a.Checksum() != b.Checksum() {
		errs = append(errs, fmt.Errorf("checksum %#x != %#x", a.Checksum(), b.Checksum()))
	}
	if a.UrgentPtr() != b.UrgentPtr() {
		errs = append(errs, fmt.Errorf("urg. ptr %d != %d", a.UrgentPtr(), b.UrgentPtr()))
	}
	if !bytes.Equal(a.Options[:], b.Options[:]) {
		errs = append(errs, fmt.Errorf("options  %#x != %#x", a.Options, b.Options))
	}
	return errs
}
