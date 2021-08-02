package swtch

// The code below was taken from github.com/mdlayher/ethernet and adapted for embedded use
// All credit to mdlayher and the ethernet Authors

import (
	"bytes"

	"github.com/soypat/ether-swtch/grams"
)

// Ethernet state machine logic

// etherCtl controlled decoding/encoding of Ethernet
// frame. Yields more triggers to other functions which
// decode following frames
func etherCtl(c *TCPConn) Trigger {
	_log("ethCtl")
	if errTrig := etherIO(c); errTrig != nil {
		return errTrig
	}
	switch c.Ethernet.EtherType() {
	case grams.EtherTypeARP:
		return arpIO
	case grams.EtherTypeIPv4:
		return ipv4Ctl
	}
	return triggerError(c, ErrUnknownEthProtocol)
}

// etherIO reads to or writes data from
// ethernet frame in Conn.
func etherIO(c *TCPConn) Trigger {
	_log("ethIO")
	var n int
	var err error
	f := &c.Ethernet

	if !c.read {
		// Marshal block.
		n = 14
		if f.IsVLAN() {
			n = 16
		}
		n, err = c.conn.Write(f[:n])
		_log("eth:send", f[:n])
		c.n += n
		if err != nil {
			return triggerError(c, err)
		}
		return nil
	}
	// Unmarshalling logic.
	n, err = c.packet.Read(f[0:14])
	c.n += n
	_log("eth:decoded", f[:n])
	if err != nil {
		return triggerError(c, err)
	}
	if f.IsVLAN() {
		n, err = c.packet.Read(f[14:16])
		c.n += n
		if err != nil {
			return triggerError(c, err)
		}
	}
	return nil
}

// set Ethernet
func etherSet(c *TCPConn) Trigger {
	_log("ethSet")
	f := &c.Ethernet
	Set := f.Set()
	if !bytes.Equal(f.Source(), c.macAddr) {
		Set.Destination(f.Source())
		Set.Source(c.macAddr)
	}
	c.minPlen = 60 // not counting CRC length
	return nil
}
