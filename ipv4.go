package swtch

import (
	"bytes"
	"encoding/binary"

	"github.com/soypat/ether-swtch/grams"
)

// IP state machine logic.

func ipv4Ctl(c *TCPConn) Trigger {
	_log("ip4Ctl")
	if errTrig := ipv4IO(c); errTrig != nil {
		return errTrig
	}
	switch c.IPv4.Protocol() {
	case grams.IPHEADER_PROTOCOL_TCP:
		return tcpCtl
	}
	return triggerError(c, ErrUnknownIPProtocol)
}

// set IPv4 response fields.
func ipv4Set(c *TCPConn) Trigger {
	_log("ip4Set")
	Set := c.IPv4.Set()
	if !bytes.Equal(c.IPv4.Source(), c.ipAddr) {
		Set.Destination(c.IPv4.Source())
		Set.Source(c.ipAddr)
	}

	switch c.IPv4.Protocol() {
	case grams.IPHEADER_PROTOCOL_TCP:
		Set.TotalLength(c.TCP.FrameLength() + 20) // 20 is the IPv4 header length.
		return nil
	}
	return triggerError(c, ErrUnknownIPProtocol)
}

func ipv4IO(c *TCPConn) Trigger {
	var n int
	var err error
	if c.read {
		// should read all the data
		n, err = c.packet.Read(c.IPv4[:])
		c.n += n
		_log("ip4:decode", c.IPv4[:n])
		if err != nil {
			return triggerError(c, err)
		}
		return nil
	}
	_log("ip4:send", c.IPv4[:n])
	// Set TotalLength field. IPv4's payload must have been set beforehand.
	binary.BigEndian.PutUint16(c.IPv4[2:4], c.IPv4.FrameLength())
	// set checksum field to zero to calculate new RFC791 checksum.
	c.IPv4[10] = 0
	c.IPv4[11] = 0
	c.checksum.Reset()
	c.checksum.Write(c.IPv4[:])

	binary.BigEndian.PutUint16(c.IPv4[10:12], c.checksum.Sum())
	n, err = c.conn.Write(c.IPv4[:])
	c.n += n
	if err != nil {
		return triggerError(c, err)
	}
	return nil
}
