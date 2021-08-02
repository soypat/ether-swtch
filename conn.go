package swtch

import (
	"time"

	"net"

	"github.com/soypat/ether-swtch/grams"
	"github.com/soypat/ether-swtch/lax"
	"github.com/soypat/ether-swtch/rfc791"
	"tinygo.org/x/drivers"
)

var _log = lax.Log

// Wrapper for a TCPConn
type TCPConn struct {
	Ethernet grams.Ethernet
	ARPv4    grams.ARPv4
	IPv4     grams.IPv4
	TCP      grams.TCP

	// checksum facilities stored in struct to avoid heap allocations.
	checksum rfc791.Checksum
	timeout  time.Duration
	start    Trigger
	// Packet length counter and auxiliary counter
	n, auxn int
	// minimum packet length. will pad extra
	minPlen int
	read    bool
	conn    drivers.Datagrammer
	packet  drivers.Packet
	macAddr net.HardwareAddr
	ipAddr  net.IP
	port    uint16
	err     error
}

type Trigger func(c *TCPConn) Trigger

func NewTCPConn(rw drivers.Datagrammer, payload grams.Frame, timeout time.Duration, MAC net.HardwareAddr, IP net.IP, port uint16) *TCPConn {
	conn := newTCPconn(rw, payload, timeout, MAC, IP, port)
	return &conn
}

func newTCPconn(rw drivers.Datagrammer, payload grams.Frame, timeout time.Duration, MAC net.HardwareAddr, IP net.IP, port uint16) TCPConn {
	conn := TCPConn{
		macAddr: MAC,
		ipAddr:  IP,
		port:    port,
		start:   tcpSetCtl, // TCPConn commanded by ethernet frames as data-link layer
		timeout: timeout,
	}
	conn.TCP.SubFrame = payload
	conn.conn = rw
	conn.TCP.Init(&conn.IPv4)

	return conn
}

func (c *TCPConn) SendResponse() error {
	_log("sendResp")
	c.read = false
	return c.runIO()
}

func (c *TCPConn) Decode() (err error) {
	_log("decode")
	if c.packet != nil {
		// Here we discard any unread data before procuring a new packet.
		err := c.packet.Discard()
		if err != nil {
			return err
		}
	}
	c.read = true
	c.packet, err = c.conn.NextPacket(time.Now().Add(c.timeout))
	if err != nil {
		return err
	}
	return c.runIO()
}

func (c *TCPConn) runIO() error {
	_log("runIO")
	c.err = nil // reset error
	c.n = 0
	// trig contains statefunction
	var trig Trigger = c.start
	for trig != nil {
		trig = trig(c)
	}
	// End of write tasks
	if !c.read {
		// Pad with ARP bytes (or any available)
		for c.err == nil && c.n < c.minPlen {
			_log("runIO:padding")
			c.auxn, c.err = c.conn.Write(c.ARPv4[:min(len(c.ARPv4), int(c.minPlen-c.n))])
			c.n += c.auxn
			if c.err != nil {
				return c.err
			}
		}
		_log("runIO:FLUSH\n")
		c.err = c.conn.Flush()
	}
	return c.err
}

func (c *TCPConn) Reset() (err error) {
	err = c.TCP.Set().Reset()
	c.IPv4.Set().Reset()
	c.Ethernet.Set().Reset()
	c.ARPv4.Set().Reset()
	return err
}

//go:inline
func triggerError(c *TCPConn, err error) Trigger {
	c.err = err
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
