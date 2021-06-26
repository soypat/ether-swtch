package swtch

import (
	"time"

	"net"
)

// RConn is a reduced instruction version
// of Go's std library's net.Conn
type RConn interface {
	Reader
	Writer
	Reset() error
	Send() error // not actually part of the std library.
	SetDeadline(t time.Time) error
}

// Wrapper for a Conn
type Conn struct {
	Ethernet *Ethernet
	ARPv4    *ARPv4
	IPv4     *IPv4
	TCP      *TCP
	start    Trigger
	n        uint16
	// minimum packet length. will pad extra
	minPlen uint16
	read    bool
	conn    RConn
	macAddr net.HardwareAddr
	err     error
}

type Trigger func(c *Conn) Trigger

func NewTCPConn(rw RConn, payload Frame, MAC net.HardwareAddr) *Conn {
	conn := &Conn{
		macAddr:  MAC,
		Ethernet: new(Ethernet),
		IPv4:     new(IPv4),
		ARPv4:    new(ARPv4),
		TCP:      new(TCP),
		start:    tcpSetCtl, // TCPConn commanded by ethernet frames as data-link layer
	}
	conn.conn = rw
	conn.TCP.PseudoHeaderInfo = conn.IPv4
	conn.TCP.SubFrame = payload
	return conn
}

func (c *Conn) Encode() error {
	_log("conn:encode")
	c.read = false
	return c.runIO()
}

func (c *Conn) Decode() error {
	_log("conn:decode")
	c.read = true
	return c.runIO()
}

func (c *Conn) runIO() error {
	c.err = nil // reset error
	c.n = 0
	// trig contains statefunction
	var trig Trigger = c.start
	for trig != nil {
		trig = trig(c)
	}
	if !c.read && c.err == nil && c.n < c.minPlen {
		n, err := c.conn.Write(make([]byte, c.minPlen-c.n))
		c.n += n
		c.err = err
	}
	return c.err
}

func triggerError(err error) Trigger {
	return func(c *Conn) Trigger {
		c.err = err
		return nil
	}
}
