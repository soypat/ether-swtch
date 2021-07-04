package swtch

import (
	"github.com/soypat/net"
)

// Wrapper for a Conn
type Conn struct {
	Ethernet *Ethernet
	ARPv4    *ARPv4
	IPv4     *IPv4
	TCP      *TCP

	start Trigger
	n     uint16
	// minimum packet length. will pad extra
	minPlen uint16
	read    bool
	conn    Datagrammer
	packet  Reader
	macAddr net.HardwareAddr
	ipAddr  net.IP
	port    uint16
	err     error
}

type Trigger func(c *Conn) Trigger

func NewTCPConn(rw Datagrammer, payload Frame, MAC net.HardwareAddr, IP net.IP, port uint16) *Conn {
	conn := &Conn{
		macAddr:  MAC,
		ipAddr:   IP,
		port:     port,
		Ethernet: new(Ethernet),
		IPv4:     new(IPv4),
		ARPv4:    new(ARPv4),
		TCP:      &TCP{SubFrame: payload},
		start:    tcpSetCtl, // TCPConn commanded by ethernet frames as data-link layer
	}
	conn.conn = rw
	conn.TCP.PseudoHeaderInfo = conn.IPv4
	return conn
}

func (c *Conn) SendResponse() error {
	_log("sendResp")
	c.read = false
	return c.runIO()
}

func (c *Conn) Decode() error {
	_log("decode")
	if c.packet != nil {
		// Here we discard any unread data before procuring a new packet.
		err := c.packet.Discard()
		if err != nil {
			return err
		}
	}
	c.read = true
	r, err := c.conn.NextPacket()
	if err != nil {
		return err
	}

	c.packet = r
	return c.runIO()
}

func (c *Conn) runIO() error {
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
		if c.err == nil && c.n < c.minPlen {
			_log("runIO:padding")
			n, err := c.conn.Write(make([]byte, c.minPlen-c.n))
			c.n += n
			if err != nil {
				return err
			}
		}
		_log("runIO:FLUSH\n")
		c.err = c.conn.Flush()
	}
	return c.err
}

func (c *Conn) Reset() (err error) {
	if c.TCP != nil {
		set := c.TCP.Set()
		set.Ack(0)
		set.Seq(0)
		set.Source(0)
		set.Flags(0)
		if c.TCP.SubFrame != nil {
			err = c.TCP.SubFrame.Reset()
		}
	}
	if c.IPv4 != nil {
		set := c.IPv4.Set()
		set.TotalLength(0)
		set.Protocol(0)
		set.Version(0)
		set.Destination(net.IP(Broadcast))
	}
	if c.Ethernet != nil {
		set := c.Ethernet.Set()
		set.Destination(Broadcast)
	}
	return err
}

func triggerError(err error) Trigger {
	return func(c *Conn) Trigger {
		c.err = err
		return nil
	}
}
