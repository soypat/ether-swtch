package swtch

import (
	"time"

	"github.com/soypat/ether-swtch/rfc791"
	"github.com/soypat/net"
)

// Wrapper for a Conn
type Conn struct {
	Ethernet *Ethernet
	ARPv4    *ARPv4
	IPv4     *IPv4
	TCP      *TCP

	// checksum facilities stored in struct to avoid heap allocations.
	checksum rfc791.Checksum
	timeout  time.Duration
	start    Trigger
	// Packet length counter and auxiliary counter
	n, auxn uint16
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

func NewTCPConn(rw Datagrammer, payload Frame, timeout time.Duration, MAC net.HardwareAddr, IP net.IP, port uint16) *Conn {
	conn := newTCPconn(rw, new(Ethernet), new(IPv4), new(ARPv4), new(TCP), payload, timeout, MAC, IP, port)
	return &conn
}

func newTCPconn(rw Datagrammer, eth *Ethernet, ip *IPv4, arp *ARPv4, tcp *TCP, payload Frame,
	timeout time.Duration, MAC net.HardwareAddr, IP net.IP, port uint16) Conn {
	conn := Conn{
		macAddr:  MAC,
		ipAddr:   IP,
		port:     port,
		Ethernet: eth,
		IPv4:     ip,
		ARPv4:    arp,
		TCP:      tcp,
		start:    tcpSetCtl, // TCPConn commanded by ethernet frames as data-link layer
		timeout:  timeout,
	}
	conn.TCP.SubFrame = payload
	conn.conn = rw
	conn.TCP.PseudoHeaderInfo = conn.IPv4
	conn.TCP.encoders[0] = conn.TCP.encodePseudo
	conn.TCP.encoders[1] = conn.TCP.encodeHeader
	conn.TCP.encoders[2] = conn.TCP.encodeOptions
	conn.TCP.encoders[3] = conn.TCP.encodeFramer
	return conn
}

func (c *Conn) SendResponse() error {
	_log("sendResp")
	c.read = false
	return c.runIO()
}

func (c *Conn) Decode() (err error) {
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
		set.EtherType(0)
		set.Destination(Broadcast)
	}
	if c.ARPv4 != nil {
		set := c.ARPv4.Set()
		set.HWTarget(None)
	}
	return err
}

//go:inline
func triggerError(c *Conn, err error) Trigger {
	c.err = err
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
