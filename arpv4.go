package swtch

import (
	"github.com/soypat/ether-swtch/bytealg"
)

// ARP state machine logic

// set ARP response
func arpSet(c *TCPConn) Trigger {
	_log("arpSet")
	// These must be pre-filled by an arp response
	if len(c.macAddr) != int(c.ARPv4.HWSize()) {
		return triggerError(c, ErrBadMac)
	}
	// copy HW AoS to HW AoT and MAC to HW AoS
	copy(c.ARPv4.HWTarget(), c.ARPv4.HWSender())
	copy(c.ARPv4.HWSender(), c.macAddr)
	// switch target and source protocol addresses
	bytealg.Swap(c.ARPv4.ProtoSender(), c.ARPv4.ProtoTarget())

	return nil
}

func arpIO(c *TCPConn) Trigger {
	var n int
	var err error
	if !c.read {
		_log("arp:send", c.ARPv4[:])
		// Marshal block
		n, err = c.conn.Write(c.ARPv4[:])
		if err != nil {
			return triggerError(c, err)
		}
		c.n += n
		return nil
	}
	// Unmarshalling block.
	c.ARPv4[5] = 0 // erase proto size to prevent false positive on ipv6 error checking
	n, err = c.packet.Read(c.ARPv4[:])
	c.n += n
	_log("arp:decode", c.ARPv4[:n])
	if err != nil {
		return triggerError(c, err)
	}
	if c.ARPv4.ProtoSize() > 4 {
		triggerError(c, ErrNotIPv4)
	}
	return nil
}
