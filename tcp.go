package swtch

import (
	"github.com/soypat/ether-swtch/bytealg"
	"github.com/soypat/ether-swtch/grams"
)

// TCP state machine logic.

// subframe response is set before encoding TCP frame and setting it's response
// This is so TCP checksum is done correctly
func tcpSetCtl(c *TCPConn) Trigger {
	_log("tcpSetCtl")
	var trigErr Trigger
	// If reading data this function is not needed
	if c.read {
		return etherCtl
	}

	// We go about setting responses and frame lengths.
	switch c.Ethernet.EtherType() {
	case grams.EtherTypeARP:
		if trigErr = arpSet(c); trigErr != nil {
			return trigErr
		}

	case grams.EtherTypeIPv4:
		// TCP frame is set first to know it's length so that IPv4 length data can be set next
		if trigErr = tcpSet(c); trigErr != nil {
			return trigErr
		}
		if trigErr = ipv4Set(c); trigErr != nil {
			return trigErr
		}
	}

	if trigErr = etherSet(c); trigErr != nil {
		return trigErr
	}

	return etherCtl
}

func tcpCtl(c *TCPConn) Trigger {
	if errTrig := tcpIO(c); errTrig != nil {
		return errTrig
	}
	return nil
}

func tcpIO(c *TCPConn) Trigger {
	if c.read {
		// Unmarshal block.
		c.auxn, c.err = c.packet.Read(c.TCP.Header[:])
		c.n += c.auxn
		if c.auxn >= 12 {
			// switch Ack and Seq (client ack is our seq and vice versa)
			bytealg.Swap(c.TCP.Header[4:8], c.TCP.Header[8:12])
		}
		_log("tcp:decode", c.TCP.Header[:c.auxn])
		if c.err != nil {
			return triggerError(c, c.err)
		}
		// Options are present branch
		for i := 0; i < int(c.TCP.Offset()-5); i++ {
			oi := (i % (len(c.TCP.Options) / grams.TCP_WORDLEN)) * 4 // Option index rewrites options if exceed option array length
			c.auxn, c.err = c.packet.Read(c.TCP.Options[oi : oi+grams.TCP_WORDLEN])
			c.n += c.auxn
			if c.err != nil {
				return triggerError(c, c.err)
			}
		}
		if c.IPv4.TotalLength()-20-uint16(c.TCP.Offset())*grams.TCP_WORDLEN <= 0 || c.TCP.SubFrame == nil {
			return nil
		}
		// Ease stack usage by returning this function and starting TCP's payload decoding in new function.
		return func(c *TCPConn) Trigger {
			c.auxn, c.err = c.TCP.SubFrame.Decode(c.packet)
			c.n += c.auxn
			if c.err != nil {
				return triggerError(c, c.err)
			}
			return nil
		}
	}
	_log("tcp:encode")
	// Marshal block.

	Set := c.TCP.Set()
	// data offset
	Set.HeaderLength(c.TCP.Offset())

	// RFC791 Checksum calculation.
	c.TCP.SetChecksum(&c.checksum)

	// Write TCP header and payload to data
	c.auxn, c.err = c.TCP.Encode(c.conn)
	c.n += c.auxn
	if c.err != nil {
		return triggerError(c, c.err)
	}
	return nil
}

// set default TCP response
func tcpSet(c *TCPConn) Trigger {
	tcp := &c.TCP
	Set := tcp.Set()
	if c.TCP.Source() != c.port {
		Set.Destination(tcp.Source())
		Set.Source(c.port)
	}
	// First TCP packet received clause
	if tcp.HasFlags(grams.TCPHEADER_FLAG_SYN) {
		// const startSeq = 2560
		_log("tcpSet [SYN,ACK]")
		// adds some entropy to sequence number so for loops don't get false positive packets
		var rand uint32 = 2560 //uint32(0x0062&c.IPv4.ID()) + uint32(0x00af&tcp.Checksum())
		Set.Seq(rand)
		Set.UrgentPtr(0)
		Set.Flags(grams.TCPHEADER_FLAG_ACK | grams.TCPHEADER_FLAG_SYN)
		// set Maximum segment size (option 0x02) length 4 (0x04) to 1280 (0x0500)
		Set.Options([]byte{0x02, 0x04, 0x05, 0x00})
		Set.Offset(5 + 1) // Nominal length + options.

		Set.Ack(tcp.Ack() + 1)
		Set.WindowSize(1400) // this is what EtherCard does?
		return nil
	}

	// Default TCP settings
	{
		Set.Offset(5)
		Set.Options(nil)
		Set.WindowSize(1024) // TODO assign meaningful value to window size (or not?)
	}

	_log("tcpSet <NOP>")
	return nil
}
