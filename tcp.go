package swtch

import (
	"encoding/binary"

	"github.com/soypat/ether-swtch/bytealg"
)

// TCP state machine logic.

// subframe response is set before encoding TCP frame and setting it's response
// This is so TCP checksum is done correctly
func tcpSetCtl(c *Conn) Trigger {
	_log("tcpSetCtl")
	var trigErr Trigger
	// If reading data this function is not needed
	if c.read {
		return etherCtl
	}

	// We go about setting responses and frame lengths.
	switch c.Ethernet.EtherType() {
	case EtherTypeARP:
		if trigErr = arpSet(c); trigErr != nil {
			return trigErr
		}

	case EtherTypeIPv4:
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

func tcpCtl(c *Conn) Trigger {
	if errTrig := tcpIO(c); errTrig != nil {
		return errTrig
	}
	return nil
}

func tcpIO(c *Conn) Trigger {
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
			oi := (i % (len(c.TCP.Options) / TCP_WORDLEN)) * 4 // Option index rewrites options if exceed option array length
			c.auxn, c.err = c.packet.Read(c.TCP.Options[oi : oi+TCP_WORDLEN])
			c.n += c.auxn
			if c.err != nil {
				return triggerError(c, c.err)
			}
		}
		if c.IPv4.TotalLength()-20-uint16(c.TCP.Offset())*TCP_WORDLEN <= 0 || c.TCP.SubFrame == nil {
			return nil
		}
		// Ease stack usage by returning this function and starting TCP's payload decoding in new function.
		return func(c *Conn) Trigger {
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
	if c.TCP.PseudoHeaderInfo.Version() != IPHEADER_VERSION_4 {
		return triggerError(c, ErrNotIPv4)
	}
	Set := c.TCP.Set()
	// data offset
	Set.HeaderLength(c.TCP.Offset())

	// Begin RFC791 Checksum calculation.
	Set.Checksum(0)
	checksum := &c.checksum
	checksum.Reset()
	// Only write subframe if IP packet len is long enough.
	hasPayload := c.IPv4.TotalLength()-20-uint16(c.TCP.Offset())*TCP_WORDLEN > 0
	for i := range c.TCP.encoders {
		if i == 3 && !hasPayload {
			continue
		}
		_, c.err = c.TCP.encoders[i](checksum)
		if c.err != nil {
			return triggerError(c, c.err)
		}
	}

	binary.BigEndian.PutUint16(c.TCP.Header[16:18], checksum.Sum())

	// Write TCP header and payload to data
	for i := range c.TCP.encoders[1:] { // skip pseudo header and subFramer
		if i == 2 && !hasPayload {
			continue
		}
		c.auxn, c.err = c.TCP.encoders[i+1](c.conn)
		c.n += c.auxn
		if c.err != nil {
			return triggerError(c, c.err)
		}
	}
	if c.TCP.SubFrame != nil {
		c.err = c.TCP.SubFrame.Reset()
		if c.err != nil {
			return triggerError(c, c.err)
		}
	}
	return nil
}

// set default TCP response
func tcpSet(c *Conn) Trigger {
	tcp := c.TCP
	if tcp.PseudoHeaderInfo == nil {
		return triggerError(c, ErrNeedPseudoHeader)
	}
	Set := tcp.Set()
	if c.TCP.Source() != c.port {
		Set.Destination(tcp.Source())
		Set.Source(c.port)
	}
	// First TCP packet received clause
	if tcp.HasFlags(TCPHEADER_FLAG_SYN) {
		// const startSeq = 2560
		_log("tcpSet [SYN,ACK]")
		// adds some entropy to sequence number so for loops don't get false positive packets
		var rand uint32 = uint32(0x0062&tcp.PseudoHeaderInfo.ID()) + uint32(0x00af&tcp.Checksum())
		Set.Seq(rand)
		Set.UrgentPtr(0)
		Set.Flags(TCPHEADER_FLAG_ACK | TCPHEADER_FLAG_SYN)
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

// There are 9 flags, bits 100 thru 103 are reserved
const (
	// TCP words are 4 octals, or uint32s
	TCP_WORDLEN                 = 4
	TCPHEADER_FLAGS_MASK uint16 = 0x01ff
)
const (
	TCPHEADER_FLAG_FIN = 1 << iota
	TCPHEADER_FLAG_SYN
	TCPHEADER_FLAG_RST
	TCPHEADER_FLAG_PSH
	TCPHEADER_FLAG_ACK
	TCPHEADER_FLAG_URG
	TCPHEADER_FLAG_ECE
	TCPHEADER_FLAG_CWR
	TCPHEADER_FLAG_NS
)

type TCP struct {
	// frame data
	Header [20]byte
	// TCP requires a 12 byte pseudo-header to calculate the checksum
	PseudoHeaderInfo *IPv4

	// LastSeq    uint32
	// limited implementation
	Options [8]byte
	// Need subframe to calculate checksum and total length.
	SubFrame Frame

	encoders [4]func(r Writer) (uint16, error)
}

func (tcp *TCP) Source() uint16      { return binary.BigEndian.Uint16(tcp.Header[0:2]) }
func (tcp *TCP) Destination() uint16 { return binary.BigEndian.Uint16(tcp.Header[2:4]) }
func (tcp *TCP) Seq() uint32         { return binary.BigEndian.Uint32(tcp.Header[4:8]) }
func (tcp *TCP) Ack() uint32         { return binary.BigEndian.Uint32(tcp.Header[8:12]) }
func (tcp *TCP) Offset() uint8       { return tcp.Header[12] >> 4 }
func (tcp *TCP) Flags() uint16 {
	return TCPHEADER_FLAGS_MASK & binary.BigEndian.Uint16(tcp.Header[12:14])
}
func (tcp *TCP) WindowSize() uint16 { return binary.BigEndian.Uint16(tcp.Header[14:16]) }
func (tcp *TCP) Checksum() uint16   { return binary.BigEndian.Uint16(tcp.Header[16:18]) }
func (tcp *TCP) UrgentPtr() uint16  { return binary.BigEndian.Uint16(tcp.Header[18:20]) }

// checksumHeader IPv4 TCP packet and PseudoHeader. Is not safe for concurrent use as it modifies the IP header
func (tcp *TCP) encodePseudo(w Writer) (n uint16, err error) {
	// We take advantage of field layout to avoid heap allocation.
	// |8 TTL |9 Proto |10 Checksum |12  Source  |16  Destination |20
	// |set 0 |  nop   | set length | nop        | nop            |
	ph := tcp.PseudoHeaderInfo
	ln := tcp.FrameLength()
	set := ph.Set()
	ttl := ph.TTL()
	sum := ph.Checksum()
	set.TTL(0)
	set.Checksum(ln)
	// encode pseudo frame
	n, err = w.Write(ph.data[8:20])
	set.TTL(ttl)
	set.Checksum(sum)
	_log("tcp:encode pseudo", ph.data[8:20])
	return
}
func (tcp *TCP) encodeOptions(w Writer) (n uint16, err error) {
	const maxlen = uint8(len(tcp.Options)) / TCP_WORDLEN
	offset := tcp.Offset()
	if offset > 5 {
		if offset-5 > maxlen {
			tcp.Set().Offset(5 + maxlen)
		}
		n, err = w.Write(tcp.Options[0 : (tcp.Offset()-5)*TCP_WORDLEN])
	}
	return n, err
}

func (tcp *TCP) encodeHeader(w Writer) (n uint16, err error) {
	n, err = w.Write(tcp.Header[:])
	_log("tcpheader:encode", tcp.Header[:n])
	return
}

func (tcp *TCP) encodeFramer(w Writer) (uint16, error) {
	if tcp.SubFrame == nil {
		return 0, nil // TODO how to handle this?
	}
	return tcp.SubFrame.Encode(w)
}

// FrameLength for TCP frame. Should be called right after unmarshalling/marshalling TCP frame.
func (tcp *TCP) FrameLength() uint16 {
	var dlen uint16
	if tcp.SubFrame != nil {
		dlen = tcp.SubFrame.FrameLength()
	}
	return uint16(tcp.Offset())*TCP_WORDLEN + dlen
}

// Has Flags returns true if ORflags are all set
func (tcp *TCP) HasFlags(ORflags uint16) bool { return (tcp.Flags() & ORflags) == ORflags }

// String Flag const
const flaglen = 3

var flagbuff = [2 + (flaglen+1)*9]byte{}

// StringFlags returns human readable flag string. i.e:
//  "[SYN,ACK]"
// Flags are printed in order from LSB (FIN) to MSB (NS).
// All flags are printed with length of 3, so a NS flag will
// end with a space i.e. [ACK,NS ]
//
// Beware use on AVR boards and other tiny places as it causes
// a lot of heap allocation and can quickly drain space.
func (tcp *TCP) StringFlags() string {
	const strflags = "FINSYNRSTPSHACKURGECECWRNS "
	n := 0
	for i := 0; i*3 < len(strflags)-flaglen; i++ {
		if tcp.HasFlags(1 << i) {
			if n == 0 {
				flagbuff[0] = '['
				n++
			} else {
				flagbuff[n] = ','
				n++
			}
			copy(flagbuff[n:n+3], []byte(strflags[i*flaglen:i*flaglen+flaglen]))
			n += 3
		}
	}
	if n > 0 {
		flagbuff[n] = ']'
		n++
	}
	return bytealg.String(flagbuff[:n])
}

func (tcp *TCP) String() string {
	return strcat("TCP port ", u32toa(uint32(tcp.Source())), "->", u32toa(uint32(tcp.Destination())),
		tcp.StringFlags(), "seq ", u32toa(tcp.Seq()), " ack ", u32toa(tcp.Ack()))
}

func (tcp *TCP) Set() TCPSet {
	return TCPSet{tcp}
}

type TCPSet struct {
	tcp *TCP
}

func (set TCPSet) Source(p uint16)      { binary.BigEndian.PutUint16(set.tcp.Header[0:2], p) }
func (set TCPSet) Destination(p uint16) { binary.BigEndian.PutUint16(set.tcp.Header[2:4], p) }
func (set TCPSet) Seq(s uint32)         { binary.BigEndian.PutUint32(set.tcp.Header[4:8], s) }
func (set TCPSet) Ack(a uint32)         { binary.BigEndian.PutUint32(set.tcp.Header[8:12], a) }
func (set TCPSet) HeaderLength(o uint8) {
	set.tcp.Header[12] &= 0b0000_0001 // zero out past value and reserved values without modifying flags
	set.tcp.Header[12] |= o << 4
}
func (set TCPSet) WindowSize(w uint16) { binary.BigEndian.PutUint16(set.tcp.Header[14:16], w) }
func (set TCPSet) Checksum(c uint16)   { binary.BigEndian.PutUint16(set.tcp.Header[16:18], c) }
func (set TCPSet) UrgentPtr(u uint16)  { binary.BigEndian.PutUint16(set.tcp.Header[18:20], u) }
func (set TCPSet) Flags(flags uint16) {
	binary.BigEndian.PutUint16(set.tcp.Header[12:14], (uint16(set.tcp.Header[12]&0xf0)<<8)|(TCPHEADER_FLAGS_MASK&flags))
}
func (set TCPSet) Offset(o uint8)            { set.tcp.Header[12] = o << 4 }
func (set TCPSet) ClearFlags(ORflags uint16) { set.Flags(set.tcp.Flags() &^ ORflags) }

func (set TCPSet) Options(opt []byte) {
	const maxwords = uint8(len(set.tcp.Options)) / TCP_WORDLEN
	words := uint8(len(opt) / TCP_WORDLEN)
	if words > maxwords {
		words = maxwords
	}
	set.Offset(5 + words)
	copy(set.tcp.Options[:], opt)
}
