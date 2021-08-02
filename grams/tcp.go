package grams

import (
	"encoding/binary"
	"io"

	"github.com/soypat/ether-swtch/bytealg"
	"github.com/soypat/ether-swtch/lax"
	"github.com/soypat/ether-swtch/rfc791"
)

func (tcp *TCP) Init(pseudoHeader *IPv4) {
	tcp.PseudoHeaderInfo = pseudoHeader
	tcp.encoders[0] = tcp.encodePseudo
	tcp.encoders[1] = tcp.encodeHeader
	tcp.encoders[2] = tcp.encodeOptions
	tcp.encoders[3] = tcp.encodeFramer
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

// TCP represents a TCP header and contains
// references to other structures required to marshal and unmarshal.
// Requires initialization with Init() method.
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

	encoders [4]func(r io.Writer) (int, error)
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
func (tcp *TCP) encodePseudo(w io.Writer) (n int, err error) {
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
	n, err = w.Write(ph[8:20])
	set.TTL(ttl)
	set.Checksum(sum)
	_log("tcp:encode pseudo", ph[8:20])
	return n, err
}
func (tcp *TCP) encodeOptions(w io.Writer) (n int, err error) {
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

func (tcp *TCP) encodeHeader(w io.Writer) (n int, err error) {
	n, err = w.Write(tcp.Header[:])
	_log("tcpheader:encode", tcp.Header[:n])
	return
}

func (tcp *TCP) encodeFramer(w io.Writer) (int, error) {
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
	return lax.Strcat("TCP port ", lax.U32toa(uint32(tcp.Source())), "->", lax.U32toa(uint32(tcp.Destination())),
		tcp.StringFlags(), "seq ", lax.U32toa(tcp.Seq()), " ack ", lax.U32toa(tcp.Ack()))
}

func (tcp *TCP) Set() TCPSet {
	return TCPSet{tcp}
}

type TCPSet struct {
	tcp *TCP
}

func (set TCPSet) Reset() (err error) {
	set.tcp.Header = [20]byte{}
	if set.tcp.SubFrame != nil {
		err = set.tcp.SubFrame.Reset()
	}
	return err
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

// SetChecksum calculates RFC791 checksum for the TCP packet, IP header, and contained payload
// and places it in the TCP's header checksum field.
//go:inline
func (tcp *TCP) SetChecksum(checksum *rfc791.Checksum) (err error) {
	Set := tcp.Set()
	// Begin RFC791 Checksum calculation.
	Set.Checksum(0)
	checksum.Reset()
	// Only write subframe if IP packet len is long enough.
	hasPayload := tcp.PseudoHeaderInfo.TotalLength()-20-uint16(tcp.Offset())*TCP_WORDLEN > 0
	for i := range tcp.encoders {
		if i == 3 && !hasPayload {
			continue
		}
		_, err = tcp.encoders[i](checksum)
		if err != nil {
			return err
		}
	}
	Set.Checksum(checksum.Sum())
	return nil
}

// Encode encodes TCP frame to stream along with payload.
func (tcp *TCP) Encode(w io.Writer) (n int, err error) {
	var aux int
	// Write TCP header and payload to data
	for i := range tcp.encoders[1:] { // skip pseudo header and subFramer
		if i == 2 && tcp.SubFrame == nil {
			continue
		}
		aux, err = tcp.encoders[i+1](w)
		n += aux
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
