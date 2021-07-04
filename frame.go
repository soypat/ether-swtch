package swtch

import "github.com/soypat/net"

type Reader interface {
	Read(b []byte) (n uint16, err error)
	// Discard discards packet data. Reader is terminated as well.
	// If reader already terminated then it should have no effect.
	Discard() error
}

type Writer interface {
	Write(b []byte) (n uint16, err error)
}

type PacketReader interface {
	NextPacket() (Reader, error)
}

type PacketWriter interface {
	Writer
	// Flush writer buffer to the underlying stream.
	Flush() error
}

// Datagrammer can marshal an unmarshal packets sent over ethernet.
type Datagrammer interface {
	PacketWriter
	PacketReader
}

type Frame interface {
	Decode(r Reader) (uint16, error)
	Encode(w Writer) (uint16, error)
	SetResponse(net.HardwareAddr) error
	FrameLength() uint16
	Reset() error
}
