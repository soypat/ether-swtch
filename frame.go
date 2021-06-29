package swtch

import "net"

type int_t = uint16
type Reader interface {
	Read(b []byte) (n int_t, err error)
	// Discard discards packet data. Reader is terminated as well.
	Discard() error
}

type Writer interface {
	Write(b []byte) (n int_t, err error)
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
	Decode(r Reader) (int_t, error)
	Encode(w Writer) (int_t, error)
	SetResponse(net.HardwareAddr) error
	FrameLength() uint16
}
