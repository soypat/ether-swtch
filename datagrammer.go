package swtch

import (
	"time"

	"github.com/soypat/net"
)

// Reader reads from a packet that was received through stream.
type Reader interface {
	Read(b []byte) (n uint16, err error)
	// Discard discards packet data. Reader is terminated as well.
	// If reader already terminated then it should have no effect.
	Discard() error
}

type Writer interface {
	// Writes data to buffer. Flush may need to be called to send packet over stream.
	Write(b []byte) (n uint16, err error)
}

type PacketReader interface {
	// Returns a Reader that reads from the next packet.
	NextPacket(deadline time.Time) (Reader, error)
}

type PacketWriter interface {
	Writer
	// Flush writes buffer to the underlying stream.
	Flush() error
}

// Datagrammer can marshal an unmarshal packets sent over ethernet. Typically is an
// IC with read/write capabilities such as the ENC28J60.
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
