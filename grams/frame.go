package grams

import (
	"io"
	"net"
)

type Frame interface {
	Decode(r io.Reader) (int, error)
	Encode(w io.Writer) (int, error)
	SetResponse(net.HardwareAddr) error
	FrameLength() uint16
	Reset() error
}
