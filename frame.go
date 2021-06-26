package swtch

import "net"

type Reader interface {
	Read(b []byte) (n uint16, err error)
}
type Writer interface {
	Write(b []byte) (n uint16, err error)
}
type Frame interface {
	Decode(r Reader) (uint16, error)
	Encode(w Writer) (uint16, error)
	SetResponse(net.HardwareAddr) error
	FrameLength() uint16
}
