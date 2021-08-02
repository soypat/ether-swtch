package swtch

import (
	"io"
)

// packet is a testing struct that implements Reader interface.
type packet struct {
	dataOnWire []byte
	ptr        int
}

func (p *packet) Read(b []byte) (n int, err error) {
	if p.ptr == len(p.dataOnWire) {
		return 0, io.EOF
	}
	n += copy(b, p.dataOnWire[p.ptr:])
	p.ptr += n
	if p.ptr == len(p.dataOnWire) {
		return n, io.EOF
	}
	return n, nil
}

func (p *packet) Discard() error {
	p.ptr = len(p.dataOnWire)
	return nil
}
