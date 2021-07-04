package swtch

import (
	"io"
)

// packet is a testing struct that implements Reader interface.
type packet struct {
	dataOnWire []byte
	ptr        int
}

func (p *packet) Read(b []byte) (n uint16, err error) {
	if p.ptr == len(p.dataOnWire) {
		return 0, io.EOF
	}
	n += uint16(copy(b, p.dataOnWire[p.ptr:]))
	p.ptr += int(n)
	if p.ptr == len(p.dataOnWire) {
		return n, io.EOF
	}
	return n, nil
}

func (p *packet) Discard() error {
	p.ptr = len(p.dataOnWire)
	return nil
}
