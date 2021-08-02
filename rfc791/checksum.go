package rfc791

import "encoding/binary"

// Checksum function as defined by RFC 791. The checksumRFC791 field
// is the 16-bit ones' complement of the ones' complement sum of
// all 16-bit words in the header. For purposes of computing the checksumRFC791,
// the value of the checksumRFC791 field is zero.
func checksumRFC791(data []byte) uint16 {
	var sum uint32
	n := len(data) / 2
	// automatic padding of data
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for i := 0; i < n; i++ {
		sum += uint32(binary.BigEndian.Uint16(data[i*2 : i*2+2]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func New() *Checksum {
	return &Checksum{}
}

type Checksum struct {
	sum      uint32
	excedent uint8
	needsPad bool
}

func (c *Checksum) Write(buff []byte) (n int, err error) {
	// automatic padding of uneven data
	if c.needsPad {
		c.sum += uint32(c.excedent)<<8 + uint32(buff[0])
		buff = buff[1:]
		c.needsPad = false
	}
	n = len(buff) / 2
	if len(buff)%2 != 0 {
		c.excedent = buff[len(buff)-1]
		buff = buff[:len(buff)-1]
		c.needsPad = true
	}
	for i := 0; i < n; i++ {
		c.sum += uint32(binary.BigEndian.Uint16(buff[i*2 : i*2+2]))
	}
	return len(buff), nil
}

func (c *Checksum) Sum() uint16 {
	if c.needsPad {
		c.sum += uint32(c.excedent) << 8
		c.needsPad = false
	}
	for c.sum > 0xffff {
		c.sum = c.sum&0xffff + c.sum>>16
	}
	return ^uint16(c.sum)
}

func (c *Checksum) Reset() {
	c.sum = 0
	c.excedent = 0
	c.needsPad = false
}
