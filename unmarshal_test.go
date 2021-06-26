package swtch

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/soypat/ether-swtch/hex"
)

type packet struct {
	src, dst   string
	dataOnWire []byte
	ptr        int
}

func (p *packet) Read(b []byte) (n uint16, err error) {
	if p.ptr >= len(p.dataOnWire) {
		return 0, io.EOF
	}
	n += uint16(copy(b, p.dataOnWire[p.ptr:]))
	p.ptr += int(n)
	if p.ptr >= len(p.dataOnWire) {
		return n, io.EOF
	}
	return n, nil
}

func packetsFromFile(t *testing.T, filename string) []packet {
	fp, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(fp)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(b, []byte("\n"))
	var p packet
	packets := make([]packet, 0)

	for _, v := range lines {
		if bytes.Index(v, []byte{'#'}) == 0 {
			dec := strings.Fields(string(v[1:]))
			if len(dec) < 2 {
				continue
			}
			if len(p.dataOnWire) != 0 { // first packet
				packets = append(packets, p)
			}
			p.src, p.dst = dec[0], dec[1]
			p.dataOnWire = make([]byte, 0, 50)
			continue
		}
		p.dataOnWire = append(p.dataOnWire, hex.Decode(v)...)
	}
	return packets
}
