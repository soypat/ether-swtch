package swtch

import (
	"testing"

	"github.com/soypat/ether-swtch/hex"
	"github.com/soypat/net"
)

func TestHTTPServer(t *testing.T) {
	t.Parallel()
	var (
		mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))

		eth, ethExpect   *Ethernet
		ip, ipExpect     *IPv4
		tcp, tcpExpect   *TCP
		http, httpExpect *HTTP
		// SEQ and ACK will contain absolute number used by the TCP connection
		SEQ, ACK uint32
	)
	dg := newTestDatagrammer(2)
	go HTTPListenAndServe(dg, mac, net.IP{192, 168, 1, 5}, func(URL []byte) (response []byte) {
		return []byte(defaultOKHeader + "Hello World!")
	}, func(e error) { t.Error(e) })

	// Send [SYN] TCP Packet
	{
		p0in := &packet{dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
	00 3c 2c da 40 00 40 06 8a 1c c0 a8 01 70 c0 a8
	01 05 e6 28 00 50 3e ab 64 f7 00 00 00 00 a0 02
	fa f0 bf 4c 00 00 02 04 05 b4 04 02 08 0a 08 a2
	77 3f 00 00 00 00 01 03 03 07`))}
		_, _, tcp0, _ := parseHTTPPacket(p0in)
		dg.in(p0in)
		p := dg.out()

		eth, ip, tcp, http = parseHTTPPacket(p)
		if eth == nil || ip == nil || tcp == nil || http != nil {
			t.Error("unexpected nil frame parsing packet")
		}
		ethExpect, ipExpect, tcpExpect, httpExpect = parseHTTPPacket(&packet{dataOnWire: hex.Decode([]byte(` 28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
00 2c 2c da 40 00 40 06 8a 2c c0 a8 01 05 c0 a8
01 70 00 50 e6 28 00 00 0a 00 3e ab 64 f8 60 12
05 78 7b 70 00 00 02 04 05 00 00 00`))})
		errs := assertEqualEthernet(ethExpect, eth)
		if errs != nil {
			t.Errorf("ethernet frames differ expect/got: %s", errs)
		}
		errs = assertEqualIPv4(ipExpect, ip)
		if errs != nil {
			t.Errorf("ip frames differ expect/got: %s", errs)
		}
		// Expected values of TCP as first response hard coded.
		tcpSet := tcpExpect.Set()
		tcpSet.Ack(tcp0.Seq() + 1)
		tcpSet.Flags(TCPHEADER_FLAG_ACK | TCPHEADER_FLAG_SYN)
		tcpSet.Seq(tcp.Seq()) // First seq number is set arbitrarily so it is not checked
		tcpSet.Checksum(tcp.Checksum())

		errs = assertEqualTCP(tcpExpect, tcp)
		if errs != nil {
			t.Errorf("tcp frames differ expect/got: %s", errs)
		}
		ACK, SEQ = tcp0.Seq(), tcp.Seq()
	}
	// Send [ACK] + HTTP GET request TCP Packets
	{
		pAck := &packet{dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
00 28 2c db 40 00 40 06 8a 2f c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 64 f8 00 00 0a 01 50 10
fa f0 9d 00 00 00`))}
		pGET := &packet{dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
01 8c 2c dc 40 00 40 06 88 ca c0 a8 01 70 c0 a8
01 05 e6 28 00 50 3e ab 64 f8 00 00 0a 01 50 18
fa f0 85 44 00 00 47 45 54 20 2f 20 48 54 54 50
2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 31 39 32 2e
31 36 38 2e 31 2e 35 0d 0a 55 73 65 72 2d 41 67
65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30
20 28 58 31 31 3b 20 55 62 75 6e 74 75 3b 20 4c
69 6e 75 78 20 78 38 36 5f 36 34 3b 20 72 76 3a
38 37 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30
30 31 30 31 20 46 69 72 65 66 6f 78 2f 38 37 2e
30 0d 0a 41 63 63 65 70 74 3a 20 74 65 78 74 2f
68 74 6d 6c 2c 61 70 70 6c 69 63 61 74 69 6f 6e
2f 78 68 74 6d 6c 2b 78 6d 6c 2c 61 70 70 6c 69
63 61 74 69 6f 6e 2f 78 6d 6c 3b 71 3d 30 2e 39
2c 69 6d 61 67 65 2f 77 65 62 70 2c 2a 2f 2a 3b
71 3d 30 2e 38 0d 0a 41 63 63 65 70 74 2d 4c 61
6e 67 75 61 67 65 3a 20 65 6e 2d 55 53 2c 65 6e
3b 71 3d 30 2e 35 0d 0a 41 63 63 65 70 74 2d 45
6e 63 6f 64 69 6e 67 3a 20 67 7a 69 70 2c 20 64
65 66 6c 61 74 65 0d 0a 43 6f 6e 6e 65 63 74 69
6f 6e 3a 20 6b 65 65 70 2d 61 6c 69 76 65 0d 0a
55 70 67 72 61 64 65 2d 49 6e 73 65 63 75 72 65
2d 52 65 71 75 65 73 74 73 3a 20 31 0d 0a 43 61
63 68 65 2d 43 6f 6e 74 72 6f 6c 3a 20 6d 61 78
2d 61 67 65 3d 30 0d 0a 0d 0a`))}

		// send packets
		_, _, tcpGET, httpGET := parseHTTPPacket(pGET)
		httpLen := len(httpGET.Body)
		dg.in(pAck)
		dg.in(pGET)
		_, _ = tcpGET, httpGET
		// first packet out now should be [ACK]
		p := dg.out()
		eth, ip, tcp, http = parseHTTPPacket(p)
		if eth == nil || ip == nil || tcp == nil || http != nil {
			t.Error("unexpected nil frame parsing packet")
		}
		ethExpect, ipExpect, tcpExpect, httpExpect = parseHTTPPacket(&packet{dataOnWire: hex.Decode([]byte(`28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
00 28 2c dc 40 00 40 06 8a 2e c0 a8 01 05 c0 a8
01 70 00 50 e6 28 00 00 0a 01 3e ab 66 5c 50 10
04 00 92 8d 00 00 00 00 00 00 00 00`))})
		errs := assertEqualEthernet(ethExpect, eth)
		if errs != nil {
			t.Errorf("ethernet frames differ expect/got: %s", errs)
		}
		errs = assertEqualIPv4(ipExpect, ip)
		if errs != nil {
			t.Errorf("ip frames differ expect/got: %s", errs)
		}
		// Expected values of TCP as first response hard coded.
		tcpSet := tcpExpect.Set()
		tcpSet.Ack(uint32(httpLen) + ACK + 1)
		tcpSet.Flags(TCPHEADER_FLAG_ACK)
		tcpSet.Seq(SEQ + 1)
		tcpSet.Checksum(tcp.Checksum())

		errs = assertEqualTCP(tcpExpect, tcp)
		if errs != nil {
			t.Errorf("tcp frames differ expect/got: %s", errs)
		}
	}

	_, _, _ = ipExpect, tcpExpect, httpExpect

}

func newTestDatagrammer(nbuff int) *TestDatagrammer {
	return &TestDatagrammer{
		rx: make(chan *packet),
		tx: make(chan *packet, nbuff),
	}
}

type TestDatagrammer struct {
	// Rx are packets that are passed to the underlying Reader of Datagrammer packets.
	rx chan *packet
	// Tx is buffered channel of packets written to Datagrammer.
	tx     chan *packet
	buffer []*packet
	ptr    int
}

func (dg *TestDatagrammer) NextPacket() (Reader, error) {
	return <-dg.rx, nil
}

func (dg *TestDatagrammer) Write(b []byte) (uint16, error) {
	if len(dg.buffer) == 0 {
		dg.buffer = []*packet{{}}
	}
	dg.buffer[len(dg.buffer)-1].dataOnWire = append(dg.buffer[len(dg.buffer)-1].dataOnWire, b...)
	return uint16(len(b)), nil
}

func (dg *TestDatagrammer) Flush() error {
	dg.buffer = append(dg.buffer, &packet{})
	pout := dg.buffer[len(dg.buffer)-2]
	dg.tx <- pout
	return nil
}

func (dg *TestDatagrammer) in(p *packet) { dg.rx <- p }

// out returns a packet that was sent over datagrammer
// using Write and Flush method. These packets are treated as a
// FIFO queue and if no packets in the queue it will return nil.
func (dg *TestDatagrammer) out() *packet { return <-dg.tx }

func parseHTTPPacket(p *packet) (eth *Ethernet, ip *IPv4, tcp *TCP, http *HTTP) {
	var n int
	buff := p.dataOnWire
	// Read Ethernet frame
	{
		if len(buff) < len(eth.data) {
			return
		}
		eth = &Ethernet{}
		// no VLAN=> read up to 14
		n += copy(eth.data[n:14], buff)
	}
	// Read IP Frame
	{
		if len(buff[n:]) < len(ip.data) {
			return
		}
		ip = &IPv4{}
		n += copy(ip.data[:], buff[n:])
	}

	// Define payload lengths
	ipPlen := ip.TotalLength() - 20
	// Read TCP Frame
	{
		if len(buff[n:]) < len(tcp.Header) {
			return
		}
		if int(ipPlen) > len(buff[n:]) {
			panic("buffer smaller than IP declared payload length")
		}
		tcp = &TCP{}
		n += copy(tcp.Header[:], buff[n:])
		optionOctets := (tcp.Offset() - 5) * TCP_WORDLEN
		if optionOctets > 0 {
			// TCP options present
			var q int
			q += copy(tcp.Options[:], buff[n:])
			n += q
			if q < int(optionOctets) {
				// If we did not read ALL the options, we skip them
				n += int(optionOctets) - q
			}
			if n > len(buff) {
				panic("bad TCP data offset")
			}
		}
	}
	tcpPlen := ipPlen - uint16(tcp.Offset())*TCP_WORDLEN
	if tcpPlen < 0 {
		panic("IP declared length mismatch with TCP offset")
	}
	if tcpPlen == 0 {
		return
	}
	// Read HTTP Frame
	{
		if len(buff[n:]) == 0 {
			return
		}
		http = &HTTP{Body: make([]byte, len(buff[n:]))}
		copy(http.Body, buff[n:])
	}
	return
}
