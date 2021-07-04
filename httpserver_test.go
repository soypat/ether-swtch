package swtch

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/soypat/ether-swtch/hex"
	"github.com/soypat/net"
)

func TestHTTPServer(t *testing.T) {
	t.Parallel()
	const N = 100
	timeout := time.Hour * 500 // long timeout given testing environment (for debugging)
	var (
		mac         = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
		httpContent = defaultOKHeader + "Hello World!"
	)
	dg := newTestDatagrammer(2)
	go HTTPListenAndServe(dg, mac, net.IP{192, 168, 1, 5}, timeout, func(URL []byte) (response []byte) {
		return []byte(httpContent)
	}, func(e error) { t.Error(e) })
	for i := 0; i < N; i++ {
		testInOutHTTPServer(t, dg, httpContent)
	}
}

func testInOutHTTPServer(t *testing.T, dg *TestDatagrammer, httpExpectedContent string) {
	var (
		eth, ethExpect   *Ethernet
		ip, ipExpect     *IPv4
		tcp, tcpExpect   *TCP
		http, httpExpect *HTTP
		// SEQ and ACK will contain absolute number used by the TCP connection
		SEQ, ACK uint32
		// clientHTTPLen accumulates lengths of client http data
		clientHTTPLen uint32
		// serverHTTPLen accumulates lengths of server http data
		serverHTTPLen uint32
	)
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
		pname := "First [SYN]"
		eth, ip, tcp, http = parseHTTPPacket(p)
		if eth == nil || ip == nil || tcp == nil {
			t.Errorf("%s: unexpected nil frame parsing packet", pname)
		}
		if http != nil {
			t.Errorf("%s: http frame expected to be nil", pname)
		}
		ethExpect, ipExpect, tcpExpect, _ = parseHTTPPacket(&packet{dataOnWire: hex.Decode([]byte(` 28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
	00 2c 2c da 40 00 40 06 8a 2c c0 a8 01 05 c0 a8
	01 70 00 50 e6 28 00 00 0a 00 3e ab 64 f8 60 12
	05 78 7b 70 00 00 02 04 05 00 00 00`))})
		errs := assertEqualEthernet(ethExpect, eth)
		if errs != nil {
			t.Errorf("%s: ethernet frames differ expect/got: %s", pname, errs)
		}
		errs = assertEqualIPv4(ipExpect, ip)
		if errs != nil {
			t.Errorf("%s: ip frames differ expect/got: %s", pname, errs)
		}
		// Expected values of TCP as first response hard coded.
		tcpSet := tcpExpect.Set()
		tcpSet.Ack(tcp0.Seq() + 1)
		tcpSet.Flags(TCPHEADER_FLAG_ACK | TCPHEADER_FLAG_SYN)
		tcpSet.Seq(tcp.Seq()) // First seq number is set arbitrarily so it is not checked
		tcpSet.Checksum(tcp.Checksum())

		errs = assertEqualTCP(tcpExpect, tcp)
		if errs != nil {
			t.Errorf("%s: tcp frames differ expect/got: %s", pname, errs)
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
		clientHTTPLen = uint32(len(httpGET.Body)) // Client httpLen
		dg.in(pAck, pGET)
		_, _ = tcpGET, httpGET
		// first packet out now should be [ACK]
		p := dg.out()
		pname := "HTTP [ACK] packet"
		eth, ip, tcp, http = parseHTTPPacket(p)
		if eth == nil || ip == nil || tcp == nil {
			t.Fatalf("%s: unexpected nil frame parsing packet", pname)
		}
		if http != nil {
			t.Errorf("%s: http frame expected to be nil in [ACK] segment", pname)
		}
		ethExpect, ipExpect, tcpExpect, _ = parseHTTPPacket(&packet{dataOnWire: hex.Decode([]byte(`28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
	00 28 2c dc 40 00 40 06 8a 2e c0 a8 01 05 c0 a8
	01 70 00 50 e6 28 00 00 0a 01 3e ab 66 5c 50 10
	04 00 92 8d 00 00 00 00 00 00 00 00`))})
		errs := assertEqualEthernet(ethExpect, eth)
		if errs != nil {
			t.Errorf("%s: ethernet frames differ expect/got: %s", pname, errs)
		}
		errs = assertEqualIPv4(ipExpect, ip)
		if errs != nil {
			t.Errorf("%s: ip frames differ expect/got: %s", pname, errs)
		}
		// Expected values of TCP as first response hard coded.
		tcpSet := tcpExpect.Set()
		tcpSet.Ack(clientHTTPLen + ACK + 1)
		tcpSet.Flags(TCPHEADER_FLAG_ACK)
		tcpSet.Seq(SEQ + 1)
		tcpSet.Checksum(tcp.Checksum())

		errs = assertEqualTCP(tcpExpect, tcp)
		if errs != nil {
			t.Errorf("%s: tcp frames differ expect/got: %s", pname, errs)
		}

		// Second packet after HTTP request is the HTTP response
		p = dg.out()
		pname = "HTTP response [FIN,PSH,ACK]"
		eth, ip, tcp, http = parseHTTPPacket(p)
		if eth == nil || ip == nil || tcp == nil || http == nil {
			t.Errorf("%s:unexpected nil frame parsing packet, outgoing http packet: %s", pname, hex.Bytes(p.dataOnWire))
		}
		expectData := append(hex.Decode([]byte(`28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
	03 1d 2c dc 40 00 40 06 87 39 c0 a8 01 05 c0 a8
	01 70 00 50 e6 28 00 00 0a 01 3e ab 66 5c 50 19
	04 00 2c 98 00 00`)), httpExpectedContent...)
		// replace IP TotalLength field to extend to end of appended http content.
		binary.BigEndian.PutUint16(expectData[16:18], uint16(20+20+len(httpExpectedContent)))
		ethExpect, ipExpect, tcpExpect, httpExpect = parseHTTPPacket(&packet{dataOnWire: expectData})
		// checksum differ since different Total Length field and TCP data
		ipExpect.Set().Checksum(ip.Checksum())

		if ethExpect == nil || ipExpect == nil || tcpExpect == nil || httpExpect == nil {
			t.Fatalf("%s: got nil frame from expected data", pname)
		}
		errs = assertEqualEthernet(ethExpect, eth)
		if errs != nil {
			t.Errorf("%s: ethernet frames differ expect/got: %s", pname, errs)
		}
		errs = assertEqualIPv4(ipExpect, ip)
		if errs != nil {
			t.Errorf("%s: IP frames differ expect/got: %s", pname, errs)
		}
		// Expected values of TCP as first response hard coded.
		tcpSet = tcpExpect.Set()
		tcpSet.Ack(ACK + clientHTTPLen + 1)
		tcpSet.Flags(TCPHEADER_FLAG_ACK | TCPHEADER_FLAG_PSH | TCPHEADER_FLAG_FIN)
		tcpSet.Seq(SEQ + 1)
		tcpSet.Checksum(tcp.Checksum())
		errs = assertEqualTCP(tcpExpect, tcp)
		if errs != nil {
			t.Errorf("%s: TCP frames differ expect/got: %s", pname, errs)
		}
		if !bytes.Equal(httpExpect.Body, http.Body) {
			t.Errorf("%s: different http payloads expect/got:\n%q\n%q", pname, httpExpect.Body, http.Body)
		}
		serverHTTPLen = uint32(len(http.Body))
	}

	// Client responds with [ACK] and [FIN,ACK] segments. Expect server reply of [ACK] ending TCP transmission
	{
		pAck := &packet{dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
	00 28 2c dd 40 00 40 06 8a 2d c0 a8 01 70 c0 a8
	01 05 e6 28 00 50 3e ab 66 5c 00 00 0c f7 50 10
	f8 64 83 e0 00 00`))}
		pFin := &packet{dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00
	00 28 2c de 40 00 40 06 8a 2c c0 a8 01 70 c0 a8
	01 05 e6 28 00 50 3e ab 66 5c 00 00 0c f7 50 11
	f8 64 83 e0 00 00`))}
		// Setting SEQ number as it is important to match handshake data for success of control flow
		binary.BigEndian.PutUint32(pAck.dataOnWire[42:46], SEQ+serverHTTPLen+1)
		binary.BigEndian.PutUint32(pFin.dataOnWire[42:46], SEQ+serverHTTPLen+1)
		dg.in(pAck, pFin)
		// ethAck, ipAck, tcpAck, _ := parseHTTPPacket(pAck)
		p := dg.out()
		pname := "Last [ACK]"
		eth, ip, tcp, http = parseHTTPPacket(p)
		if eth == nil || ip == nil || tcp == nil {
			t.Errorf("%s: unexpected nil frame parsing packet, outgoing http packet: %s", pname, hex.Bytes(p.dataOnWire))
		}
		if http != nil {
			t.Errorf("%s: http frame expected to be nil", pname)
		}
		ethExpect, ipExpect, tcpExpect, _ = parseHTTPPacket(&packet{dataOnWire: hex.Decode([]byte(`28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
	00 28 2c de 40 00 40 06 8a 2c c0 a8 01 05 c0 a8
	01 70 00 50 e6 28 00 00 0c f7 3e ab 66 5d 50 10
	04 00 8f 96 00 00 00 00 00 00 00 00`))})
		if ethExpect == nil || ipExpect == nil || tcpExpect == nil {
			t.Fatalf("%s: got nil frame from expected data", pname)
		}
		errs := assertEqualEthernet(ethExpect, eth)
		if errs != nil {
			t.Errorf("%s: ethernet frames differ expect/got: %s", pname, errs)
		}
		errs = assertEqualIPv4(ipExpect, ip)
		if errs != nil {
			t.Errorf("%s: IP frames differ expect/got: %s", pname, errs)
		}
		// set expected TCP values
		tcpSet := tcpExpect.Set()
		tcpSet.Ack(ACK + clientHTTPLen + 2)
		tcpSet.Seq(SEQ + serverHTTPLen + 2)
		tcpSet.Checksum(tcp.Checksum())
		tcpSet.Flags(TCPHEADER_FLAG_ACK)
		errs = assertEqualTCP(tcpExpect, tcp)
		if errs != nil {
			t.Errorf("%s: TCP frames differ expect/got: %s", pname, errs)
		}
	}
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

// in sends packets over Datagrammer reader over RX
func (dg *TestDatagrammer) in(p ...*packet) {
	for i := range p {
		if p[i] == nil {
			panic("got nil packet in test datagrammer read")
		}
		dg.rx <- p[i]
	}
}

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
	tcpPlen := int(ipPlen) - int(tcp.Offset())*TCP_WORDLEN
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
