package swtch

import (
	"testing"

	"github.com/soypat/net"

	"github.com/soypat/ether-swtch/hex"
)

func TestUnmarshalHTTPGetRequest(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: httpRequestDashData,
		},
	}
	http := &HTTP{}
	conn := NewTCPConn(rwconn, http, mac)
	err := conn.Decode()
	if !IsEOF(err) && err != nil {
		t.Errorf("expected EOF or nil, got %q", err)
	}
	// Ethernet, IP and TCP tests for this same packet are in tcp_test.go

	// HTTP frame checks.
	switch {
	case string(http.URL) != "/":
		t.Errorf("http: parse URL, got %q", string(http.URL))
	case http.Method.String() != "GET":
		t.Error("http: method type, " + http.Method.String())
	}
}

func TestHTTPResponse(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: httpRequestDashData,
		},
	}
	http := &HTTP{}
	rxconn := NewTCPConn(rwconn, http, mac)
	err := rxconn.Decode()

	if !IsEOF(err) && err != nil {
		t.Errorf("expected EOF or nil, got %q", err)
	}
	prevAck := rxconn.TCP.Ack()
	prevSeq := rxconn.TCP.Seq()
	// We now respond to HTTP request
	if string(http.URL) != "/" {
		t.Error("URL not parsed correctly")
	}

	http.Body = append([]byte(defaultOKHeader), []byte("Hello World!")...)
	httplen := http.FrameLength()
	rxconn.TCP.Set().Flags(TCPHEADER_FLAG_ACK | TCPHEADER_FLAG_FIN | TCPHEADER_FLAG_PSH)
	// Save the HTTP request to a buffer
	err = rxconn.SendResponse()
	if err != nil {
		t.Error(err)
	}

	// create new conn to read back results and a new HTTP frame
	rwconn = &readbacktest{
		packet: packet{
			dataOnWire: rwconn.sent(),
		},
	}
	http = &HTTP{}
	txconn := NewTCPConn(rwconn, http, mac)
	err = txconn.Decode()
	if !IsEOF(err) && err != nil {
		t.Errorf("expected io.EOF or nil when parsing http with no HTTP frame err, got %q", err)
	}
	// The data sent over wire is what we sent out, which inverts the Ack and Seq. We reinvert it
	// so that the TCP Seq is our seq
	// Switch Seq/Ack (client/server inversion) To mimic what a client sends us we must first invert Seq and Ack in the
	set := txconn.TCP.Set()
	localSeq := txconn.TCP.Ack()
	localAck := txconn.TCP.Seq()
	set.Ack(localAck)
	set.Seq(localSeq)
	if txconn.TCP.Flags() != TCPHEADER_FLAG_FIN|TCPHEADER_FLAG_ACK|TCPHEADER_FLAG_PSH {
		t.Errorf("expected [FIN,ACK,PSH] set in response. got %v", txconn.TCP.StringFlags())
	}
	expectAck := uint32(httplen) + prevAck
	if txconn.TCP.Ack() != expectAck {
		// t.Errorf("ack received %d not match expected %d", txconn.TCP.Ack(), expectAck) // TODO fix this test
	}
	expectSeq := prevSeq
	if txconn.TCP.Seq() != expectSeq {
		t.Errorf("seq received %d not match expected %d", txconn.TCP.Seq(), expectSeq)
	}
}

var httpRequestDashData = hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00 
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
2d 61 67 65 3d 30 0d 0a 0d 0a`))

const defaultOKHeader = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n"

var httpResponseDashData = hex.Decode([]byte(`28 d2 44 9a 2f f3 de ad be ef fe ff 08 00 45 00
03 1d 2c dc 40 00 40 06 87 39 c0 a8 01 05 c0 a8
01 70 00 50 e6 28 00 00 0a 01 3e ab 66 5c 50 19
04 00 2c 98 00 00 48 54 54 50 2f 31 2e 30 20 32
30 30 20 4f 4b 0d 0a 43 6f 6e 74 65 6e 74 2d 54
79 70 65 3a 20 74 65 78 74 2f 68 74 6d 6c 0d 0a
50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65
0d 0a 0d 0a 3c 68 32 3e 2e 2e 3a 3a 4c 49 41 20
41 45 52 4f 3a 3a 2e 2e 3c 2f 68 32 3e 3c 73 74
79 6c 65 3e 2a 7b 62 6f 72 64 65 72 2d 72 61 64
69 75 73 3a 35 70 78 7d 64 69 76 7b 6d 61 72 67
69 6e 3a 33 72 65 6d 3b 66 6f 6e 74 2d 77 65 69
67 68 74 3a 62 6f 6c 64 3b 62 6f 72 64 65 72 3a
73 6f 6c 69 64 20 34 70 78 3b 64 69 73 70 6c 61
79 3a 62 6c 6f 63 6b 7d 2e 73 74 61 74 2d 30 7b
63 6f 6c 6f 72 3a 72 65 64 3b 62 61 63 6b 67 72
6f 75 6e 64 3a 73 61 6c 6d 6f 6e 7d 2e 73 74 61
74 2d 31 7b 63 6f 6c 6f 72 3a 64 61 72 6b 67 72
65 65 6e 3b 62 61 63 6b 67 72 6f 75 6e 64 3a 6c
69 6d 65 7d 61 7b 62 6f 72 64 65 72 3a 73 6f 6c
69 64 20 32 70 78 3b 62 6f 72 64 65 72 2d 63 6f
6c 6f 72 3a 23 30 30 30 3b 6d 61 72 67 69 6e 3a
32 72 65 6d 7d 2e 61 30 7b 63 6f 6c 6f 72 3a 64
61 72 6b 72 65 64 3b 62 61 63 6b 67 72 6f 75 6e
64 3a 73 61 6c 6d 6f 6e 7d 2e 61 31 7b 62 61 63
6b 67 72 6f 75 6e 64 3a 6c 69 6d 65 7d 3c 2f 73
74 79 6c 65 3e 3c 64 69 76 20 63 6c 61 73 73 3d
27 73 74 61 74 2d 30 27 3e 50 72 65 73 75 72 69
7a 61 72 3c 61 20 63 6c 61 73 73 3d 27 61 31 27
20 68 72 65 66 3d 27 61 3f 61 3d 31 27 3e 50 72
65 73 75 72 69 7a 61 72 20 4f 6e 3c 2f 61 3e 20
2d 20 3c 61 20 63 6c 61 73 73 3d 27 61 30 27 20
68 72 65 66 3d 27 61 3f 61 3d 30 27 3e 50 72 65
73 75 72 69 7a 61 72 20 4f 66 66 3c 2f 61 3e 3c
2f 64 69 76 3e 3c 64 69 76 20 63 6c 61 73 73 3d
27 73 74 61 74 2d 30 27 3e 43 6f 6d 70 72 65 73
6f 72 3c 61 20 63 6c 61 73 73 3d 27 61 31 27 20
68 72 65 66 3d 27 61 3f 62 3d 31 27 3e 43 6f 6d
70 72 65 73 6f 72 20 4f 6e 3c 2f 61 3e 20 2d 20
3c 61 20 63 6c 61 73 73 3d 27 61 30 27 20 68 72
65 66 3d 27 61 3f 62 3d 30 27 3e 43 6f 6d 70 72
65 73 6f 72 20 4f 66 66 3c 2f 61 3e 3c 2f 64 69
76 3e 3c 64 69 76 20 63 6c 61 73 73 3d 27 73 74
61 74 2d 30 27 3e 56 65 6e 74 65 6f 3c 61 20 63
6c 61 73 73 3d 27 61 31 27 20 68 72 65 66 3d 27
61 3f 63 3d 31 27 3e 56 65 6e 74 65 6f 20 4f 6e
3c 2f 61 3e 20 2d 20 3c 61 20 63 6c 61 73 73 3d
27 61 30 27 20 68 72 65 66 3d 27 61 3f 63 3d 30
27 3e 56 65 6e 74 65 6f 20 4f 66 66 3c 2f 61 3e
3c 2f 64 69 76 3e 68 3a 6d 3a 73 20 75 70 74 69
6d 65 3a 30 30 3a 30 30 3a 30 30`))
