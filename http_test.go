package swtch

import (
	"io"
	"testing"

	"github.com/soypat/net"

	"github.com/soypat/ether-swtch/hex"
)

func TestUnmarshalHTTPGetRequest(t *testing.T) {
	var mac = net.HardwareAddr(hex.Decode([]byte(`de ad be ef fe ff`)))
	var rwconn = &readbacktest{
		packet: packet{
			dataOnWire: hex.Decode([]byte(`de ad be ef fe ff 28 d2 44 9a 2f f3 08 00 45 00 
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
2d 61 67 65 3d 30 0d 0a 0d 0a`)),
		},
	}
	http := &HTTP{}
	conn := NewTCPConn(rwconn, http, mac)
	err := conn.Decode()
	if err != io.EOF && err != nil {
		t.Errorf("expected io.EOF or nil when parsing http with no HTTP frame err, got %q", err)
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
