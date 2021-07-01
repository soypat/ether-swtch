# ether-swtch
Low level Ethernet stack marshaller/unmarshaller for use in tiny places.


*This is a work in progress. The API is subject to change.*

```go
package main

import (
    "github.com/soypat/net"

    swtch "github.com/soypat/ether-swtch"
	"github.com/soypat/ether-swtch/hex"
)

func main() {
    // initialization of what could be an HTTP server.
    MAC := net.HardwareAddr(hex.Decode([]byte("de:ad:be:ef:fe:ff")))
    conn := swtch.NewTCPConn(sim, &swtch.HTTP{}, MAC)

    err := conn.Decode() // decode the next incoming connection
    if !swtch.IsEOF(err) {
        panic(err)
    }
    // conn stores headers in TCP, Ethernet, IP and HTTP frames.

    // We now encode our response.
    // Encode method has response logic, we only need to call it.
    err = conn.Encode()
	if err != nil {
		panic(err)
	}
    // Send method signals the packet is ready to be
    // sent over the wire.
	err = conn.Send()
    if err != nil {
        panic(err)
    }
}


```