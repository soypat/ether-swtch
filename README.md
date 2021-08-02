# ether-swtch
Low level Ethernet/IP/TCP/HTTP stack marshaller/unmarshaller for use in tiny places.


*This is a work in progress. The API is subject to change.*

Below is an example of an HTTP server for the ENC28J60 integrated circuit using TinyGo. Works on the Arduino Mega 2560. Use build tag `-tags=noheap` to reduce heap allocations.
```go
package main

import (
    "net"

    swtch "github.com/soypat/ether-swtch"
    "github.com/soypat/ether-swtch/hex"
)

func main() {
	var (
		// SPI Chip select pin. Can be any Digital pin.
		spiCS = machine.D53
		MAC   = net.HardwareAddr{0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xFF}
		MyIP  = net.IP{192, 168, 1, 5} //static setup is the only one available
	)

	// Configure writer/reader integrated circuit.
	dev := enc28j60.New(spiCS, machine.SPI0)

	err := dev.Init(MAC)
	if err != nil {
		println(err.Error())
	}
	const okHeader = "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n"
	timeout := time.Second * 1
	// Spin up HTTP server which responds with "Hello world!"
	swtch.HTTPListenAndServe(dev, MAC, MyIP, timeout, func(URL []byte) (response []byte) {
		return []byte(okHeader + "Hello world!")
	}, printNonNilErr)
}

func printNonNilErr(err error) {
	if err != nil {
		println(err.Error())
	}
}
```

With `noheap` build tag enabled the above program consumes the following memory
```
   code    data     bss |   flash     ram
  22278     765     856 |   23043    1621
```
The program should be small enough to run on the Arduino UNO as well (2k sram, 32k flash).
