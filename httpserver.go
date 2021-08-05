package swtch

import (
	"bytes"
	"time"

	"net"

	"github.com/soypat/ether-swtch/grams"
	"github.com/soypat/ether-swtch/lax"
	"tinygo.org/x/drivers"
)

// HTTPListenAndServe spins up a blocking HTTP server on port 80.
//
// Not safe for multiple instantiations on same device. Concurrent use not tested.
func HTTPListenAndServe(dg drivers.Datagrammer, mac net.HardwareAddr, IPAddr net.IP, timeout time.Duration, handler func(URL []byte) (response []byte), errhandler func(error)) {
	var count uint
	var err error
	var _http = HTTP{}
	var httpf = &_http
	// HTTP/TCP variables
	var (
		// HTTPLen variables accumulate total data sent by the client and server
		clientHTTPLen, serverHTTPLen, ACK, SEQ uint32
		response                               []byte
	)
	var conn TCPConn
	err = conn.Init(dg, httpf, timeout, mac, IPAddr, 80)
	if err != nil {
		panic(err.Error())
	}
	// conn := newTCPconn(dg, httpf, timeout, mac, IPAddr, 80)

	// declare shorthand frames
	eth := &conn.Ethernet
	ipf := &conn.IPv4
	tcpf := &conn.TCP
	arpf := &conn.ARPv4
	tcpSet := tcpf.Set()

	var deadline time.Time

START: // START begins search for a new TCP connection.
	for {
		err = conn.Reset()
		if err != nil {
			errhandler(err)
		}
		err = conn.Decode()
		if err != nil && !lax.IsEOF(err) {
			errhandler(err)
			continue START
		}
		if eth.EtherType() == grams.EtherTypeARP && bytes.Equal(arpf.ProtoTarget(), IPAddr) {
			// ARP Packet control.
			_log("=======etherType ARPv4")
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
				continue START
			}
			count++

		} else if eth.EtherType() == grams.EtherTypeIPv4 {
			// TCP Packet control
			if !bytes.Equal(ipf.Destination(), IPAddr) || !bytes.Equal(eth.Destination(), mac) || // check destination address is ours
				!tcpf.HasFlags(grams.TCPHEADER_FLAG_SYN) { // Must be SYN packet to start TCP handshake
				continue START
			}
			// Create deadline for TCP transaction finish
			deadline = time.Now().Add(timeout)

			_log("\n=======ipv4 dst here")
			// conn takes care of SYN response. Rest of logic is inside HTTPServer
			// TODO standarize where logic lives HTTPServer vs. tcpCtl
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
				continue START
			}

			SEQ, ACK = tcpf.Seq(), tcpf.Ack()-1

			_log("\n=======loop http decode")
			// while not the packet we are looking for keep going.
			for tcpf.Seq() != SEQ+1 || len(httpf.URL) == 0 || httpf.Method == httpUNDEFINED || tcpf.HasFlags(grams.TCPHEADER_FLAG_SYN) || tcpf.Flags() == grams.TCPHEADER_FLAG_ACK {
				// Get incoming ACK and skip it (len=0) and get HTTP request
				err = conn.Decode()
				if err != nil && !lax.IsEOF(err) || time.Since(deadline) > 0 {
					errhandler(err)
					continue START
				}
				_log(lax.Strcat("[ACK] loop expecting ", lax.U32toa(SEQ+1), " got ", lax.U32toa(tcpf.Seq())))
				spinLoopContent()
			}
			lax.LogStringer("HTTP:", httpf)

			// Send TCP ACK first and save response
			{
				response = handler(httpf.URL)
				serverHTTPLen = uint32(len(response))
				clientHTTPLen = uint32(ipf.TotalLength()) - 20 - uint32(tcpf.Offset())*4
				if clientHTTPLen <= 0 {
					_log("got a zero length HTTP packet")
					continue START
				}
				httpf.Body = nil
				tcpSet.Ack(ACK + clientHTTPLen + 1)
				tcpSet.Seq(SEQ + 1)
				tcpSet.Flags(grams.TCPHEADER_FLAG_ACK)
				err = conn.SendResponse()
				if err != nil {
					errhandler(err)
					continue START
				}
			}

			// Send FIN|PSH|ACK with HTTP response to client
			{
				tcpf.Set().Flags(grams.TCPHEADER_FLAG_FIN | grams.TCPHEADER_FLAG_PSH | grams.TCPHEADER_FLAG_ACK)
				httpf.Body = response
				err = conn.SendResponse()
				if err != nil {
					errhandler(err)
					continue START
				}
			}

			// clear current flags to prevent false positive. We seek to ACK the FIN|ACK segment.
			tcpSet.ClearFlags(grams.TCPHEADER_FLAG_FIN)
			for tcpf.Seq() != SEQ+serverHTTPLen+2 || tcpf.Flags() != grams.TCPHEADER_FLAG_FIN|grams.TCPHEADER_FLAG_ACK {
				err = conn.Decode()
				if err != nil && !lax.IsEOF(err) || time.Since(deadline) > 0 {
					errhandler(err)
					continue START
				}
				_log(lax.Strcat("[FIN] loop expecting seq ", lax.U32toa(SEQ+serverHTTPLen+2), " got ", lax.U32toa(tcpf.Seq()), "\n"))
				spinLoopContent()
			}

			tcpSet.Flags(grams.TCPHEADER_FLAG_ACK)
			tcpSet.Ack(ACK + clientHTTPLen + 2)
			tcpSet.Seq(SEQ + serverHTTPLen + 2)
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
			}
			lax.LogStringer("\nEnd TCP handshake with :", tcpf)
			count++
		}
		spinLoopContent()
	}
}

func spinLoopContent() {

}
