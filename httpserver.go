package swtch

import (
	"bytes"
	"time"

	"github.com/soypat/net"
)

var (
	httpserverHTTPFrame HTTP
	httpserverEthFrame  Ethernet
	httpserverIPFrame   IPv4
	httpserverTCPFrame  TCP
	httpserverARPFrame  ARPv4
)

// HTTPListenAndServe spins up a blocking HTTP server on port 80.
//
// Not safe for multiple instantiations on same device. Concurrent use not tested.
func HTTPListenAndServe(dg Datagrammer, mac net.HardwareAddr, IPAddr net.IP, timeout time.Duration, handler func(URL []byte) (response []byte), errhandler func(error)) {
	var count uint
	var httpf *HTTP = &httpserverHTTPFrame

	// HTTP/TCP variables
	var (
		// HTTPLen variables accumulate total data sent by the client and server
		clientHTTPLen, serverHTTPLen, ACK, SEQ uint32
		response                               []byte
	)
	conn := newTCPconn(dg, &httpserverEthFrame, &httpserverIPFrame, &httpserverARPFrame, &httpserverTCPFrame, httpf, timeout, mac, IPAddr, 80)

	// declare shorthand frames
	eth := conn.Ethernet
	ipf := conn.IPv4
	tcpf := conn.TCP
	arpf := conn.ARPv4
	tcpSet := tcpf.Set()
	var err error
	var deadline time.Time

START: // START begins search for a new TCP connection.
	for {
		err = conn.Reset()
		if err != nil {
			errhandler(err)
		}
		err = conn.Decode()
		if err != nil && !IsEOF(err) {
			errhandler(err)
			continue START
		}
		if eth.EtherType() == EtherTypeARP && bytes.Equal(arpf.ProtoTarget(), IPAddr) {
			// ARP Packet control.
			_log("=======etherType ARPv4")
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
				continue START
			}
			count++

		} else if eth.EtherType() == EtherTypeIPv4 {
			// TCP Packet control
			if !bytes.Equal(ipf.Destination(), IPAddr) || !bytes.Equal(eth.Destination(), mac) || // check destination address is ours
				!tcpf.HasFlags(TCPHEADER_FLAG_SYN) { // Must be SYN packet to start TCP handshake
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
			for tcpf.Seq() != SEQ+1 || len(httpf.URL) == 0 || httpf.Method == httpUNDEFINED || tcpf.HasFlags(TCPHEADER_FLAG_SYN) || tcpf.Flags() == TCPHEADER_FLAG_ACK {

				// Get incoming ACK and skip it (len=0) and get HTTP request
				err = conn.Decode()
				if err != nil && !IsEOF(err) || time.Since(deadline) > 0 {
					errhandler(err)
					continue START
				}
				_log(strcat("[ACK] loop expecting ", u32toa(SEQ+1), " got ", u32toa(tcpf.Seq())))
			}
			_logStringer("HTTP:", httpf)

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
				tcpSet.Flags(TCPHEADER_FLAG_ACK)
				err = conn.SendResponse()
				if err != nil {
					errhandler(err)
					continue START
				}
			}

			// Send FIN|PSH|ACK with HTTP response to client
			{
				tcpf.Set().Flags(TCPHEADER_FLAG_FIN | TCPHEADER_FLAG_PSH | TCPHEADER_FLAG_ACK)
				httpf.Body = response
				err = conn.SendResponse()
				if err != nil {
					errhandler(err)
					continue START
				}
			}

			// clear current flags to prevent false positive. We seek to ACK the FIN|ACK segment.
			tcpSet.ClearFlags(TCPHEADER_FLAG_FIN)
			for tcpf.Seq() != SEQ+serverHTTPLen+2 || tcpf.Flags() != TCPHEADER_FLAG_FIN|TCPHEADER_FLAG_ACK {
				err = conn.Decode()
				if err != nil && !IsEOF(err) || time.Since(deadline) > 0 {
					errhandler(err)
					continue START
				}
				_log(strcat("[FIN] loop expecting seq ", u32toa(SEQ+serverHTTPLen+2), " got ", u32toa(tcpf.Seq()), "\n"))
			}

			tcpSet.Flags(TCPHEADER_FLAG_ACK)
			tcpSet.Ack(ACK + clientHTTPLen + 2)
			tcpSet.Seq(SEQ + serverHTTPLen + 2)
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
			}
			_logStringer("\nEnd TCP handshake with :", tcpf)
			count++
		}
	}
}
