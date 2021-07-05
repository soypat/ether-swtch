package swtch

import (
	"bytes"
	"strconv"
	"time"

	"github.com/soypat/net"
)

func HTTPListenAndServe(dg Datagrammer, mac net.HardwareAddr, IPAddr net.IP, timeout time.Duration, handler func(URL []byte) (response []byte), errhandler func(error)) {
	var count uint
	httpf := new(HTTP)
	// HTTP/TCP variables
	var (
		// HTTPLen variables accumulate total data sent by the client and server
		clientHTTPLen, serverHTTPLen, ACK, SEQ uint32
		response                               []byte
	)
	conn := NewTCPConn(dg, httpf, mac, IPAddr, 80)

	// declare shorthand frames
	eth := conn.Ethernet
	ipf := conn.IPv4
	tcpf := conn.TCP
	arpf := conn.ARPv4
	tcpSet := tcpf.Set()
	var deadline time.Time
	var err error
A:
	for {
		err = conn.Reset()
		if err != nil {
			errhandler(err)
		}
		err = conn.Decode()
		if err != nil && !IsEOF(err) {
			errhandler(err)
			continue
		}

		if eth.EtherType() == EtherTypeARP && bytes.Equal(arpf.ProtoTarget(), IPAddr) {
			// ARP Packet control.
			_log("=======etherType ARPv4")
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
				continue
			}
			count++

		} else if eth.EtherType() == EtherTypeIPv4 {
			deadline = time.Now().Add(timeout)
			// TCP Packet control
			if !bytes.Equal(ipf.Destination(), IPAddr) || !bytes.Equal(eth.Destination(), mac) || // check destination address is ours
				!tcpf.HasFlags(TCPHEADER_FLAG_SYN) { // Must be SYN packet to start TCP handshake
				continue
			}

			_log("\n=======ipv4 dst here")
			// conn takes care of replying
			err = conn.SendResponse()

			if err != nil {
				errhandler(err)
				continue A
			}
			SEQ, ACK = tcpf.Seq(), tcpf.Ack()-1

			_log("\n=======loop http decode")
			// while not the packet we are looking for keep going.
			for tcpf.Seq() != SEQ+1 || len(httpf.URL) == 0 || httpf.Method == httpUNDEFINED || tcpf.HasFlags(TCPHEADER_FLAG_SYN) || tcpf.Flags() == TCPHEADER_FLAG_ACK {
				if time.Now().After(deadline) {
					// deadline exceeded
					continue A
				}

				// Get incoming ACK and skip it (len=0) and get HTTP request
				err = conn.Decode()
				if err != nil && !IsEOF(err) {
					errhandler(err)
				}
				_log("[ACK] loop expecting " + strconv.Itoa(int(SEQ+1)) + " got " + strconv.Itoa(int(tcpf.Seq())))
			}
			_log("HTTP:" + httpf.String())

			// Send TCP ACK first and save response
			{
				response = handler(httpf.URL)
				serverHTTPLen = uint32(len(response))
				clientHTTPLen = uint32(ipf.TotalLength()) - 20 - uint32(tcpf.Offset())*4
				if clientHTTPLen <= 0 {
					_log("got a zero length HTTP packet")
					continue A
				}
				httpf.Body = nil
				tcpSet.Ack(ACK + clientHTTPLen + 1)
				tcpSet.Seq(SEQ + 1)
				tcpSet.Flags(TCPHEADER_FLAG_ACK)
				err = conn.SendResponse()
				if err != nil {
					errhandler(err)
				}
			}

			// Send FIN|PSH|ACK with HTTP response to client
			{
				tcpf.Set().Flags(TCPHEADER_FLAG_FIN | TCPHEADER_FLAG_PSH | TCPHEADER_FLAG_ACK)
				httpf.Body = response
				err = conn.SendResponse()
				if err != nil {
					errhandler(err)
				}
			}

			// clear current flags to prevent false positive. We seek to ACK the FIN|ACK segment.
			tcpSet.ClearFlags(TCPHEADER_FLAG_FIN)
			for tcpf.Seq() != SEQ+serverHTTPLen+2 || tcpf.Flags() != TCPHEADER_FLAG_FIN|TCPHEADER_FLAG_ACK {
				if time.Now().After(deadline) {
					// deadline exceeded
					continue A
				}
				err = conn.Decode()
				if err != nil && !IsEOF(err) {
					errhandler(err)
				}
				_log("[FIN] loop expecting seq " + strconv.Itoa(int(SEQ+serverHTTPLen+2)) + " got " + strconv.Itoa(int(tcpf.Seq())) + "\n")
			}

			tcpSet.Flags(TCPHEADER_FLAG_ACK)
			tcpSet.Ack(ACK + clientHTTPLen + 2)
			tcpSet.Seq(SEQ + serverHTTPLen + 2)
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
			}
			_log("\nEnd TCP handshake with :" + tcpf.String())
			count++
		}
	}
}
