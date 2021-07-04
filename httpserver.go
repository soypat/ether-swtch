package swtch

import (
	"bytes"

	"github.com/soypat/net"
)

func HTTPListenAndServe(dg Datagrammer, mac net.HardwareAddr, IPAddr net.IP, handler func(URL []byte) (response []byte), errhandler func(error)) (err error) {
	var count uint
	httpf := new(HTTP)
	// HTTP/TCP variables
	var (
		httpLen, nextseq uint32
		response         []byte
	)
	conn := NewTCPConn(dg, httpf, mac)

	// declare shorthand frames
	eth := conn.Ethernet
	ipf := conn.IPv4
	tcpf := conn.TCP
	arpf := conn.ARPv4
	tcpSet := tcpf.Set()
A:
	for {
		tcpSet.Flags(0) // clear flags
		err := conn.Decode()
		if err != nil && !IsEOF(err) {
			errhandler(err)
			continue
		}

		if eth.EtherType() == EtherTypeARP && bytes.Equal(arpf.ProtoTarget(), IPAddr) {
			// ARP Packet control.
			_log("=======etherType ARPv4")
			err = conn.SendResponse()
			if err != nil && !IsEOF(err) {
				errhandler(err)
				continue
			}
			count++

		} else if eth.EtherType() == EtherTypeIPv4 {
			// TCP Packet control
			if !bytes.Equal(ipf.Destination(), IPAddr) || !bytes.Equal(eth.Destination(), mac) || // check destination address is ours
				!tcpf.HasFlags(TCPHEADER_FLAG_SYN) || (err != nil && !IsEOF(err)) { // must have no non-EOF error. Must be SYN packet to start TCP handshake
				continue
			}
			_log("\n=======ipv4 dst here")
			// conn takes care of replying
			err = conn.SendResponse()
			if err != nil {
				errhandler(err)
			}

			loopsDone := 0
			_log("\n=======loop http decode")
			conn.Decode()
			// while not the packet we are looking for keep going.
			for tcpf.Seq() != tcpf.LastSeq+1 || len(httpf.URL) == 0 || tcpf.HasFlags(TCPHEADER_FLAG_SYN) {
				// Get incoming ACK and skip it (len=0) and get HTTP request

				loopsDone++
				if loopsDone > 4 {
					_log("=======loop > 4")
					continue A
				}
				err = conn.Decode()
				if err != nil && !IsEOF(err) {
					errhandler(err)
				}
			}
			_log("HTTP:" + httpf.String())

			// Send TCP ACK first and save response
			{
				response = handler(httpf.URL)
				httpLen = uint32(ipf.TotalLength()) - 20 - uint32(tcpf.Offset())*4
				if httpLen <= 0 {
					panic("zero or negative calculated httplength")
				}
				ack := conn.TCP.Ack() + httpLen
				tcpSet.Ack(ack)
				tcpSet.Flags(TCPHEADER_FLAG_ACK)
				err = conn.SendResponse()
				if err != nil && !IsEOF(err) {
					errhandler(err)
				}
			}

			// Send FIN|PSH|ACK with HTTP response to client
			{
				tcpf.Set().Flags(TCPHEADER_FLAG_FIN | TCPHEADER_FLAG_PSH | TCPHEADER_FLAG_ACK)
				httpf.Body = response
				// calculate next sequence number expected based on response sent
				nextseq = tcpf.Seq() + httpLen + 1
				err = conn.SendResponse()
				if err != nil && !IsEOF(err) {
					errhandler(err)
				}
			}

			// clear current flags to prevent false positive
			tcpSet.ClearFlags(TCPHEADER_FLAG_FIN)
			conn.Decode()
			for (tcpf.Seq() != nextseq && !tcpf.HasFlags(TCPHEADER_FLAG_FIN)) || tcpf.HasFlags(TCPHEADER_FLAG_SYN) {
				loopsDone++
				if loopsDone > 4 {
					continue A
				}
				err = conn.Decode()
				if err != nil && !IsEOF(err) {
					errhandler(err)
				}
			}

			err = conn.SendResponse()
			if err != nil && !IsEOF(err) {
				errhandler(err)
			}
			count++
		}
	}

	return err
}
