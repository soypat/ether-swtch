package swtch

import (
	"github.com/soypat/net"

	"github.com/soypat/ether-swtch/bytealg"
)

// HTTP unmarshal http requests and marshal body data
type HTTP struct {
	// Request
	Method HTTPMethod
	// buffer HTTPBuffer
	buff [32]byte
	URL  []byte
	// Response
	Body []byte
}

type HTTPMethod uint8

const (
	httpUNDEFINED HTTPMethod = iota
	HTTPGET
	HTTPHEAD
	HTTPPOST
	HTTPPUT
	HTTPDELETE
	HTTPTRACE
	HTTPOPTIONS
	HTTPCONNECT
	HTTPPATCH
)

var spaceByte = []byte{' '}

func (h *HTTP) Decode(r Reader) (n uint16, err error) {
	n, err = r.Read(h.buff[:])
	_log(strcat("http decode: ", string(h.buff[:n])))
	if err != nil && !IsEOF(err) {
		return n, err
	}
	if n <= 6 {
		return n, ErrShortRead
	}
	idx1 := bytealg.IdxRabinKarpBytes(h.buff[:], spaceByte)
	if idx1 < 3 {
		return n, ErrHTTPField
	}
	idx2 := bytealg.IdxRabinKarpBytes(h.buff[idx1+1:], spaceByte) + idx1 + 1
	if idx2 < 5 {
		return n, ErrHTTPField
	}
	h.URL = h.buff[idx1+1 : idx2]
	_log("got url", h.URL)
	switch bytealg.String(h.buff[:3]) {
	case "GET":
		h.Method = HTTPGET
	case "POS":
		h.Method = HTTPPOST
	case "DEL":
		h.Method = HTTPDELETE
	case "PUT":
		h.Method = HTTPPUT
	}
	return n, err
}

func (h *HTTP) Encode(w Writer) (n uint16, err error) {
	_log("http:send", h.buff[:n])
	if len(h.Body) == 0 {
		return 0, nil
	}
	return w.Write(h.Body)
}

func (h *HTTP) FrameLength() uint16 {
	return uint16(len(h.Body))
}

func (h *HTTP) Reset() error {
	h.Body = nil
	return nil
}

func (h *HTTP) SetResponse(MAC net.HardwareAddr) error {
	return nil
}

func (h *HTTP) String() string {
	if h.URL == nil {
		return "undefined http request"
	}
	return strcat(h.Method.String(), " @ ", bytealg.String(h.URL))
}

func (h HTTPMethod) String() (s string) {
	switch h {
	case HTTPGET:
		s = "GET"
	case HTTPDELETE:
		s = "DELETE"
	case HTTPPOST:
		s = "POST"
	case HTTPPUT:
		s = "PUT"
	default:
		s = "?"
	}
	return s
}
