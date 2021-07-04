package swtch

import (
	"errors"
)

var (
	ErrShortRead          = errors.New("swtch: remaining data too short for frame")
	ErrUnknownEthProtocol = errors.New("swtch: unable to follow ethernet protocol ctl")
	ErrUnknownIPProtocol  = errors.New("swtch: unable to follow ip protocol ctl")
	// The protocol handler is available to user but was not found in Conn instance.
	ErrNoProtocol = errors.New("swtch: uninitialized or missing protocol")
)

var (
	ErrBadMac           = errors.New("swtch: bad MAC address")
	ErrNotIPv4          = errors.New("swtch: expected ipv4 protocol")
	ErrNeedPseudoHeader = errors.New("swtch: need pseudo header for tcp frame")

	ErrHTTPField = errors.New("swtch: parsing http field")
	ErrNilReader = errors.New("swtch: nil reader")
)
