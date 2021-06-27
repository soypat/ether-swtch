package swtch

import "errors"

var (
	ErrUnknownEthProtocol = errors.New("swtch: unable to follow ethernet protocol ctl")
	ErrUnknownIPProtocol  = errors.New("swtch: unable to follow ip protocol ctl")
)

var (
	ErrBadMac           = errors.New("swtch: bad MAC address")
	ErrNotIPv4          = errors.New("swtch: expected ipv4 protocol")
	ErrNeedPseudoHeader = errors.New("swtch: need pseudo header for tcp frame")

	ErrHTTPField = errors.New("swtch: parsing http field")
)
