package godnsbl

import "errors"

var (
	ErrDNSTimeout = errors.New("godnsbl: DNS Timeout")
	ErrInvalidIP  = errors.New("godnsbl: Invalid IP Address")
)
