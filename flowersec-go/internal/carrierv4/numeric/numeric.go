// Package numeric supplies one synchronous native TCP connection to a prepared
// numeric endpoint. Callers preadmit one connection, two overlapping native
// handles during FileConn handoff, and their platform runtime backing.
package numeric

import "errors"

var (
	ErrEndpoint = errors.New("numericv4: invalid prepared endpoint")
	ErrPlatform = errors.New("numericv4: numeric dialing requires Darwin or Linux")
)
