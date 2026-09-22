//go:build !darwin && !linux

package numeric

import (
	"context"
	"net"
	"net/netip"
	"time"
)

func CheckPlatform(netip.AddrPort) error { return ErrPlatform }

func Connect(context.Context, netip.AddrPort, time.Time) (net.Conn, error) {
	return nil, ErrPlatform
}
