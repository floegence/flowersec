package websocket

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/carrierv4/numeric"
)

func checkDialPlatform(address netip.AddrPort) error { return numeric.CheckPlatform(address) }
func connectNumeric(ctx context.Context, address netip.AddrPort, deadline time.Time) (net.Conn, error) {
	return numeric.Connect(ctx, address, deadline)
}
