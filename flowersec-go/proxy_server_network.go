package flowersec

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const proxyMaxResolvedAddresses = 64

// One immutable policy controls both HTTP and WebSocket socket creation. Numeric
// upstreams are pinned automatically; names require independently supplied ranges.
// The standard resolver's internal allocations remain part of the native runtime
// allowance, not a claim that this result limit bounds the DNS implementation.
type proxyNetworkPolicy struct {
	host     string
	port     string
	numeric  netip.Addr
	prefixes []netip.Prefix
	resolver *net.Resolver
}

func compileProxyNetworkPolicy(host, port string, ranges []string) (*proxyNetworkPolicy, error) {
	policy := &proxyNetworkPolicy{host: host, port: port, resolver: &net.Resolver{PreferGo: true}}
	if len(ranges) > proxyMaxResolvedAddresses {
		return nil, ErrInvalidProxyServer
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return nil, ErrInvalidProxyServer
		}
		policy.numeric = address.Unmap()
	} else if !validProxyDNSName(host) || len(ranges) == 0 {
		return nil, ErrInvalidProxyServer
	}
	for _, raw := range ranges {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			address, addressErr := netip.ParseAddr(raw)
			if addressErr != nil || address.Zone() != "" {
				return nil, ErrInvalidProxyServer
			}
			prefix = netip.PrefixFrom(address, address.BitLen())
		}
		if prefix != prefix.Masked() {
			return nil, ErrInvalidProxyServer
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, ErrInvalidProxyServer
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		policy.prefixes = append(policy.prefixes, prefix)
	}
	if policy.numeric.IsValid() {
		if len(policy.prefixes) != 0 && !policy.allows(policy.numeric) {
			return nil, ErrInvalidProxyServer
		}
		// Explicit ranges never widen a numeric authority to another address.
		policy.prefixes = []netip.Prefix{netip.PrefixFrom(policy.numeric, policy.numeric.BitLen())}
	}
	return policy, nil
}

func validProxyDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
		// Reject historical inet_aton spellings, including octal/hex components.
		digits, base := label, "0123456789"
		if strings.HasPrefix(digits, "0x") {
			digits, base = digits[2:], "0123456789abcdef"
		}
		if digits == "" || strings.Trim(digits, base) != "" {
			allNumeric = false
		}
	}
	return !allNumeric
}

func (policy *proxyNetworkPolicy) allows(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
		return false
	}
	address = address.Unmap()
	for _, prefix := range policy.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func (policy *proxyNetworkPolicy) resolve(ctx context.Context) ([]netip.Addr, error) {
	if policy.numeric.IsValid() {
		return []netip.Addr{policy.numeric}, nil
	}
	addresses, err := policy.resolver.LookupNetIP(ctx, "ip", policy.host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 || len(addresses) > proxyMaxResolvedAddresses {
		return nil, ErrInvalidProxyServer
	}
	// Validate the complete answer before a socket may be created. A mixed
	// allowed/forbidden answer is not an invitation to choose its allowed part.
	for index, address := range addresses {
		if !policy.allows(address) {
			return nil, ErrInvalidProxyServer
		}
		addresses[index] = address.Unmap()
	}
	return addresses, nil
}

func (policy *proxyNetworkPolicy) dialContext(ctx context.Context, network, authority string) (net.Conn, error) {
	if network != "tcp" || authority != net.JoinHostPort(policy.host, policy.port) {
		return nil, ErrInvalidProxyServer
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := policy.resolve(ctx)
	if err != nil {
		return nil, err
	}
	var lastErr error
	// These are connection preparation attempts, never HTTP request retries.
	// All candidates have already passed the same immutable network policy.
	for _, address := range addresses[:min(3, len(addresses))] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), policy.port))
		if err != nil {
			lastErr = err
			continue
		}
		peer, ok := connection.RemoteAddr().(*net.TCPAddr)
		if !ok || peer.Zone != "" || peer.AddrPort().Addr().Unmap() != address ||
			strconv.Itoa(peer.Port) != policy.port || !policy.allows(peer.AddrPort().Addr()) || ctx.Err() != nil {
			_ = connection.Close()
			return nil, ErrInvalidProxyServer
		}
		return connection, nil
	}
	return nil, lastErr
}
