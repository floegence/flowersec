package protocolv4

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
)

// Signed host text is accepted only in its canonical ASCII spelling. No
// consumer URL library is allowed to repair host, authority or Origin text.
func wireHostText(value string) error {
	var workspace wireIDNAWorkspace
	return wireHost(value, &workspace)
}

func wireHost(value string, workspace *wireIDNAWorkspace) error {
	if value == "" {
		return CBORFailure("host_wire_ascii")
	}
	for _, c := range value {
		if c <= 32 || c >= 127 || strings.ContainsRune("[]%\\/?#@", c) {
			return CBORFailure("host_syntax")
		}
	}
	if strings.Contains(value, ":") {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is6() {
			return CBORFailure("host_ipv6")
		}
		if ipv6WireText(addr) != value {
			return CBORFailure("host_noncanonical")
		}
		return nil
	}
	numeric := true
	for _, c := range value {
		numeric = numeric && (c == '.' || c >= '0' && c <= '9')
	}
	if numeric {
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.Is4() || addr.String() != value {
			return CBORFailure("host_noncanonical")
		}
		return nil
	}
	if err := wireDNS(value, workspace); err != nil {
		return err
	}
	last := value[strings.LastIndexByte(value, '.')+1:]
	base := 10
	digits := last
	if strings.HasPrefix(last, "0x") {
		base = 16
		digits = last[2:]
	}
	numeric = true
	for _, c := range digits {
		numeric = numeric && (c >= '0' && c <= '9' || base == 16 && c >= 'a' && c <= 'f')
	}
	if numeric {
		return CBORFailure("host_numeric_final_label")
	}
	return nil
}

// RFC 5952 hex-only form also preserves IPv4-mapped IPv6 addresses. netip's
// default mapped-address rendering uses dotted decimal and is not this wire form.
func ipv6WireText(addr netip.Addr) string {
	data := addr.As16()
	var words [8]uint16
	var parts [8]string
	for i := range words {
		words[i] = binary.BigEndian.Uint16(data[2*i : 2*i+2])
		parts[i] = strconv.FormatUint(uint64(words[i]), 16)
	}
	best, length := -1, 1
	for i := 0; i < 8; {
		if words[i] != 0 {
			i++
			continue
		}
		end := i + 1
		for end < 8 && words[end] == 0 {
			end++
		}
		if end-i > length {
			best, length = i, end-i
		}
		i = end
	}
	if best < 0 {
		return strings.Join(parts[:], ":")
	}
	return strings.Join(parts[:best], ":") + "::" + strings.Join(parts[best+length:], ":")
}

func (r *wireRules) originDefaultPort(scheme string) (uint64, error) {
	entry, ok := r.Fields["origin_schemes"][scheme].(map[string]any)
	if !ok {
		return 0, CBORFailure("origin_scheme_unregistered")
	}
	port, ok := ruleUint(entry["default_port"])
	if !ok {
		return 0, CBORFailure("registry_unresolved")
	}
	return port, nil
}
func (r *wireRules) originText(value string) error {
	var workspace wireIDNAWorkspace
	return r.origin(value, &workspace)
}

func (r *wireRules) origin(value string, workspace *wireIDNAWorkspace) error {
	for _, c := range value {
		if c < 0x21 || c > 0x7e {
			return CBORFailure("origin_ascii")
		}
	}
	scheme, authority, ok := strings.Cut(value, "://")
	if !ok || authority == "" {
		return CBORFailure("origin_syntax")
	}
	standard, err := r.originDefaultPort(scheme)
	if err != nil {
		return err
	}
	host, port := authority, ""
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return CBORFailure("origin_syntax")
		}
		host = authority[1:end]
		if !strings.Contains(host, ":") {
			return CBORFailure("origin_syntax")
		}
		if end+1 < len(authority) {
			if authority[end+1] != ':' {
				return CBORFailure("origin_syntax")
			}
			port = authority[end+2:]
			if port == "" {
				return CBORFailure("origin_port")
			}
		}
	} else if index := strings.IndexByte(authority, ':'); index >= 0 {
		host, port = authority[:index], authority[index+1:]
		if port == "" {
			return CBORFailure("origin_port")
		}
	}
	if err := wireHost(host, workspace); err != nil {
		return err
	}
	if port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || strconv.FormatUint(n, 10) != port {
			return CBORFailure("origin_port")
		}
		if n == standard {
			return CBORFailure("origin_default_port")
		}
	}
	return nil
}
func (r *wireRules) textFormat(format, value string, workspace *wireIDNAWorkspace) error {
	switch format {
	case "host":
		return wireHost(value, workspace)
	case "origin":
		return r.origin(value, workspace)
	case "loopback_host":
		if err := wireHost(value, workspace); err != nil {
			return err
		}
		addr, err := netip.ParseAddr(value)
		if err != nil || !(value == "::1" || addr.Is4() && addr.As4()[0] == 127) {
			return CBORFailure("host_loopback")
		}
		return nil
	}
	return CBORFailure("text_format_unresolved")
}
