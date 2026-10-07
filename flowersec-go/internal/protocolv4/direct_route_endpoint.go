package protocolv4

import "bytes"

// SameDirectRouteEndpoint compares every registered direct route field except
// the TLS policy. It allows a listener owner to install independent complete
// policies for the same physical endpoint; it grants no signed route authority.
func (d *Document) SameDirectRouteEndpoint(other *Document) bool {
	if d == nil || other == nil || d.schema != "Route" || other.schema != "Route" {
		return false
	}
	left, right := d.Root(), other.Root()
	lp, lok := left.Named("Route", "path_kind").Uint()
	rp, rok := right.Named("Route", "path_kind").Uint()
	if !lok || !rok || lp != 0 || rp != 0 {
		return false
	}
	registry, err := runtimeSchema()
	if err != nil {
		return false
	}
	for name := range registry.Maps["Route"].byName {
		if name != "direct_leg" && !bytes.Equal(left.Named("Route", name).Encoded(), right.Named("Route", name).Encoded()) {
			return false
		}
	}
	left, right = left.Named("Route", "direct_leg"), right.Named("Route", "direct_leg")
	for name := range registry.Maps["Leg"].byName {
		if name != "tls_policy" && !bytes.Equal(left.Named("Leg", name).Encoded(), right.Named("Leg", name).Encoded()) {
			return false
		}
	}
	return true
}
