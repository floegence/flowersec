package quicbase

import "testing"

func TestV4LimitsKeepPriorCapacitySeparate(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxInboundStreams = 1035 + 128 + 1
	if limits.ValidateV4() != nil {
		t.Fatal("v4 positive, ingress and maintenance capacity refused")
	}
	if limits.Validate() == nil {
		t.Fatal("v4 relaxed prior carrier bounds")
	}
	limits.MaxInboundStreams = 2049
	if limits.ValidateV4() == nil {
		t.Fatal("v4 provider cap not bounded")
	}
}
