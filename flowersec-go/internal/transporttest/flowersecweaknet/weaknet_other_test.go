//go:build !linux

package flowersecweaknet

import "testing"

func TestPrivilegedFlowersecWeaknet(t *testing.T) {
	t.Skip("privileged Flowersec weak-network diagnostics require Linux")
}
