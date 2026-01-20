package tunnelsharding

import "testing"

func TestPickTunnelURL_Empty(t *testing.T) {
	if got := PickTunnelURL("ch_1", nil); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestPickTunnelURL_DeterministicAndOrderIndependent(t *testing.T) {
	urls := []string{
		"wss://tunnel-a.example/ws",
		"wss://tunnel-b.example/ws",
		"wss://tunnel-c.example/ws",
	}
	got1 := PickTunnelURL("ch_1", urls)
	got2 := PickTunnelURL("ch_1", urls)
	if got1 == "" || got1 != got2 {
		t.Fatalf("expected stable non-empty pick, got1=%q got2=%q", got1, got2)
	}

	reordered := []string{
		urls[2],
		urls[0],
		urls[1],
	}
	got3 := PickTunnelURL("ch_1", reordered)
	if got3 != got1 {
		t.Fatalf("expected order-independent pick %q, got %q", got1, got3)
	}
}
