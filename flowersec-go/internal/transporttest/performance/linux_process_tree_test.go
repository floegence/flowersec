package performance

import "testing"

func TestParseLinuxProcStatHandlesSpacesAndParenthesesInCommand(t *testing.T) {
	record := "42 (node (capacity) worker) S 7 42 42 0 0 0 0 0 0 0 11 13 0 0 0 0 8 0 12345 0 0"
	stat, err := parseLinuxProcStatRecord(42, record)
	if err != nil {
		t.Fatal(err)
	}
	if stat.ppid != 7 || stat.pgid != 42 || stat.state != 'S' || stat.userTicks != 11 || stat.systemTicks != 13 || stat.startTicks != 12345 {
		t.Fatalf("parsed stat = %+v", stat)
	}
}

func TestParseLinuxProcStatAcceptsZeroStartTime(t *testing.T) {
	stat, err := parseLinuxProcStatRecord(2, "2 (kthreadd) S 0 0 0 0 0 0 0 0 0 11 13 0 0 0 0 8 0 0 0 0")
	if err != nil {
		t.Fatal(err)
	}
	if stat.startTicks != 0 {
		t.Fatalf("start ticks = %d, want 0", stat.startTicks)
	}
}
