package ordinalbits

import "testing"

func TestPagedLifetimeAndCleanup(t *testing.T) {
	const bound = 2097153
	s := New(bound)
	if BackingBytes(bound) != uint64(len(s))*(8+pageWords*8) {
		t.Fatal("maximum backing omitted pages or directory")
	}
	for _, page := range s {
		if page != nil {
			t.Fatal("unused ordinal allocated a page")
		}
	}
	// Cover word/page boundaries and the original million-stream lifetime.
	for _, bit := range []uint64{0, 63, 64, pageBits - 1, pageBits, 1048576, bound - 1} {
		if s.Has(bit) {
			t.Fatal("unused ordinal marked", bit)
		}
		s.Add(bit)
		s.Add(bit)
	}
	for bit := uint64(0); bit < bound; bit++ {
		expected := bit == 0 || bit == 63 || bit == 64 || bit == pageBits-1 || bit == pageBits || bit == 1048576 || bit == bound-1
		if s.Has(bit) != expected {
			t.Fatal("lifetime history changed", bit)
		}
	}
	page := s[0]
	s.Clear()
	for _, word := range page {
		if word != 0 {
			t.Fatal("cleanup retained history backing")
		}
	}
	for _, page := range s {
		if page != nil {
			t.Fatal("cleanup retained a page")
		}
	}
}
