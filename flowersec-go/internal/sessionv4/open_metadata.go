package sessionv4

import (
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
)

const openMetadataPageBytes = 256

// openMetadataArena keeps the original absolute byte positions and first-fit
// allocation. Pages change only physical backing, never logical capacity or
// fragmentation. Its caller holds admission.mu and the complete arena charge.
type openMetadataArena struct {
	capacity int
	pages    []*[openMetadataPageBytes]byte
	used     []uint64
}

func openMetadataBackingBytes(capacity int) uint64 {
	pages, words := (capacity-1)/openMetadataPageBytes+1, (capacity-1)/64+1
	return uint64(pages)*(openMetadataPageBytes+uint64(unsafe.Sizeof((*[openMetadataPageBytes]byte)(nil)))) + uint64(words)*uint64(unsafe.Sizeof(uint64(0)))
}

func newOpenMetadataArena(capacity int) (openMetadataArena, error) {
	// The original reservation includes one data byte and one occupancy byte
	// per logical position. It covers every possible page, its directory, last
	// page padding and the fixed occupancy bitmap before any page is allocated.
	if capacity <= 0 || openMetadataBackingBytes(capacity) > 2*uint64(capacity) {
		return openMetadataArena{}, cryptov4.ErrConfiguration
	}
	return openMetadataArena{capacity: capacity, pages: make([]*[openMetadataPageBytes]byte, (capacity-1)/openMetadataPageBytes+1), used: make([]uint64, (capacity-1)/64+1)}, nil
}

func (m *openMetadataArena) reserve(kind string, metadata []byte) (int, bool) {
	size, run := len(kind)+len(metadata), 0
	if size <= 0 || size > m.capacity {
		return 0, false
	}
	for at := 0; at < m.capacity; at++ {
		if m.used[at/64]&(uint64(1)<<uint(at%64)) != 0 {
			run = 0
		} else {
			run++
		}
		if run != size {
			continue
		}
		start := at + 1 - size
		for offset := start; offset <= at; offset++ {
			m.used[offset/64] |= uint64(1) << uint(offset%64)
		}
		for offset := 0; offset < size; {
			absolute := start + offset
			pageIndex, pageOffset := absolute/openMetadataPageBytes, absolute%openMetadataPageBytes
			if m.pages[pageIndex] == nil {
				m.pages[pageIndex] = new([openMetadataPageBytes]byte)
			}
			n := min(size-offset, openMetadataPageBytes-pageOffset)
			if offset < len(kind) {
				n = min(n, len(kind)-offset)
				copy(m.pages[pageIndex][pageOffset:pageOffset+n], kind[offset:offset+n])
			} else {
				copy(m.pages[pageIndex][pageOffset:pageOffset+n], metadata[offset-len(kind):offset-len(kind)+n])
			}
			offset += n
		}
		return start, true
	}
	return 0, false
}

// copyRange writes into the caller's existing admitted storage. Page views
// never escape, so releasing one range cannot invalidate another owner's view.
func (m *openMetadataArena) copyRange(dst []byte, start, end int) int {
	size := min(len(dst), end-start)
	for copied := 0; copied < size; {
		absolute := start + copied
		pageOffset := absolute % openMetadataPageBytes
		n := min(size-copied, openMetadataPageBytes-pageOffset)
		copy(dst[copied:copied+n], m.pages[absolute/openMetadataPageBytes][pageOffset:pageOffset+n])
		copied += n
	}
	return size
}

func (m *openMetadataArena) equals(start, end int, value string) bool {
	if end-start != len(value) {
		return false
	}
	for offset := range len(value) {
		absolute := start + offset
		if m.pages[absolute/openMetadataPageBytes][absolute%openMetadataPageBytes] != value[offset] {
			return false
		}
	}
	return true
}

func (m *openMetadataArena) release(start, size int) {
	end := start + size
	for at := start; at < end; at++ {
		m.pages[at/openMetadataPageBytes][at%openMetadataPageBytes] = 0
		m.used[at/64] &^= uint64(1) << uint(at%64)
	}
	if size == 0 {
		return
	}
	for pageIndex := start / openMetadataPageBytes; pageIndex <= (end-1)/openMetadataPageBytes; pageIndex++ {
		empty := true
		firstWord := pageIndex * (openMetadataPageBytes / 64)
		for _, word := range m.used[firstWord:min(firstWord+openMetadataPageBytes/64, len(m.used))] {
			empty = empty && word == 0
		}
		if empty {
			clear(m.pages[pageIndex][:])
			m.pages[pageIndex] = nil
		}
	}
}

func (m *openMetadataArena) clear() {
	for i, page := range m.pages {
		if page != nil {
			clear(page[:])
			m.pages[i] = nil
		}
	}
	clear(m.used)
}
