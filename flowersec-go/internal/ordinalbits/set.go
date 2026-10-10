// Package ordinalbits stores a finite lifetime bitmap in prepaid pages.
// Its caller serializes access and owns the complete maximum backing charge;
// allocating a page never admits another bit or increases that bound.
package ordinalbits

const pageWords = 512
const pageBits = pageWords * 64

type Set []*[pageWords]uint64

// BackingBytes includes the directory and every possible complete page.
// Callers validate the ordinal bound before constructing or indexing a Set.
func BackingBytes(bits uint64) uint64 {
	pages := bits / pageBits
	if bits%pageBits != 0 {
		pages++
	}
	return pages * (8 + pageWords*8)
}

func New(bits uint64) Set {
	pages := bits / pageBits
	if bits%pageBits != 0 {
		pages++
	}
	return make(Set, int(pages))
}

func (s Set) Has(bit uint64) bool {
	page := s[bit/pageBits]
	return page != nil && page[(bit%pageBits)/64]&(uint64(1)<<(bit%64)) != 0
}

func (s Set) Add(bit uint64) {
	index := bit / pageBits
	if s[index] == nil {
		s[index] = new([pageWords]uint64)
	}
	s[index][(bit%pageBits)/64] |= uint64(1) << (bit % 64)
}

func (s Set) Clear() {
	for i, page := range s {
		if page != nil {
			clear(page[:])
			s[i] = nil
		}
	}
}
