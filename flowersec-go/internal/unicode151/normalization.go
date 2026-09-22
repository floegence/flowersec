package unicode151

import "unicode/utf8"

// NormalizationSpace returns the rune capacity required in each of the two
// caller-owned workspaces. The bound includes fully expanded decomposition.
func NormalizationSpace(inputBytes int) (int, bool) {
	if inputBytes < 0 || inputBytes > int(^uint(0)>>1)/MaxCanonicalDecomposition {
		return 0, false
	}
	return inputBytes * MaxCanonicalDecomposition, true
}

func combiningClass(cp rune) uint8 {
	lo, hi := 0, len(combiningClasses)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if combiningClasses[mid].cp < cp {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(combiningClasses) && combiningClasses[lo].cp == cp {
		return combiningClasses[lo].class
	}
	return 0
}

func compose(a, b rune) (rune, bool) {
	if a >= 0x1100 && a < 0x1100+19 && b >= 0x1161 && b < 0x1161+21 {
		return 0xac00 + ((a-0x1100)*21+b-0x1161)*28, true
	}
	if a >= 0xac00 && a < 0xac00+11172 && (a-0xac00)%28 == 0 && b > 0x11a7 && b < 0x11a7+28 {
		return a + b - 0x11a7, true
	}
	lo, hi := 0, len(canonicalCompositions)
	for lo < hi {
		mid := lo + (hi-lo)/2
		v := canonicalCompositions[mid]
		if v.a < a || v.a == a && v.b < b {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(canonicalCompositions) {
		v := canonicalCompositions[lo]
		if v.a == a && v.b == b {
			return v.result, true
		}
	}
	return 0, false
}

// Normalize writes Unicode 15.1 NFC into work, using scratch for stable linear
// counting sort of combining runs. It never grows either workspace. Callers
// keep both arrays reserved until the returned view has been consumed.
func Normalize(input []byte, work, scratch []rune) ([]rune, bool) {
	space, ok := NormalizationSpace(len(input))
	if !ok || len(work) < space || len(scratch) < space || !utf8.Valid(input) {
		return nil, false
	}
	n := 0
	for offset := 0; offset < len(input); {
		cp, size := utf8.DecodeRune(input[offset:])
		offset += size
		if !Assigned(cp) {
			return nil, false
		}
		if cp >= 0xac00 && cp < 0xac00+11172 {
			v := cp - 0xac00
			work[n] = 0x1100 + v/588
			work[n+1] = 0x1161 + (v%588)/28
			n += 2
			if v%28 != 0 {
				work[n] = 0x11a7 + v%28
				n++
			}
			continue
		}
		lo, hi := 0, len(canonicalDecompositions)
		for lo < hi {
			mid := lo + (hi-lo)/2
			if canonicalDecompositions[mid].cp < cp {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo < len(canonicalDecompositions) && canonicalDecompositions[lo].cp == cp {
			v := canonicalDecompositions[lo]
			n += copy(work[n:], v.parts[:v.count])
		} else {
			work[n] = cp
			n++
		}
	}
	for start := 0; start < n; {
		if combiningClass(work[start]) == 0 {
			start++
			continue
		}
		end := start + 1
		for end < n && combiningClass(work[end]) != 0 {
			end++
		}
		var positions [256]int
		for _, cp := range work[start:end] {
			positions[combiningClass(cp)]++
		}
		total := 0
		for i, count := range positions {
			positions[i] = total
			total += count
		}
		for _, cp := range work[start:end] {
			c := combiningClass(cp)
			scratch[positions[c]] = cp
			positions[c]++
		}
		copy(work[start:end], scratch[:end-start])
		start = end
	}
	out, starter, lastClass := 0, -1, uint8(0)
	for _, cp := range work[:n] {
		class := combiningClass(cp)
		if starter >= 0 && (lastClass == 0 || lastClass < class) {
			if composite, ok := compose(work[starter], cp); ok {
				work[starter] = composite
				continue
			}
		}
		if class == 0 {
			starter = out
		}
		work[out] = cp
		out++
		lastClass = class
	}
	return work[:out], true
}

// IsNFC validates the original bytes; it never normalizes a signed input in
// place. Invalid UTF-8 and code points outside the pinned assignment set fail.
func IsNFC(input []byte, work, scratch []rune) bool {
	normalized, ok := Normalize(input, work, scratch)
	if !ok {
		return false
	}
	offset := 0
	for _, cp := range normalized {
		if offset >= len(input) {
			return false
		}
		actual, n := utf8.DecodeRune(input[offset:])
		if cp != actual {
			return false
		}
		offset += n
	}
	return offset == len(input)
}
