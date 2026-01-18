package timeutil

import (
	"math"
	"time"
)

// SkewSecondsCeil converts a duration to whole seconds, rounding up.
// Negative and zero values return 0.
func SkewSecondsCeil(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	secs := d / time.Second
	if d%time.Second != 0 {
		secs++
	}
	if secs <= 0 {
		return 0
	}
	return int64(secs)
}

// NormalizeSkew rounds a skew duration up to whole seconds.
func NormalizeSkew(d time.Duration) time.Duration {
	secs := SkewSecondsCeil(d)
	if secs == 0 {
		return 0
	}
	if secs > int64(math.MaxInt64)/int64(time.Second) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(secs) * time.Second
}

// AddSkewUnix adds a skew window (rounded up to whole seconds) to a Unix seconds
// timestamp and clamps to MaxInt64 on overflow.
func AddSkewUnix(unixS int64, skew time.Duration) int64 {
	secs := SkewSecondsCeil(skew)
	if secs == 0 {
		return unixS
	}
	if unixS > math.MaxInt64-secs {
		return math.MaxInt64
	}
	return unixS + secs
}
