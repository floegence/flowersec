package weaknet

import (
	"fmt"
	"time"
)

type tokenBucket struct {
	profile   RateLimit
	tokens    int64
	last      time.Duration
	remainder int64
	started   bool
}

func newTokenBucket(profile RateLimit) tokenBucket {
	return tokenBucket{profile: profile, tokens: profile.BurstBytes}
}

func (b *tokenBucket) schedule(at time.Duration, size int) (time.Duration, bool, error) {
	if !b.profile.enabled() || size == 0 {
		return at, false, nil
	}
	if int64(size) > b.profile.BurstBytes {
		return 0, false, fmt.Errorf("%w: unit size exceeds token bucket burst", ErrInvalidProfile)
	}
	if !b.started {
		b.started = true
		b.last = at
	} else if at > b.last {
		b.refill(at - b.last)
		b.last = at
	} else {
		at = b.last
	}
	if b.tokens >= int64(size) {
		b.tokens -= int64(size)
		return at, false, nil
	}

	missing := int64(size) - b.tokens
	numerator := missing*int64(time.Second) - b.remainder
	waitNanos := (numerator + b.profile.BytesPerSecond - 1) / b.profile.BytesPerSecond
	wait := time.Duration(waitNanos)
	b.refill(wait)
	b.last += wait
	if b.tokens < int64(size) {
		return 0, false, fmt.Errorf("%w: token bucket failed to make progress", ErrInvalidProfile)
	}
	b.tokens -= int64(size)
	return b.last, true, nil
}

func (b *tokenBucket) refill(elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	numerator := elapsed.Nanoseconds()*b.profile.BytesPerSecond + b.remainder
	b.tokens += numerator / int64(time.Second)
	b.remainder = numerator % int64(time.Second)
	if b.tokens >= b.profile.BurstBytes {
		b.tokens = b.profile.BurstBytes
		b.remainder = 0
	}
}
