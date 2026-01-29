package proxy

import (
	"io"
	"time"
)

const errorWriteTimeout = 1 * time.Second

func withWriteDeadline(w io.Writer, d time.Duration, fn func()) {
	if d <= 0 {
		fn()
		return
	}
	dl, ok := w.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		fn()
		return
	}
	_ = dl.SetWriteDeadline(time.Now().Add(d))
	defer func() { _ = dl.SetWriteDeadline(time.Time{}) }()
	fn()
}
