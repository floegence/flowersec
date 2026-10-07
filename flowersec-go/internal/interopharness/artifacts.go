package interopharness

import (
	"os"
	"path/filepath"
)

// NewPeerReporter places owned SQLite/provider scratch outside the checkout and
// outside system temporary roots. The reporter removes its successful owned
// directory after real cleanup; no other task's resources are inspected.
func NewPeerReporter() (reporter *Reporter, err error) {
	base := os.Getenv("FLOWERSEC_TEST_ARTIFACT_DIR")
	if base == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		base = filepath.Join(cache, "flowersec-engineering")
	}
	if err = os.MkdirAll(base, 0700); err != nil {
		return nil, err
	}
	owned, err := os.MkdirTemp(base, "peer-")
	if err != nil {
		return nil, err
	}
	reporter, err = NewReporter(owned)
	if err != nil {
		_ = os.Remove(owned)
		return nil, err
	}
	// Remove after the real authority/store cleanup, which runs in reverse order.
	reporter.mu.Lock()
	reporter.cleanup = append([]*reporterCleanup{{callback: func() { reporter.ErrorIf(os.Remove(owned)) }}}, reporter.cleanup...)
	reporter.mu.Unlock()
	return reporter, nil
}
