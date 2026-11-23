//go:build !linux || (!amd64 && !arm64)

package main

import "os"

func newIssuerSync() (publicationSync, func() error, error) {
	return (*os.File).Sync, func() error { return nil }, nil
}
