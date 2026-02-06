package cmdutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// UsageError marks an error as a usage/config error (exit=2 for user-facing CLIs).
type UsageError struct {
	Msg string
}

func (e *UsageError) Error() string { return e.Msg }

// IsUsage reports whether err is a UsageError (directly or wrapped).
func IsUsage(err error) bool {
	var ue *UsageError
	return errors.As(err, &ue)
}

// RefuseOverwrite returns a UsageError when path already exists and overwrite is false.
//
// If os.Stat returns an error other than fs.ErrNotExist, it is returned as-is (runtime error).
func RefuseOverwrite(path string, overwrite bool) error {
	if path == "" || overwrite {
		return nil
	}
	_, err := os.Stat(path)
	if err == nil {
		return &UsageError{Msg: fmt.Sprintf("refusing to overwrite existing file: %s (use --overwrite)", path)}
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
