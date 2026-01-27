package securefile

import (
	"os"
	"path/filepath"
	"runtime"
)

// MkdirAllOwnerOnly creates dir (and parents) and enforces owner-only permissions on unix.
//
// On Windows, permission bits are not reliable; the function only ensures the directory exists.
func MkdirAllOwnerOnly(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	// MkdirAll does not tighten permissions on an existing directory.
	return os.Chmod(dir, 0o700)
}

// WriteFileAtomic writes data to filename via a temp file + rename, enforcing perm on unix.
//
// This ensures overwrite also applies the desired file mode (os.WriteFile only sets perm on create).
func WriteFileAtomic(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	base := filepath.Base(filename)

	f, err := os.CreateTemp(dir, "."+base+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()

	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()

	if runtime.GOOS != "windows" {
		if err := f.Chmod(perm); err != nil {
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// On Windows, os.Rename does not overwrite an existing destination.
	if runtime.GOOS == "windows" {
		_ = os.Remove(filename)
	}
	if err := os.Rename(tmp, filename); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		// Best-effort: keep the final path at the desired mode even if umask or FS quirks interfere.
		if err := os.Chmod(filename, perm); err != nil {
			return err
		}
	}
	ok = true
	return nil
}
