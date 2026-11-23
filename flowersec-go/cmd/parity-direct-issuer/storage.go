package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type directories struct {
	record, approval, invitation string
	claims                       string
}

func (dirs *directories) prepare() error {
	var roots []os.FileInfo
	var parents []os.FileInfo
	for _, role := range []*string{&dirs.approval, &dirs.invitation, &dirs.record} {
		if *role == "" {
			continue
		}
		path, err := privateDirectory(*role)
		if err != nil {
			return fmt.Errorf("prepare role directory: %w", err)
		}
		var ancestors []os.FileInfo
		for ancestor := path; ; ancestor = filepath.Dir(ancestor) {
			info, err := os.Stat(ancestor)
			if err != nil {
				return err
			}
			for _, root := range roots {
				if os.SameFile(info, root) {
					return errors.New("role directories overlap")
				}
			}
			ancestors = append(ancestors, info)
			if filepath.Dir(ancestor) == ancestor {
				break
			}
		}
		for _, parent := range parents {
			if os.SameFile(ancestors[0], parent) {
				return errors.New("role directories overlap")
			}
		}
		parents = append(parents, ancestors[1:]...)
		roots = append(roots, ancestors[0])
		*role = path
	}
	var err error
	dirs.claims, err = privateDirectory(filepath.Join(dirs.approval, ".issuer-claims"))
	return err
}

func privateDirectory(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("role paths must be real directories with mode 0700")
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func (dirs directories) reserve(name string) error {
	claim, err := os.OpenFile(filepath.Join(dirs.claims, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("channel already reserved; do not retry")
	}
	if err != nil {
		return err
	}
	if err := errors.Join(claim.Sync(), claim.Close()); err != nil {
		return err
	}
	if err := syncDirectory(dirs.claims); err != nil {
		return err
	}
	for _, dir := range []string{dirs.approval, dirs.invitation} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("channel destination exists or cannot be verified")
		}
	}
	return nil
}

func publish(dir, name string, value []byte) error {
	staged, err := os.CreateTemp(dir, ".issuer-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	if _, err := staged.Write(value); err != nil {
		staged.Close()
		return err
	}
	if err := errors.Join(staged.Sync(), staged.Close()); err != nil {
		return err
	}
	if err := os.Link(staged.Name(), filepath.Join(dir, name)); err != nil {
		return err
	}
	if err := os.Remove(staged.Name()); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
