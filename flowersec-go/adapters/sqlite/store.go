// Package sqlite implements the optional Flowersec credential and lease store.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store holds private, durable state for the roles provisioned by the host.
type Store struct{ db *sql.DB }

const applicationID = 0x46533553

const schema = `
CREATE TABLE client_spends (credential TEXT PRIMARY KEY NOT NULL) STRICT;
CREATE TABLE admissions (
 credential TEXT PRIMARY KEY NOT NULL, record BLOB, lease TEXT UNIQUE,
 released INTEGER NOT NULL DEFAULT 0 CHECK(released IN (0,1)),
 CHECK(record IS NULL OR lease IS NULL), CHECK(released=0 OR lease IS NOT NULL)
) STRICT;`

// Create provisions a new private database. It never overwrites prior state.
func Create(ctx context.Context, path string) (*Store, error) {
	return open(ctx, path, true)
}

// Open requires an existing Flowersec database; missing or unknown history fails.
func Open(ctx context.Context, path string) (*Store, error) {
	return open(ctx, path, false)
}

func open(ctx context.Context, path string, create bool) (*Store, error) {
	if ctx == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("sqlite: expected a context and absolute database path")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if create {
		for _, suffix := range []string{"-journal", "-wal", "-shm"} {
			if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("sqlite: cannot verify an empty database namespace")
			}
		}
		file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("sqlite: expected a private regular database file")
	}
	fileURL := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: "mode=rw&_synchronous=EXTRA&_busy_timeout=5000&_pragma=trusted_schema(OFF)&_pragma=fullfsync(ON)"}
	db, err := sql.Open("sqlite", fileURL.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	if create {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA application_id=%d; PRAGMA user_version=1;", applicationID)+schema); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return nil, err
		}
	}
	var id, revision, durability int
	var journal string
	for _, pragma := range []struct {
		query string
		dest  any
	}{
		{"PRAGMA application_id", &id}, {"PRAGMA user_version", &revision},
		{"PRAGMA synchronous", &durability}, {"PRAGMA journal_mode", &journal},
	} {
		if err := db.QueryRowContext(ctx, pragma.query).Scan(pragma.dest); err != nil {
			return nil, err
		}
	}
	if id != applicationID || revision != 1 || durability != 3 || journal != "delete" {
		return nil, errors.New("sqlite: incompatible database format or durability settings")
	}
	ok = true
	return &Store{db: db}, nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return errors.New("sqlite: missing store")
	}
	return store.db.Close()
}
