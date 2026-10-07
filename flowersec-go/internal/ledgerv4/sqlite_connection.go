package ledgerv4

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	"modernc.org/libc"
	"modernc.org/libc/sys/types"
	sqlite3 "modernc.org/sqlite/lib"
)

// sqliteConnection uses the pinned engine's public C API so refusal can disable
// checkpoint-on-close before the first database access. No driver-private
// connection layout is inspected. The store owns this synchronous connection
// through inspection, admission, normal work and final physical close.
type sqliteConnection struct {
	tls           *libc.TLS
	db, scratch   uintptr
	maxValueBytes uint64
}

type sqliteEngineError int32

func (e sqliteEngineError) Error() string { return fmt.Sprintf("sqlite: engine code %d", int32(e)) }
func (e sqliteEngineError) Code() int     { return int(e) }

func openSQLiteConnection(path string, limits SQLiteLimits, inspect bool) (connection *sqliteConnection, err error) {
	c := &sqliteConnection{tls: libc.NewTLS(), maxValueBytes: uint64(limits.MaxPages) * sqlitePageBytes}
	c.scratch = libc.Xcalloc(c.tls, 1, 32)
	if c.scratch == 0 {
		c.tls.Close()
		return nil, ErrCapacity
	}
	defer func() {
		if err != nil {
			if closeErr := c.Close(); closeErr != nil {
				connection = c
				err = errors.Join(err, closeErr)
			}
		}
	}()
	query := "mode=rw"
	if runtime.GOOS != "windows" {
		query += "&vfs=unix-excl"
	}
	u := url.URL{Scheme: "file", Path: path, RawQuery: query}
	// Resolve the configured parent, while keeping the database basename
	// subject to NOFOLLOW. System temporary roots may themselves be symlinks.
	directory, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	u.Path = filepath.Join(directory, filepath.Base(path))
	if len(u.Path) > 4096 {
		return nil, ErrConfiguration
	}
	name, err := libc.CString(u.String())
	if err != nil {
		return nil, err
	}
	code := sqlite3.Xsqlite3_open_v2(c.tls, name, c.scratch,
		sqlite3.SQLITE_OPEN_READWRITE|sqlite3.SQLITE_OPEN_URI|sqlite3.SQLITE_OPEN_FULLMUTEX|sqlite3.SQLITE_OPEN_NOFOLLOW, 0)
	libc.Xfree(c.tls, name)
	c.db = libc.AtomicLoadNUintptr(c.scratch, 0)
	if code != sqlite3.SQLITE_OK {
		return nil, sqliteEngineError(code)
	}
	code = sqlite3.Xsqlite3_db_config(c.tls, c.db, sqlite3.SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
		libc.VaList(c.scratch+8, int32(1), c.scratch+24))
	if code != sqlite3.SQLITE_OK {
		return nil, sqliteEngineError(code)
	}
	code = sqlite3.Xsqlite3_db_config(c.tls, c.db, sqlite3.SQLITE_DBCONFIG_DEFENSIVE,
		libc.VaList(c.scratch+8, int32(1), c.scratch+24))
	if code != sqlite3.SQLITE_OK {
		return nil, sqliteEngineError(code)
	}
	// Bound SQLite's own intermediate allocations before schema inspection;
	// row conversion limits alone run after the engine has materialized values.
	for _, limit := range [][2]int32{
		{sqlite3.SQLITE_LIMIT_LENGTH, int32(min(c.maxValueBytes, uint64(math.MaxInt32)))},
		{sqlite3.SQLITE_LIMIT_SQL_LENGTH, 65536},
		{sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 64},
		{sqlite3.SQLITE_LIMIT_ATTACHED, 0},
		{sqlite3.SQLITE_LIMIT_WORKER_THREADS, 0},
	} {
		sqlite3.Xsqlite3_limit(c.tls, c.db, limit[0], limit[1])
	}
	// Exclusive locking before the first WAL access keeps the WAL index in
	// private memory. query_only prevents recovery/schema writers; disabling
	// checkpoint-on-close also preserves a crashed database on refusal.
	settings := []string{"PRAGMA locking_mode=EXCLUSIVE", "PRAGMA busy_timeout=0", "PRAGMA trusted_schema=OFF", "PRAGMA temp_store=MEMORY", "PRAGMA cache_spill=OFF", "PRAGMA mmap_size=0"}
	if inspect {
		settings = append(settings, "PRAGMA query_only=ON")
	}
	for _, setting := range settings {
		if _, err = c.ExecContext(context.Background(), setting, nil); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Cache sizing may inspect a corrupt database header. The store applies it
// once its current transaction-group owner can project typed format refusals.
func (c *sqliteConnection) boundCache(limits SQLiteLimits) error {
	_, err := c.ExecContext(context.Background(), fmt.Sprintf("PRAGMA cache_size=%d", limits.MaxPages), nil)
	return err
}

// Enable normal close checkpointing only after the complete storage admission.
func (c *sqliteConnection) admit() error {
	code := sqlite3.Xsqlite3_db_config(c.tls, c.db, sqlite3.SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
		libc.VaList(c.scratch+8, int32(0), c.scratch+24))
	if code != sqlite3.SQLITE_OK {
		return sqliteEngineError(code)
	}
	return nil
}

func (c *sqliteConnection) Prepare(string) (driver.Stmt, error) { return nil, ErrConfiguration }
func (c *sqliteConnection) Begin() (driver.Tx, error)           { return nil, ErrConfiguration }
func (c *sqliteConnection) Close() error {
	if c.tls == nil {
		return nil
	}
	if c.db != 0 {
		if code := sqlite3.Xsqlite3_close(c.tls, c.db); code != sqlite3.SQLITE_OK {
			return sqliteEngineError(code)
		}
		c.db = 0
	}
	libc.Xfree(c.tls, c.scratch)
	c.scratch = 0
	c.tls.Close()
	c.tls = nil
	return nil
}

type sqliteRows struct {
	connection  *sqliteConnection
	statement   uintptr
	allocations []uintptr
	columns     []string
	done        bool
}

func (c *sqliteConnection) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (_ driver.Rows, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if c.db == 0 || len(query) > math.MaxInt32 || len(args) > math.MaxInt32 {
		return nil, ErrConfiguration
	}
	text, err := libc.CString(query)
	if err != nil {
		return nil, err
	}
	libc.AssignPtrUintptr(c.scratch, 0)
	libc.AssignPtrUintptr(c.scratch+8, 0)
	code := sqlite3.Xsqlite3_prepare_v2(c.tls, c.db, text, int32(len(query)), c.scratch, c.scratch+8)
	tail := ""
	if code == sqlite3.SQLITE_OK {
		tail = libc.GoString(libc.AtomicLoadNUintptr(c.scratch+8, 0))
	}
	libc.Xfree(c.tls, text)
	r := &sqliteRows{connection: c, statement: libc.AtomicLoadNUintptr(c.scratch, 0)}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	if code != sqlite3.SQLITE_OK {
		return nil, sqliteEngineError(code)
	}
	if strings.TrimSpace(tail) != "" || r.statement == 0 || int(sqlite3.Xsqlite3_bind_parameter_count(c.tls, r.statement)) != len(args) {
		return nil, ErrConfiguration
	}
	for i, arg := range args {
		if arg.Ordinal != i+1 || arg.Name != "" {
			return nil, ErrConfiguration
		}
		if err = r.bind(int32(i+1), arg.Value); err != nil {
			return nil, err
		}
	}
	count := int(sqlite3.Xsqlite3_column_count(c.tls, r.statement))
	r.columns = make([]string, count)
	for i := range r.columns {
		r.columns[i] = libc.GoString(sqlite3.Xsqlite3_column_name(c.tls, r.statement, int32(i)))
	}
	return r, nil
}

func (r *sqliteRows) bind(index int32, value driver.Value) error {
	c := r.connection
	var code int32
	switch value := value.(type) {
	case nil:
		code = sqlite3.Xsqlite3_bind_null(c.tls, r.statement, index)
	case int64:
		code = sqlite3.Xsqlite3_bind_int64(c.tls, r.statement, index, value)
	case string:
		if len(value) > math.MaxInt32 || uint64(len(value)) > c.maxValueBytes {
			return ErrCapacity
		}
		p, err := libc.CString(value)
		if err != nil {
			return err
		}
		r.allocations = append(r.allocations, p)
		code = sqlite3.Xsqlite3_bind_text(c.tls, r.statement, index, p, int32(len(value)), 0)
	case []byte:
		if value == nil {
			code = sqlite3.Xsqlite3_bind_null(c.tls, r.statement, index)
		} else if len(value) == 0 {
			code = sqlite3.Xsqlite3_bind_zeroblob(c.tls, r.statement, index, 0)
		} else {
			if len(value) > math.MaxInt32 || uint64(len(value)) > c.maxValueBytes {
				return ErrCapacity
			}
			p := libc.Xmalloc(c.tls, types.Size_t(len(value)))
			if p == 0 {
				return ErrCapacity
			}
			copy(libc.GoBytes(p, len(value)), value)
			r.allocations = append(r.allocations, p)
			code = sqlite3.Xsqlite3_bind_blob(c.tls, r.statement, index, p, int32(len(value)), 0)
		}
	default:
		return ErrConfiguration
	}
	if code != sqlite3.SQLITE_OK {
		return sqliteEngineError(code)
	}
	return nil
}

func (r *sqliteRows) Columns() []string { return r.columns }
func (r *sqliteRows) Close() error {
	if r.statement == 0 {
		return nil
	}
	c := r.connection
	code := sqlite3.Xsqlite3_finalize(c.tls, r.statement)
	r.statement = 0
	for _, allocation := range r.allocations {
		libc.Xfree(c.tls, allocation)
	}
	r.allocations = nil
	if code != sqlite3.SQLITE_OK {
		return sqliteEngineError(code)
	}
	return nil
}
func (r *sqliteRows) Next(values []driver.Value) error {
	if r.statement == 0 || r.done {
		return io.EOF
	}
	if len(values) != len(r.columns) {
		return ErrConfiguration
	}
	c := r.connection
	code := sqlite3.Xsqlite3_step(c.tls, r.statement)
	if code == sqlite3.SQLITE_DONE {
		r.done = true
		return io.EOF
	}
	if code != sqlite3.SQLITE_ROW {
		r.done = true
		return sqliteEngineError(code)
	}
	for i := range values {
		column := int32(i)
		switch sqlite3.Xsqlite3_column_type(c.tls, r.statement, column) {
		case sqlite3.SQLITE_NULL:
			values[i] = nil
		case sqlite3.SQLITE_INTEGER:
			values[i] = sqlite3.Xsqlite3_column_int64(c.tls, r.statement, column)
		case sqlite3.SQLITE_FLOAT:
			values[i] = sqlite3.Xsqlite3_column_double(c.tls, r.statement, column)
		case sqlite3.SQLITE_TEXT, sqlite3.SQLITE_BLOB:
			text := sqlite3.Xsqlite3_column_type(c.tls, r.statement, column) == sqlite3.SQLITE_TEXT
			var p uintptr
			if text {
				p = sqlite3.Xsqlite3_column_text(c.tls, r.statement, column)
			} else {
				p = sqlite3.Xsqlite3_column_blob(c.tls, r.statement, column)
			}
			size := int(sqlite3.Xsqlite3_column_bytes(c.tls, r.statement, column))
			if size < 0 || uint64(size) > c.maxValueBytes {
				return ErrStorageFormat
			}
			if size != 0 && p == 0 {
				return ErrCapacity
			}
			value := make([]byte, size)
			copy(value, libc.GoBytes(p, size))
			if text {
				values[i] = string(value)
			} else {
				values[i] = value
			}
		default:
			return ErrStorageFormat
		}
	}
	return nil
}
func (c *sqliteConnection) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (_ driver.Result, err error) {
	rows, err := c.QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	values := make([]driver.Value, len(rows.Columns()))
	for {
		if err = rows.Next(values); err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return driver.RowsAffected(sqlite3.Xsqlite3_changes64(c.tls, c.db)), nil
}
