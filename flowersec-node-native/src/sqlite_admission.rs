//! Connection configuration through SQLite's public loadable-extension ABI.
//! Node retains its original database, statements, allocator and SQLite build.
//! No private Node pointer, second database connection or global API table is used.

use libsqlite3_sys::{
    SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, SQLITE_ERROR, SQLITE_LIMIT_ATTACHED, SQLITE_LIMIT_LENGTH,
    SQLITE_LIMIT_SQL_LENGTH, SQLITE_LIMIT_VARIABLE_NUMBER, SQLITE_LIMIT_WORKER_THREADS,
    SQLITE_MISUSE, SQLITE_OK, sqlite3, sqlite3_api_routines,
};
use std::ffi::{c_char, c_int};

#[napi_derive::napi(js_name = "sqliteAdmissionVersion")]
pub fn sqlite_admission_version() -> u32 {
    1
}

// SQLite calls each entry with the connection and API table from its own
// runtime. Read only the stable ABI prefix, without storing a process-global
// table that different Node workers or SQLite runtimes could overwrite.
unsafe fn checkpoint_on_close(
    database: *mut sqlite3,
    api: *const sqlite3_api_routines,
    disabled: c_int,
) -> c_int {
    if database.is_null() || api.is_null() {
        return SQLITE_MISUSE;
    }
    let Some(version) = (unsafe { (*api).libversion_number }) else {
        return SQLITE_ERROR;
    };
    // NO_CKPT_ON_CLOSE is available from SQLite 3.16.0.
    if unsafe { version() } < 3_016_000 {
        return SQLITE_ERROR;
    }
    let Some(configure) = (unsafe { (*api).db_config }) else {
        return SQLITE_ERROR;
    };
    let mut observed: c_int = -1;
    let status = unsafe {
        configure(
            database,
            SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            disabled,
            &mut observed as *mut c_int,
        )
    };
    if status != SQLITE_OK {
        status
    } else if observed != disabled {
        SQLITE_ERROR
    } else {
        SQLITE_OK
    }
}

unsafe fn inspect(
    database: *mut sqlite3,
    api: *const sqlite3_api_routines,
    maximum: c_int,
) -> c_int {
    let status = unsafe { checkpoint_on_close(database, api, 1) };
    if status != SQLITE_OK {
        return status;
    }
    let Some(limit) = (unsafe { (*api).limit }) else {
        return SQLITE_ERROR;
    };
    // Set engine limits before any header/schema/WAL access. Node's runtime
    // limit API is not available on every supported minimum Node version.
    for (kind, value) in [
        (SQLITE_LIMIT_LENGTH, maximum),
        (SQLITE_LIMIT_SQL_LENGTH, 65536),
        (SQLITE_LIMIT_VARIABLE_NUMBER, 64),
        (SQLITE_LIMIT_ATTACHED, 0),
        (SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        unsafe {
            limit(database, kind, value);
        }
        if unsafe { limit(database, kind, -1) } != value {
            return SQLITE_ERROR;
        }
    }
    SQLITE_OK
}

// The maintained worker selects a fixed profile from its admitted local row
// budget. No SQL function, stored SQL or caller-supplied executable is loaded.
macro_rules! inspection_entry {
    ($name:ident, $maximum:expr) => {
        /// # Safety
        /// Called by SQLite with its live connection and matching API table.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            database: *mut sqlite3,
            _error: *mut *mut c_char,
            api: *const sqlite3_api_routines,
        ) -> c_int {
            unsafe { inspect(database, api, $maximum) }
        }
    };
}
inspection_entry!(sqlite3_flowersec_inspect128_init, 128 << 10);
inspection_entry!(sqlite3_flowersec_inspect256_init, 256 << 10);
inspection_entry!(sqlite3_flowersec_inspect512_init, 512 << 10);
inspection_entry!(sqlite3_flowersec_inspect1024_init, 1024 << 10);
inspection_entry!(sqlite3_flowersec_inspect2048_init, 2048 << 10);

/// # Safety
/// Called by SQLite with its live connection and matching extension API table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqlite3_flowersec_admit_init(
    database: *mut sqlite3,
    _error: *mut *mut c_char,
    api: *const sqlite3_api_routines,
) -> c_int {
    unsafe { checkpoint_on_close(database, api, 0) }
}
