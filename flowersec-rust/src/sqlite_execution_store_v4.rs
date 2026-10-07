//! Bounded SQLite backing for the original Environment execution history.
//! Transactions precede dispatch and publication; uncertain commits seal access.
use crate::sqlite_application_format_v4::{self as format, Kind};
use crate::{
    api_v4::CleanupStatus,
    environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceLimits},
    execution_history::{ExecutionServiceOptions, ExecutionState, Key, Record, State},
    service_contract::{ServiceError, ServiceFailure, ServiceShape},
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, limits::Limit, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn database<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|_| failure(ServiceFailure::ServiceUnavailable))
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SQLiteExecutionStoreOptions {
    pub path: PathBuf,
    pub max_pages: u32,
    pub provider_runtime_bytes: u64,
    pub disk_overhead_bytes: u64,
}
struct StoreState {
    connection: Option<Connection>,
    inode: Option<(u64, u64)>,
    failed: bool,
    closed: bool,
}
pub(crate) struct ExecutionStoreOwner {
    root: Arc<EnvironmentRoot>,
    options: SQLiteExecutionStoreOptions,
    domain: ExecutionServiceOptions,
    state: Mutex<StoreState>,
    runtime_charge: Mutex<Option<EnvironmentCharge>>,
    disk_charge: Mutex<Option<EnvironmentCharge>>,
}
impl fmt::Debug for ExecutionStoreOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SQLiteExecutionStore { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct SQLiteExecutionStore(pub(crate) Arc<ExecutionStoreOwner>);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    request: [u8; 32],
    contract: [u8; 32],
    cutoff: u64,
    history_until: u64,
    accepted_ms: u64,
    deadline_ms: u64,
    run_started_ms: Option<u64>,
    retention: u64,
    limit: u32,
    shape: ServiceShape,
    state: ExecutionState,
    cancel_mode: bool,
    cancel_requested: bool,
    active: bool,
    dispatched: bool,
    metadata_finished: bool,
    error: Option<ServiceFailure>,
    result_until: Option<u64>,
    result_bytes: u32,
    result_digest: [u8; 32],
    application_error: Option<u32>,
    retained_checkpoint: Option<crate::checkpoint_v4::RetainedCheckpoint>,
    stream_progress: Option<crate::execution_history::ExecutionStreamProgress>,
    resume_request: Option<Vec<u8>>,
}
impl StoredRecord {
    fn capture(record: &Record) -> Self {
        Self {
            request: record.request,
            contract: record.contract,
            cutoff: record.cutoff,
            history_until: record.history_until,
            accepted_ms: record.accepted_ms,
            deadline_ms: record.deadline_ms,
            run_started_ms: record.run_started_ms,
            retention: record.retention,
            limit: record.limit,
            shape: record.shape,
            state: record.state,
            cancel_mode: record.cancel_mode,
            cancel_requested: record.cancel_requested,
            active: record.active,
            dispatched: record.dispatched,
            metadata_finished: record.metadata_finished,
            error: record.error,
            result_until: record.result_until,
            result_bytes: record.result_bytes,
            result_digest: record.result_digest,
            application_error: record.application_error,
            retained_checkpoint: record.retained_checkpoint.clone(),
            stream_progress: record.stream_progress.clone(),
            resume_request: record.resume_request.clone(),
        }
    }
    fn restore(
        self,
        key: &Key,
        payload: Option<Vec<u8>>,
        options: &ExecutionServiceOptions,
    ) -> Result<Record> {
        if key.authority == [0; 32]
            || !options.caller_authorities.contains(&key.authority)
            || !crate::execution_history::id(&key.subject)
            || key.operation == [0; 32]
            || self.request == [0; 32]
            || self.contract == [0; 32]
            || self.cutoff
                != u64::from_be_bytes(
                    key.operation[..8]
                        .try_into()
                        .map_err(|_| failure(ServiceFailure::Protocol))?,
                )
            || self.history_until <= self.cutoff
            || self.deadline_ms <= self.accepted_ms
            || self.limit > 1 << 20
            || self
                .run_started_ms
                .is_some_and(|start| start < self.accepted_ms || start >= self.deadline_ms)
            || self.dispatched != self.run_started_ms.is_some()
            || self.result_bytes > self.limit && self.shape == ServiceShape::Unary
            || payload
                .as_ref()
                .is_some_and(|payload| payload.len() > self.limit as usize)
            || self.result_until.is_some()
                && (self.retention == 0
                    || self.shape != ServiceShape::Unary
                    || !self.dispatched
                    || self.error.is_some()
                    || self.metadata_finished
                    || !matches!(
                        self.state,
                        ExecutionState::Completed | ExecutionState::Failed
                    )
                    || self.state == ExecutionState::Failed && self.application_error.is_none())
            || self.application_error == Some(0)
            || self.retained_checkpoint.as_ref().is_some_and(|retained| {
                retained.generation == 0
                    || retained.issues == 0
                    || retained.issues > 1024
                    || retained.checkpoint.len() > 4232
                    || retained.token.len() > 4980
                    || retained.expires_at_ms <= retained.last_issue_ms
                    || retained.expires_at_ms > self.history_until
                    || crate::ApplicationCheckpoint::capture(&retained.checkpoint).is_err()
                    || retained.consumed != retained.consumption.is_some()
                    || retained.reissuance.as_ref().is_some_and(|receipt| {
                        receipt.previous_token_digest == [0; 32]
                            || receipt.issuing_operation == [0; 32]
                            || receipt.issuing_request == [0; 32]
                            || receipt.issuing_operation == key.operation
                            || receipt.requested_lifetime_ms == 0
                    })
                    || retained.consumption.as_ref().is_some_and(|consumption| {
                        consumption.exchange_operation == [0; 32]
                            || consumption.exchange_request == [0; 32]
                            || consumption.exchange_operation == key.operation
                            || retained.generation.checked_add(1) != Some(consumption.generation)
                            || consumption.target.validate().is_err()
                    })
            })
            || payload.as_ref().is_some_and(|_payload| {
                self.result_until.is_none()
                    || self.shape != ServiceShape::Unary
                    || self.retention == 0
            })
            || payload.as_ref().is_some_and(|payload| {
                self.result_until.is_some()
                    && (payload.len() != self.result_bytes as usize
                        || sha2::Sha256::digest(payload).as_slice() != self.result_digest)
            })
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        if let Some(encoded) = &self.resume_request {
            crate::checkpoint_v4::ApplicationResumeRequest::capture(encoded)?;
            if self.shape != ServiceShape::Unary
                || self.retention == 0
                || self.retained_checkpoint.is_some()
            {
                return Err(failure(ServiceFailure::ContractMismatch));
            }
            if let Some(payload) = &payload {
                let result = crate::ApplicationResumeResult::capture(payload)?;
                if result.status() == crate::ApplicationResumeStatus::Accepted {
                    let progress = result
                        .progress()
                        .ok_or_else(|| failure(ServiceFailure::ContractMismatch))?;
                    let request = crate::checkpoint_v4::ApplicationResumeRequest::capture(encoded)?;
                    if progress.checkpoint != request.expected
                        || request.generation.checked_add(1) != Some(progress.generation)
                    {
                        return Err(failure(ServiceFailure::ContractMismatch));
                    }
                }
            }
        }
        if (self.shape == ServiceShape::ServerStreaming) != self.stream_progress.is_some() {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        if let Some(progress) = &self.stream_progress {
            progress.validate(
                key,
                self.request,
                self.contract,
                self.deadline_ms,
                self.limit,
            )?;
        }
        // A persisted running claim survives restart as an uncertain fact. It
        // grants no new application entry and never restores a running task.
        let interrupted = self.active && !self.metadata_finished && self.result_until.is_none();
        Ok(Record {
            request: self.request,
            contract: self.contract,
            cutoff: self.cutoff,
            history_until: self.history_until,
            accepted_ms: self.accepted_ms,
            deadline_ms: self.deadline_ms,
            run_started_ms: self.run_started_ms,
            retention: self.retention,
            limit: self.limit,
            shape: self.shape,
            state: if interrupted {
                if self.dispatched {
                    ExecutionState::Unknown
                } else {
                    ExecutionState::Failed
                }
            } else {
                self.state
            },
            cancel_mode: self.cancel_mode,
            cancel_requested: self.cancel_requested,
            active: false,
            dispatched: self.dispatched,
            metadata_finished: self.metadata_finished,
            error: if interrupted {
                Some(ServiceFailure::ServiceUnavailable)
            } else {
                self.error
            },
            result: payload.map(Zeroizing::new),
            result_until: self.result_until,
            result_bytes: self.result_bytes,
            result_digest: self.result_digest,
            application_error: self.application_error,
            retained_checkpoint: self.retained_checkpoint,
            stream_progress: self.stream_progress,
            resume_request: self.resume_request,
            holders: 0,
            changed: Arc::new(Notify::new()),
            cancellation: CancellationToken::new(),
        })
    }
}
use sha2::Digest;
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}
fn protected(path: &Path, capacity: u64) -> Result<(u64, u64)> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
    if !metadata.is_file() || metadata.len() > capacity {
        return Err(failure(ServiceFailure::ServiceUnavailable));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        Ok((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        Err(failure(ServiceFailure::ConfigurationCapacity))
    }
}
impl SQLiteExecutionStore {
    pub(crate) fn prepare(
        root: Arc<EnvironmentRoot>,
        domain: ExecutionServiceOptions,
        options: SQLiteExecutionStoreOptions,
    ) -> Result<Self> {
        if !options.path.is_absolute()
            || options.path.as_os_str().len() > 4096
            || !(16..=65536).contains(&options.max_pages)
            || options.provider_runtime_bytes < 262144
            || options.disk_overhead_bytes < 65536
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let parent = options
            .path
            .parent()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        if fs::canonicalize(parent).map_err(|_| failure(ServiceFailure::ServiceUnavailable))?
            != parent
        {
            return Err(failure(ServiceFailure::PermissionDenied));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if fs::metadata(parent)
                .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?
                .mode()
                & 0o022
                != 0
            {
                return Err(failure(ServiceFailure::PermissionDenied));
            }
        }
        let pages = u64::from(options.max_pages);
        let disk_bytes = pages
            .checked_mul(4096 * 3 + 24)
            .and_then(|bytes| bytes.checked_add(options.disk_overhead_bytes + 65536))
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let disk = root.reserve_environment(ResourceLimits {
            disk_bytes,
            sdk_bytes: 16384,
            items: u64::from(domain.max_records) + 3,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let runtime = root.reserve_environment(ResourceLimits {
            provider_bytes: options.provider_runtime_bytes,
            native_handles: 5,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let store = Self(Arc::new(ExecutionStoreOwner {
            root: root.clone(),
            options,
            domain,
            state: Mutex::new(StoreState {
                connection: None,
                inode: None,
                failed: false,
                closed: false,
            }),
            runtime_charge: Mutex::new(Some(runtime)),
            disk_charge: Mutex::new(Some(disk)),
        }));
        root.register_execution_store(store.0.clone())?;
        Ok(store)
    }
    pub fn options(&self) -> &SQLiteExecutionStoreOptions {
        &self.0.options
    }
    #[cfg(test)]
    pub(crate) fn with_test_connection<R>(&self, inspect: impl FnOnce(&Connection) -> R) -> R {
        let state = self.0.state.lock().expect("execution database");
        inspect(state.connection.as_ref().expect("open execution database"))
    }
    pub(crate) fn initialize(&self, state: &mut State) -> Result<()> {
        let assembled = self.0.open_and_load(state);
        if assembled.is_err() {
            self.0
                .root
                .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::StoreFailures);
            self.0.state.lock().expect("execution database").failed = true;
            self.close();
        }
        assembled
    }
    pub(crate) fn configure_recovery(
        &self,
        configuration: &crate::checkpoint_v4::RecoveryConfiguration,
        retained: bool,
    ) -> Result<()> {
        let encoded = serde_json::to_vec(configuration)
            .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
        if encoded.len() > 4096 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        self.0.transaction(|connection| {
            let original: Option<Vec<u8>> = database(
                connection
                    .query_row(
                        "SELECT configuration FROM execution_recovery WHERE id=1",
                        [],
                        |row| row.get(0),
                    )
                    .optional(),
            )?;
            match original {
                Some(original) if original != encoded => {
                    Err(failure(ServiceFailure::ContractMismatch))
                }
                Some(_) => Ok(()),
                None if retained => Err(failure(ServiceFailure::ContractMismatch)),
                None => {
                    database(connection.execute(
                        "INSERT INTO execution_recovery VALUES(1,?1)",
                        [encoded.as_slice()],
                    ))?;
                    Ok(())
                }
            }
        })
    }
    pub(crate) fn persist(&self, key: &Key, record: &Record) -> Result<()> {
        self.0
            .transaction(|connection| put(connection, key, record))
    }
    pub(crate) fn persist_pair(
        &self,
        original: &Key,
        original_record: &Record,
        exchange: &Key,
        exchange_record: &Record,
    ) -> Result<()> {
        self.0.transaction(|connection| {
            put_pair(
                connection,
                original,
                original_record,
                exchange,
                exchange_record,
            )
        })
    }
    pub(crate) fn collect(&self, authority: [u8; 32], floor: u64, key: &Key) -> Result<()> {
        self.0.transaction(|connection| {
            database(connection.execute(
                "UPDATE execution_floor SET cutoff=?2 WHERE authority=?1 AND cutoff<=?2",
                params![authority.as_slice(), floor.to_be_bytes().as_slice()],
            ))?;
            database(connection.execute(
                "DELETE FROM execution_record WHERE authority=?1 AND subject=?2 AND operation=?3",
                params![
                    key.authority.as_slice(),
                    key.subject,
                    key.operation.as_slice()
                ],
            ))?;
            Ok(())
        })
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let state = self.0.state.lock().expect("execution database");
        let complete = state.closed && state.connection.is_none();
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: u64::from(!complete),
        }
    }
    /// The host removes retained database files after its retention policy. Disk
    /// ownership is released only after all original files are actually absent.
    pub fn release_removed(&self) -> Result<()> {
        if !self.cleanup_status().complete {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            match fs::symlink_metadata(sibling(&self.0.options.path, suffix)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(failure(ServiceFailure::ServiceUnavailable)),
            }
        }
        self.0
            .disk_charge
            .lock()
            .expect("execution disk charge")
            .take();
        self.0.root.release_execution_store(&self.0);
        Ok(())
    }
}
fn put(connection: &Connection, key: &Key, record: &Record) -> Result<()> {
    let metadata = Zeroizing::new(
        serde_json::to_vec(&StoredRecord::capture(record))
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
    );
    if metadata.len() > 65536 {
        return Err(failure(ServiceFailure::ResourceExhausted));
    }
    // An allocated result buffer reserves future capacity. Only an original
    // completed result with its retention anchor is a durable result body.
    let payload = record
        .result
        .as_ref()
        .filter(|_| record.result_until.is_some())
        .map(|payload| payload.as_slice());
    database(connection.execute("INSERT INTO execution_record(authority,subject,operation,metadata,result) VALUES (?1,?2,?3,?4,?5) ON CONFLICT(authority,subject,operation) DO UPDATE SET metadata=excluded.metadata,result=excluded.result",
        params![key.authority.as_slice(), key.subject, key.operation.as_slice(), metadata.as_slice(), payload]))?;
    Ok(())
}
fn put_pair(
    connection: &Connection,
    original: &Key,
    original_record: &Record,
    exchange: &Key,
    exchange_record: &Record,
) -> Result<()> {
    if original == exchange {
        return Err(failure(ServiceFailure::OperationConflict));
    }
    put(connection, original, original_record)?;
    put(connection, exchange, exchange_record)
}
impl ExecutionStoreOwner {
    pub(crate) fn path(&self) -> &Path {
        &self.options.path
    }
    fn files(&self, state: &StoreState) -> Result<()> {
        let pages = u64::from(self.options.max_pages);
        if Some(protected(&self.options.path, pages * 4096)?) != state.inode {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        for (suffix, capacity) in [
            ("-wal", 32 + pages * 4120),
            ("-shm", 65536 + pages / 4096 * 32768),
        ] {
            let path = sibling(&self.options.path, suffix);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    protected(&path, capacity)?;
                }
                Err(_) => return Err(failure(ServiceFailure::ServiceUnavailable)),
            }
        }
        if fs::symlink_metadata(sibling(&self.options.path, "-journal")).is_ok() {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        Ok(())
    }
    fn transaction(&self, operation: impl FnOnce(&Connection) -> Result<()>) -> Result<()> {
        let mut state = self.state.lock().expect("execution database");
        if state.closed || state.failed {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        let result = (|| {
            self.files(&state)?;
            let connection = state
                .connection
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::ServiceUnavailable))?;
            database(connection.execute_batch("BEGIN IMMEDIATE"))?;
            if let Err(error) = operation(connection) {
                let _ = connection.execute_batch("ROLLBACK");
                return Err(error);
            }
            database(connection.execute_batch("COMMIT"))?;
            self.files(&state)
        })();
        if result.is_err() {
            state.failed = true;
        }
        result
    }
    fn open_and_load(&self, history: &mut State) -> Result<()> {
        let mut state = self.state.lock().expect("execution database");
        if state.closed || state.connection.is_some() {
            return Err(failure(ServiceFailure::Closed));
        }
        let fresh = match fs::symlink_metadata(&self.options.path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let file = options
                    .open(&self.options.path)
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                file.sync_all()
                    .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                true
            }
            Err(_) => return Err(failure(ServiceFailure::ServiceUnavailable)),
        };
        let pages = u64::from(self.options.max_pages);
        state.inode = Some(protected(&self.options.path, pages * 4096)?);
        for suffix in ["-wal", "-shm", "-journal"] {
            if fresh && fs::symlink_metadata(sibling(&self.options.path, suffix)).is_ok() {
                return Err(failure(ServiceFailure::ServiceUnavailable));
            }
        }
        let connection = database(Connection::open_with_flags(
            &self.options.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ))?;
        let prepare_connection = |connection: &Connection| -> Result<()> {
            database(connection.busy_timeout(std::time::Duration::from_millis(250)))?;
            database(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))?;
            database(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true))?;
            database(connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 1_114_624))?;
            database(connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 8192))?;
            database(connection.set_limit(Limit::SQLITE_LIMIT_COLUMN, 16))?;
            database(connection.set_limit(Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 8))?;
            database(connection.set_limit(Limit::SQLITE_LIMIT_ATTACHED, 0))?;
            // Set the private WAL index before any pragma that may read schema.
            database(connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE"))?;
            if !fresh {
                database(connection.execute_batch("PRAGMA query_only=ON"))?;
            }
            database(connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA cache_size=-128; PRAGMA mmap_size=0; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF"))?;
            Ok(())
        };
        prepare_connection(&connection)?;
        let configure = |connection: &Connection| -> Result<()> {
            database(connection.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=1; PRAGMA locking_mode=EXCLUSIVE; PRAGMA mmap_size=0; PRAGMA cache_size=-128"))?;
            database(connection.execute_batch(&format!(
                "PRAGMA max_page_count={}; PRAGMA journal_size_limit={}",
                self.options.max_pages,
                pages * 4120 + 32
            )))?;
            Ok(())
        };
        if fresh {
            configure(&connection)?;
        }
        let manifest = serde_json::to_string(&self.domain)
            .map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
        if fresh {
            database(connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE execution_manifest(id INTEGER PRIMARY KEY CHECK(id=1),format TEXT NOT NULL CHECK(format='flowersec-execution-2'),domain TEXT NOT NULL,max_pages INTEGER NOT NULL) STRICT, WITHOUT ROWID; CREATE TABLE execution_recovery(id INTEGER PRIMARY KEY CHECK(id=1),configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 4096)) STRICT, WITHOUT ROWID; CREATE TABLE execution_floor(authority BLOB PRIMARY KEY CHECK(length(authority)=32),cutoff BLOB NOT NULL CHECK(length(cutoff)=8)) STRICT, WITHOUT ROWID; CREATE TABLE execution_record(authority BLOB NOT NULL CHECK(length(authority)=32),subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 128),operation BLOB NOT NULL CHECK(length(operation)=32),metadata BLOB NOT NULL CHECK(length(metadata) BETWEEN 1 AND 65536),result BLOB CHECK(result IS NULL OR length(result)<=1048576),PRIMARY KEY(authority,subject,operation)) STRICT, WITHOUT ROWID;"))?;
            database(connection.execute(
                "INSERT INTO execution_manifest VALUES(1,'flowersec-execution-2',?1,?2)",
                params![manifest, self.options.max_pages],
            ))?;
            for authority in &self.domain.caller_authorities {
                database(connection.execute(
                    "INSERT INTO execution_floor VALUES(?1,?2)",
                    params![authority.as_slice(), 0u64.to_be_bytes().as_slice()],
                ))?;
            }
            database(connection.execute_batch("PRAGMA user_version=2; COMMIT"))?;
        }
        let inspect_current = |connection: &Connection| {
            format::read_snapshot(connection, Kind::Execution, || {
                format::inspect(
                    connection,
                    Kind::Execution,
                    &manifest,
                    None,
                    self.options.max_pages,
                )?;
                format::validate_schema(connection, Kind::Execution)?;
                fn read_database<T>(value: rusqlite::Result<T>) -> Result<T> {
                    Kind::Execution.database(value, Some(2))
                }
                let mut floors = BTreeMap::new();
                {
                    let mut statement = read_database(connection.prepare(
                        "SELECT authority,cutoff FROM execution_floor ORDER BY authority LIMIT 17",
                    ))?;
                    let rows = read_database(statement.query_map([], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    }))?;
                    for row in rows {
                        let (authority, cutoff) = read_database(row)?;
                        let authority: [u8; 32] = authority.try_into().map_err(|_| {
                            Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value)
                        })?;
                        let cutoff = u64::from_be_bytes(cutoff.try_into().map_err(|_| {
                            Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value)
                        })?);
                        if !self.domain.caller_authorities.contains(&authority) {
                            return Err(Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value));
                        }
                        floors.insert(authority, cutoff);
                    }
                }
                if floors.len() != self.domain.caller_authorities.len() {
                    return Err(
                        Kind::Execution.error(Some(2), crate::StorageFormatMismatchReason::Value)
                    );
                }
                let mut records = BTreeMap::new();
                let mut result_capacity = 0u64;
                {
                    let mut statement = read_database(connection.prepare("SELECT authority,subject,operation,metadata,result FROM execution_record ORDER BY authority,subject,operation LIMIT ?1"))?;
                    let rows = read_database(statement.query_map(
                        [u64::from(self.domain.max_records) + 1],
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                                row.get::<_, Vec<u8>>(3)?,
                                row.get::<_, Option<Vec<u8>>>(4)?,
                            ))
                        },
                    ))?;
                    for row in rows {
                        let (authority, subject, operation, metadata, payload) =
                            read_database(row)?;
                        if records.len() >= self.domain.max_records as usize
                            || metadata.len() > 65536
                        {
                            return Err(Kind::Execution.error(
                                Some(2),
                                crate::StorageFormatMismatchReason::Configuration,
                            ));
                        }
                        let key = Key {
                            authority: authority.try_into().map_err(|_| {
                                Kind::Execution
                                    .error(Some(2), crate::StorageFormatMismatchReason::Value)
                            })?,
                            subject,
                            operation: operation.try_into().map_err(|_| {
                                Kind::Execution
                                    .error(Some(2), crate::StorageFormatMismatchReason::Value)
                            })?,
                        };
                        let stored: StoredRecord =
                            serde_json::from_slice(&metadata).map_err(|_| {
                                Kind::Execution
                                    .error(Some(2), crate::StorageFormatMismatchReason::Value)
                            })?;
                        let record = stored.restore(&key, payload, &self.domain).map_err(|_| {
                            Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value)
                        })?;
                        if record.result.is_some() {
                            result_capacity = result_capacity
                                .checked_add(u64::from(record.limit))
                                .ok_or_else(|| {
                                    Kind::Execution.error(
                                        Some(2),
                                        crate::StorageFormatMismatchReason::Configuration,
                                    )
                                })?;
                        }
                        if result_capacity > self.domain.result_bytes {
                            return Err(Kind::Execution.error(
                                Some(2),
                                crate::StorageFormatMismatchReason::Configuration,
                            ));
                        }
                        records.insert(key, record);
                    }
                }
                // The recovery row is part of this transaction group even before a
                // recovery service is attached; malformed state must refuse read-only.
                {
                    let mut statement = read_database(
                        connection
                            .prepare("SELECT id,configuration FROM execution_recovery LIMIT 2"),
                    )?;
                    let mut rows = read_database(statement.query([]))?;
                    if let Some(row) = read_database(rows.next())? {
                        let id: u32 = read_database(row.get(0))?;
                        let bytes: Vec<u8> = read_database(row.get(1))?;
                        if id != 1
                            || bytes.is_empty()
                            || bytes.len() > 4096
                            || read_database(rows.next())?.is_some()
                        {
                            return Err(Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value));
                        }
                        let configuration: crate::checkpoint_v4::RecoveryConfiguration =
                            serde_json::from_slice(&bytes).map_err(|_| {
                                Kind::Execution
                                    .error(Some(2), crate::StorageFormatMismatchReason::Value)
                            })?;
                        configuration.policy.validate().map_err(|_| {
                            Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value)
                        })?;
                        if configuration.key_id == [0; 16] {
                            return Err(Kind::Execution
                                .error(Some(2), crate::StorageFormatMismatchReason::Value));
                        }
                    }
                }
                let page_count: u64 =
                    read_database(connection.query_row("PRAGMA page_count", [], |row| row.get(0)))?;
                if page_count > pages {
                    return Err(Kind::Execution
                        .error(Some(2), crate::StorageFormatMismatchReason::Configuration));
                }
                self.files(&state)?;
                Ok((floors, records, result_capacity))
            })
        };
        let (floors, records, result_capacity) = inspect_current(&connection)?;
        if !fresh {
            self.files(&state)?;
            database(connection.execute_batch("PRAGMA query_only=OFF"))?;
            configure(&connection)?;
        }
        // Restart flush is one original transaction before any new admission.
        database(connection.execute_batch("BEGIN IMMEDIATE"))?;
        for (key, record) in &records {
            if let Err(error) = put(&connection, key, record) {
                let _ = connection.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        database(connection.execute_batch("COMMIT"))?;
        history.records = records;
        history.floors = floors;
        history.active = 0;
        history.result_capacity = result_capacity;
        database(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false))?;
        state.connection = Some(connection);
        self.files(&state)
    }
    pub(crate) fn close(&self) {
        let mut state = self.state.lock().expect("execution database");
        state.closed = true;
        if let Some(connection) = state.connection.take()
            && let Err((connection, _error)) = connection.close()
        {
            state.failed = true;
            state.connection = Some(connection);
            return;
        }
        self.runtime_charge
            .lock()
            .expect("execution database runtime charge")
            .take();
    }
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn fixture() -> (ExecutionServiceOptions, Key, Record) {
        let domain = ExecutionServiceOptions {
            tenant: "tenant".into(),
            audience: "service".into(),
            namespace: "example/files".into(),
            caller_authorities: vec![[1; 32]],
            max_records: 2,
            max_active: 1,
            result_bytes: 32,
        };
        let mut operation = [2; 32];
        operation[..8].copy_from_slice(&2000u64.to_be_bytes());
        let key = Key {
            authority: [1; 32],
            subject: "client".into(),
            operation,
        };
        let record = Record {
            request: [3; 32],
            contract: [4; 32],
            cutoff: 2000,
            history_until: 10000,
            accepted_ms: 1000,
            deadline_ms: 3000,
            run_started_ms: None,
            retention: 1000,
            limit: 16,
            shape: ServiceShape::Unary,
            state: ExecutionState::Accepted,
            cancel_mode: true,
            cancel_requested: false,
            active: true,
            dispatched: false,
            metadata_finished: false,
            error: None,
            result: Some(Zeroizing::new(Vec::with_capacity(16))),
            result_until: None,
            result_bytes: 0,
            result_digest: [0; 32],
            application_error: None,
            retained_checkpoint: None,
            stream_progress: None,
            resume_request: None,
            holders: 1,
            changed: Arc::new(Notify::new()),
            cancellation: CancellationToken::new(),
        };
        (domain, key, record)
    }
    fn round_trip(key: &Key, record: &Record) -> (StoredRecord, Option<Vec<u8>>) {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE execution_record(authority BLOB,subject TEXT,operation BLOB,metadata BLOB,result BLOB,PRIMARY KEY(authority,subject,operation))").unwrap();
        put(&connection, key, record).unwrap();
        let (metadata, payload): (Vec<u8>, Option<Vec<u8>>) = connection
            .query_row("SELECT metadata,result FROM execution_record", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        (serde_json::from_slice(&metadata).unwrap(), payload)
    }
    #[test]
    fn unfinished_result_capacity_reopens_as_unknown_without_a_result_body() {
        let (domain, key, mut original) = fixture();
        for dispatched in [false, true] {
            original.dispatched = dispatched;
            original.run_started_ms = dispatched.then_some(1000);
            original.state = if dispatched {
                ExecutionState::Executing
            } else {
                ExecutionState::Accepted
            };
            let (stored, payload) = round_trip(&key, &original);
            assert!(payload.is_none());
            let reopened = stored.restore(&key, payload, &domain).unwrap();
            assert!(!reopened.active);
            assert!(reopened.result.is_none());
            assert_eq!(
                reopened.state,
                if dispatched {
                    ExecutionState::Unknown
                } else {
                    ExecutionState::Failed
                }
            );
            assert_eq!(reopened.error, Some(ServiceFailure::ServiceUnavailable));
        }
    }
    fn streaming_record(key: &Key, record: &mut Record) {
        use crate::rpc_wire_v4::{ApplicationHeader, HeaderScalar};
        let mut fields = [None; 11];
        fields[1] = Some(HeaderScalar::Bytes(key.operation));
        fields[2] = Some(HeaderScalar::Uint(7));
        fields[3] = Some(HeaderScalar::Uint(1));
        fields[4] = Some(HeaderScalar::Bytes(record.request));
        fields[5] = Some(HeaderScalar::Uint(record.deadline_ms));
        fields[6] = Some(HeaderScalar::Bytes(record.contract));
        fields[7] = Some(HeaderScalar::Uint(0));
        fields[8] = Some(HeaderScalar::Uint(u64::from(record.limit)));
        let header = ApplicationHeader::create("execution_stream_request", fields).unwrap();
        let mut request_header = vec![0; 512];
        let length = header.encode(&mut request_header).unwrap();
        request_header.truncate(length);
        record.shape = ServiceShape::ServerStreaming;
        record.retention = 0;
        record.result = None;
        record.dispatched = true;
        record.run_started_ms = Some(1100);
        record.state = ExecutionState::Executing;
        record.stream_progress = Some(crate::execution_history::ExecutionStreamProgress {
            request_header,
            max_items: 3,
            max_bytes: 32,
            duration_ms: 1000,
            items: 2,
            bytes: 13,
        });
    }
    #[test]
    fn interrupted_stream_reopens_with_original_response_binding_origin_and_counters() {
        let (domain, key, mut original) = fixture();
        streaming_record(&key, &mut original);
        let original_header = original
            .stream_progress
            .as_ref()
            .unwrap()
            .request_header
            .clone();
        let (stored, payload) = round_trip(&key, &original);
        assert!(payload.is_none());
        let reopened = stored.restore(&key, payload, &domain).unwrap();
        assert_eq!(reopened.state, ExecutionState::Unknown);
        assert_eq!(reopened.run_started_ms, Some(1100));
        let progress = reopened.stream_progress.unwrap();
        assert_eq!(progress.request_header, original_header);
        assert_eq!(
            (
                progress.items,
                progress.bytes,
                progress.max_items,
                progress.max_bytes
            ),
            (2, 13, 3, 32)
        );
        assert_eq!(progress.duration_ms, 1000);
    }
    #[test]
    fn reopening_rejects_stream_budget_or_original_response_binding_corruption() {
        let (domain, key, mut original) = fixture();
        streaming_record(&key, &mut original);
        for mutation in 0..3 {
            let (mut stored, payload) = round_trip(&key, &original);
            match mutation {
                0 => stored.stream_progress.as_mut().unwrap().items = 4,
                1 => stored.stream_progress.as_mut().unwrap().bytes = 33,
                _ => stored.request = [9; 32],
            }
            assert!(stored.restore(&key, payload, &domain).is_err());
        }
    }
    #[test]
    fn empty_retained_application_error_remains_an_actual_body_after_reopen() {
        let (domain, key, mut original) = fixture();
        original.dispatched = true;
        original.run_started_ms = Some(1000);
        original.active = false;
        original.state = ExecutionState::Failed;
        original.application_error = Some(7);
        original.result_until = Some(4000);
        original.result_digest = Sha256::digest([]).into();
        let (stored, payload) = round_trip(&key, &original);
        assert_eq!(payload, Some(Vec::new()));
        let reopened = stored.restore(&key, payload, &domain).unwrap();
        assert_eq!(reopened.state, ExecutionState::Failed);
        assert_eq!(reopened.application_error, Some(7));
        assert_eq!(
            reopened.result.as_deref().map(|body| body.as_slice()),
            Some(&[][..])
        );
    }
    #[test]
    fn failed_second_record_rolls_back_the_original_checkpoint_consumption_transaction() {
        let (_, key, original) = fixture();
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE execution_record(authority BLOB,subject TEXT,operation BLOB,metadata BLOB,result BLOB,PRIMARY KEY(authority,subject,operation))").unwrap();
        put(&connection, &key, &original).unwrap();
        let before: Vec<u8> = connection
            .query_row("SELECT metadata FROM execution_record", [], |row| {
                row.get(0)
            })
            .unwrap();
        let (_, mut exchange_key, mut exchange) = fixture();
        exchange_key.operation[31] ^= 1;
        // Exceed the bounded metadata row on the second write, after the first
        // original row has already been updated inside the same transaction.
        exchange.resume_request = Some(vec![255; 65537]);
        let (_, _, mut consumed) = fixture();
        consumed.dispatched = true;
        consumed.run_started_ms = Some(1100);
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert_eq!(
            put_pair(&connection, &key, &consumed, &exchange_key, &exchange)
                .unwrap_err()
                .0,
            ServiceFailure::ResourceExhausted
        );
        connection.execute_batch("ROLLBACK").unwrap();
        let after: Vec<u8> = connection
            .query_row("SELECT metadata FROM execution_record", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(after, before);
        let rows: u64 = connection
            .query_row("SELECT COUNT(*) FROM execution_record", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1);
    }
    #[test]
    fn original_claim_and_recovery_confirmation_commit_as_one_sqlite_transaction() {
        let (domain, key, mut original) = fixture();
        original.dispatched = true;
        original.run_started_ms = Some(1100);
        let (_, mut exchange_key, mut exchange) = fixture();
        exchange_key.operation[31] ^= 1;
        exchange.request = [9; 32];
        exchange.dispatched = true;
        exchange.run_started_ms = Some(1800);
        exchange.active = false;
        let checkpoint = crate::ApplicationCheckpoint::new("cursor".into(), vec![7]).unwrap();
        let signing = crate::ServiceCheckpointSigningKey::new(
            crate::CheckpointTokenProtection::HmacSha256,
            [5; 16],
            [6; 32],
        )
        .unwrap();
        let target = crate::ExecutionTarget {
            tenant: domain.tenant.clone(),
            audience: domain.audience.clone(),
            namespace: domain.namespace.clone(),
            caller_subject: key.subject.clone(),
            caller_authority: key.authority,
            operation_id: key.operation,
            request_digest: original.request,
            contract_digest: original.contract,
        };
        let token_bytes = signing
            .sign(&crate::checkpoint_v4::claims(&target, &checkpoint, 9, 1500, 5000).unwrap())
            .unwrap();
        let token = crate::ApplicationCheckpointToken::verify(
            &token_bytes,
            &signing.verification_key().unwrap(),
        )
        .unwrap();
        let stream = crate::checkpoint_v4::ResumeTargetBinding {
            context: [8; 32],
            stream: 3,
        };
        exchange.resume_request = Some(
            crate::checkpoint_v4::ApplicationResumeRequest::prepare(&token, stream.clone())
                .unwrap()
                .encoded()
                .unwrap(),
        );
        original.retained_checkpoint = Some(crate::checkpoint_v4::RetainedCheckpoint {
            generation: 9,
            issues: 1,
            last_issue_ms: 1500,
            checkpoint: checkpoint.encoded(),
            token: token_bytes,
            expires_at_ms: 5000,
            consumed: true,
            consumption: Some(crate::checkpoint_v4::CheckpointConsumption {
                exchange_operation: exchange_key.operation,
                exchange_request: exchange.request,
                generation: 10,
                target: stream.clone(),
                callback_entered: false,
            }),
            reissuance: None,
        });
        let confirmation = crate::ApplicationResumeResult::accepted(checkpoint, 10)
            .unwrap()
            .encoded()
            .unwrap();
        exchange.limit = 128;
        exchange.result_bytes = confirmation.len() as u32;
        exchange.result_digest = Sha256::digest(&confirmation).into();
        exchange.result = Some(Zeroizing::new(confirmation.clone()));
        exchange.result_until = Some(4000);
        exchange.state = ExecutionState::Completed;
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE execution_record(authority BLOB,subject TEXT,operation BLOB,metadata BLOB,result BLOB,PRIMARY KEY(authority,subject,operation)); BEGIN IMMEDIATE").unwrap();
        put_pair(&connection, &key, &original, &exchange_key, &exchange).unwrap();
        connection.execute_batch("COMMIT").unwrap();
        let rows: u64 = connection
            .query_row("SELECT COUNT(*) FROM execution_record", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 2);
        let stored_confirmation: Vec<u8> = connection
            .query_row(
                "SELECT result FROM execution_record WHERE operation=?1",
                [exchange_key.operation.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_confirmation, confirmation);
        let stored: Vec<u8> = connection
            .query_row(
                "SELECT metadata FROM execution_record WHERE operation=?1",
                [key.operation.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let claim: StoredRecord = serde_json::from_slice(&stored).unwrap();
        assert!(claim.dispatched);
        assert_eq!(claim.run_started_ms, Some(1100));
        let reopened = claim.restore(&key, None, &domain).unwrap();
        let consumed = reopened.retained_checkpoint.unwrap();
        assert!(consumed.consumed);
        let binding = consumed.consumption.unwrap();
        assert_eq!(binding.generation, 10);
        assert_eq!(binding.target, stream);
        assert_eq!(binding.exchange_operation, exchange_key.operation);
        assert_eq!(binding.exchange_request, exchange.request);
        let stored_exchange: Vec<u8> = connection
            .query_row(
                "SELECT metadata FROM execution_record WHERE operation=?1",
                [exchange_key.operation.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        let outer: StoredRecord = serde_json::from_slice(&stored_exchange).unwrap();
        let outer = outer
            .restore(&exchange_key, Some(stored_confirmation), &domain)
            .unwrap();
        assert_eq!(outer.state, ExecutionState::Completed);
        assert!(outer.resume_request.is_some());
    }
    #[test]
    fn a_result_body_cannot_convert_an_unfinished_record_into_a_completed_fact() {
        let (domain, key, mut original) = fixture();
        original.result_until = Some(4000);
        original.result_digest = Sha256::digest([]).into();
        let stored = StoredRecord::capture(&original);
        match stored.restore(&key, Some(Vec::new()), &domain) {
            Err(error) => assert_eq!(error.0, ServiceFailure::ContractMismatch),
            Ok(_) => panic!("an unfinished record cannot carry a retained result"),
        }
    }
}
