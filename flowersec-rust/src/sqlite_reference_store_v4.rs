//! A local durable create-or-compare provider for canonical operation locators.
//! Rows contain no Start capability, Session identity or credentials.
use crate::sqlite_application_format_v4::{self as format, Kind};
use crate::{
    ApplicationInvocationContext, OperationReference, ServiceError, ServiceFailure,
    api_v4::CleanupStatus,
    environment_v4::{EnvironmentCharge, EnvironmentRoot, ResourceLimits},
    operation_reference_v4::OperationReferenceCodec,
    reference_store_v4::{OperationReferenceStore, ReferenceSaveOutcome},
};
use async_trait::async_trait;
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, limits::Limit, params};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{runtime::Handle, sync::Notify};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn database<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|_| failure(ServiceFailure::ServiceUnavailable))
}
#[derive(Clone, Debug)]
pub struct SQLiteReferenceStoreOptions {
    pub path: PathBuf,
    pub target_domain: String,
    pub max_records: u32,
    pub max_pages: u32,
    pub provider_runtime_bytes: u64,
    pub disk_overhead_bytes: u64,
}
struct ProviderState {
    opening: bool,
    busy: bool,
}
struct State {
    connection: Option<Connection>,
    runtime_charge: Option<EnvironmentCharge>,
    inode: (u64, u64),
}
pub(crate) struct ReferenceOwner {
    root: Arc<EnvironmentRoot>,
    options: SQLiteReferenceStoreOptions,
    codec: OperationReferenceCodec,
    state: Mutex<State>,
    provider: Mutex<ProviderState>,
    closed: AtomicBool,
    close_started: AtomicBool,
    close_complete: AtomicBool,
    changed: Notify,
    runtime: Handle,
    disk_charge: Mutex<Option<EnvironmentCharge>>,
}
impl fmt::Debug for ReferenceOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SQLiteOperationReferenceStore { <opaque> }")
    }
}
#[derive(Clone, Debug)]
pub struct SQLiteOperationReferenceStore(pub(crate) Arc<ReferenceOwner>);
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_owned();
    path.push(suffix);
    PathBuf::from(path)
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
impl SQLiteOperationReferenceStore {
    pub(crate) fn open(
        root: Arc<EnvironmentRoot>,
        options: SQLiteReferenceStoreOptions,
    ) -> Result<Self> {
        if !options.path.is_absolute()
            || options.path.as_os_str().len() > 4096
            || !(1..=65536).contains(&options.max_records)
            || !(16..=65536).contains(&options.max_pages)
            || options.provider_runtime_bytes < 262144
            || options.disk_overhead_bytes < 65536
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let runtime =
            Handle::try_current().map_err(|_| failure(ServiceFailure::ConfigurationCapacity))?;
        let parent = options
            .path
            .parent()
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let canonical =
            fs::canonicalize(parent).map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        if canonical != parent {
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
        let codec = OperationReferenceCodec::new(root.clone(), options.target_domain.clone())?;
        let pages = u64::from(options.max_pages);
        let disk = pages
            .checked_mul(4096 * 3 + 24)
            .and_then(|value| value.checked_add(options.disk_overhead_bytes + 65536))
            .ok_or_else(|| failure(ServiceFailure::ConfigurationCapacity))?;
        let disk_charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            disk_bytes: disk,
            items: u64::from(options.max_records) + 2,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let runtime_charge = root.reserve_environment(ResourceLimits {
            provider_bytes: options.provider_runtime_bytes,
            native_handles: 5,
            tasks: 2,
            ..ResourceLimits::default()
        })?;
        let owner = Arc::new(ReferenceOwner {
            root: root.clone(),
            options: options.clone(),
            codec,
            provider: Mutex::new(ProviderState {
                opening: true,
                busy: false,
            }),
            state: Mutex::new(State {
                connection: None,
                runtime_charge: Some(runtime_charge),
                inode: (0, 0),
            }),
            closed: AtomicBool::new(false),
            close_started: AtomicBool::new(false),
            close_complete: AtomicBool::new(false),
            changed: Notify::new(),
            runtime,
            disk_charge: Mutex::new(Some(disk_charge)),
        });
        root.register_reference_store(owner.clone())?;
        let mut opening = ReferenceOpening(Some(owner.clone()));
        // Persistent backing is registered before the first filesystem or VFS
        // effect. A failed open cannot refund bytes that still exist on disk.
        let assembled = (|| -> Result<(Connection, (u64, u64))> {
            if owner.closed.load(Ordering::Acquire) {
                return Err(failure(ServiceFailure::Closed));
            }
            let fresh = match fs::symlink_metadata(&options.path) {
                Ok(_) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let mut file = OpenOptions::new();
                    file.read(true).write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        file.mode(0o600);
                    }
                    let file = file
                        .open(&options.path)
                        .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                    file.sync_all()
                        .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
                    true
                }
                Err(_) => return Err(failure(ServiceFailure::ServiceUnavailable)),
            };
            let inode = protected(&options.path, pages * 4096)?;
            for suffix in ["-wal", "-shm", "-journal"] {
                if fresh && fs::symlink_metadata(sibling(&options.path, suffix)).is_ok() {
                    return Err(failure(ServiceFailure::ServiceUnavailable));
                }
            }
            let connection = database(Connection::open_with_flags(
                &options.path,
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            ))?;
            let prepare_connection = |connection: &Connection| -> Result<()> {
                database(connection.busy_timeout(Duration::from_millis(250)))?;
                database(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true))?;
                database(
                    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true),
                )?;
                database(connection.set_limit(Limit::SQLITE_LIMIT_LENGTH, 16384))?;
                database(connection.set_limit(Limit::SQLITE_LIMIT_SQL_LENGTH, 16384))?;
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
            let check_files = || -> Result<()> {
                if protected(&options.path, pages * 4096)? != inode {
                    return Err(Kind::Reference
                        .error(None, crate::StorageFormatMismatchReason::IdentityMismatch));
                }
                for (suffix, capacity) in [
                    ("-wal", 32 + pages * 4120),
                    ("-shm", 65536 + pages / 4096 * 32768),
                ] {
                    match fs::symlink_metadata(sibling(&options.path, suffix)) {
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Ok(_) => {
                            protected(&sibling(&options.path, suffix), capacity)?;
                        }
                        Err(_) => return Err(failure(ServiceFailure::ServiceUnavailable)),
                    }
                }
                if fs::symlink_metadata(sibling(&options.path, "-journal")).is_ok() {
                    return Err(failure(ServiceFailure::ServiceUnavailable));
                }
                Ok(())
            };
            check_files()?;
            let configure = |connection: &Connection| -> Result<()> {
                database(connection.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=1; PRAGMA locking_mode=EXCLUSIVE;"))?;
                database(connection.execute_batch(&format!("PRAGMA max_page_count={}; PRAGMA cache_size=-128; PRAGMA mmap_size=0; PRAGMA journal_size_limit={}", options.max_pages, pages * 4120 + 32)))?;
                Ok(())
            };
            if fresh {
                configure(&connection)?;
            }
            if fresh {
                database(connection.execute_batch("BEGIN IMMEDIATE; CREATE TABLE reference_manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-operation-reference-1'), domain TEXT NOT NULL, max_records INTEGER NOT NULL, max_pages INTEGER NOT NULL) STRICT, WITHOUT ROWID; CREATE TABLE operation_reference (identity BLOB PRIMARY KEY CHECK(length(identity)=32), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 4096)) STRICT, WITHOUT ROWID;"))?;
                database(connection.execute("INSERT INTO reference_manifest VALUES (1,'flowersec-operation-reference-1',?1,?2,?3)",
                params![options.target_domain, options.max_records, options.max_pages]))?;
                database(connection.execute_batch("PRAGMA user_version=1; COMMIT"))?;
            }
            let inspect_current = |connection: &Connection| {
                format::read_snapshot(connection, Kind::Reference, || {
                    format::inspect(
                        connection,
                        Kind::Reference,
                        &options.target_domain,
                        Some(options.max_records),
                        options.max_pages,
                    )?;
                    format::validate_schema(connection, Kind::Reference)?;
                    // Validate every current canonical locator before any writable configuration.
                    // The bounded header above refuses unsupported layouts without entering this reader.
                    {
                        let kind = Kind::Reference;
                        let revision = Some(kind.required());
                        let mut statement = kind.database(connection.prepare("SELECT identity,canonical FROM operation_reference ORDER BY identity LIMIT ?1"), revision)?;
                        let mut rows = kind.database(
                            statement.query([u64::from(options.max_records) + 1]),
                            revision,
                        )?;
                        let mut count = 0u32;
                        while let Some(row) = kind.database(rows.next(), revision)? {
                            count += 1;
                            if count > options.max_records {
                                return Err(kind.error(
                                    revision,
                                    crate::StorageFormatMismatchReason::Configuration,
                                ));
                            }
                            let stored_identity: Vec<u8> = kind.database(row.get(0), revision)?;
                            let canonical: Vec<u8> = kind.database(row.get(1), revision)?;
                            if stored_identity.len() != 32
                                || canonical.is_empty()
                                || canonical.len() > 4096
                            {
                                return Err(
                                    kind.error(revision, crate::StorageFormatMismatchReason::Value)
                                );
                            }
                            let reference = owner.codec.import(&canonical).map_err(|_| {
                                kind.error(revision, crate::StorageFormatMismatchReason::Value)
                            })?;
                            if identity(&reference).as_slice() != stored_identity.as_slice() {
                                return Err(
                                    kind.error(revision, crate::StorageFormatMismatchReason::Value)
                                );
                            }
                        }
                    }
                    let page_count: u64 = Kind::Reference.database(
                        connection.query_row("PRAGMA page_count", [], |row| row.get(0)),
                        Some(1),
                    )?;
                    if page_count > pages {
                        return Err(Kind::Reference
                            .error(Some(1), crate::StorageFormatMismatchReason::Configuration));
                    }
                    check_files()?;
                    Ok(())
                })
            };
            inspect_current(&connection)?;
            if !fresh {
                check_files()?;
                database(connection.execute_batch("PRAGMA query_only=OFF"))?;
                configure(&connection)?;
            }
            database(connection.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false))?;
            Ok((connection, inode))
        })();
        match assembled {
            Ok((connection, inode)) => {
                let mut provider = owner.provider.lock().expect("reference provider handoff");
                let mut state = owner.state.lock().expect("reference database");
                // Even a late connection transfers to its original owner for
                // physical cleanup. A closed constructor never publishes it.
                state.connection = Some(connection);
                state.inode = inode;
                provider.opening = false;
                opening.0.take();
                drop(state);
                drop(provider);
                owner.changed.notify_waiters();
                if owner.closed.load(Ordering::Acquire) {
                    owner.close();
                    return Err(failure(ServiceFailure::Closed));
                }
            }
            Err(error) => {
                // The local connection and all prepared statements have exited
                // before opening is cleared and the close worker can refund.
                root.diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::StoreFailures);
                drop(opening);
                return Err(error);
            }
        }
        Ok(Self(owner))
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let complete = self.0.close_complete.load(Ordering::Acquire);
        CleanupStatus {
            complete,
            cleanup_incomplete: !complete,
            pending_callbacks: u64::from(!complete),
        }
    }
    pub async fn wait_cleanup(
        &self,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<CleanupStatus> {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return Ok(status);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)) }
        }
    }
    /// Persistent disk debt is discharged only after the host has removed the
    /// original database and every journal after meeting its retention policy.
    pub fn release_removed(&self) -> Result<()> {
        if !self.0.close_complete.load(Ordering::Acquire) {
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
            .expect("reference disk backing")
            .take();
        self.0.root.release_reference_store(&self.0);
        Ok(())
    }
    pub async fn load(
        &self,
        locator: &OperationReference,
        context: ApplicationInvocationContext,
    ) -> Result<Option<OperationReference>> {
        context.check_cancellation()?;
        if locator.target_domain() != self.0.options.target_domain {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let owner = self.0.clone();
        let key = identity(locator);
        let permit = owner.admit()?;
        let bytes = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            context.check_cancellation()?;
            owner.root.sample()?;
            if owner.closed.load(Ordering::Acquire) {
                return Err(failure(ServiceFailure::Closed));
            }
            let state = owner.state.lock().expect("reference database");
            owner.files(&state)?;
            let connection = state
                .connection
                .as_ref()
                .ok_or_else(|| failure(ServiceFailure::Closed))?;
            let bytes: Option<Vec<u8>> = database(
                connection
                    .query_row(
                        "SELECT canonical FROM operation_reference WHERE identity=?1",
                        params![key.as_slice()],
                        |row| row.get(0),
                    )
                    .optional(),
            )?;
            bytes.map(|bytes| owner.codec.import(&bytes)).transpose()
        })
        .await
        .map_err(|_| failure(ServiceFailure::ServiceUnavailable))??;
        Ok(bytes)
    }
}
fn identity(reference: &OperationReference) -> [u8; 32] {
    let target = reference.target();
    let mut hash = Sha256::new();
    hash.update(b"flowersec/local/operation-reference-identity\0");
    for part in [
        reference.target_domain().as_bytes(),
        target.tenant.as_bytes(),
        target.audience.as_bytes(),
        target.namespace.as_bytes(),
        target.caller_subject.as_bytes(),
        target.caller_authority.as_slice(),
        target.operation_id.as_slice(),
    ] {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
impl ReferenceOwner {
    pub(crate) fn path(&self) -> &Path {
        &self.options.path
    }
    fn admit(self: &Arc<Self>) -> Result<ProviderPermit> {
        let mut provider = self.provider.lock().expect("reference provider admission");
        if self.closed.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        if provider.opening || provider.busy {
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        provider.busy = true;
        Ok(ProviderPermit(self.clone()))
    }
    fn files(&self, state: &State) -> Result<()> {
        let pages = u64::from(self.options.max_pages);
        if protected(&self.options.path, pages * 4096)? != state.inode {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        for (suffix, cap) in [
            ("-wal", 32 + pages * 4120),
            ("-shm", 65536 + pages / 4096 * 32768),
        ] {
            let path = sibling(&self.options.path, suffix);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    protected(&path, cap)?;
                }
                Err(_) => return Err(failure(ServiceFailure::ServiceUnavailable)),
            }
        }
        if fs::symlink_metadata(sibling(&self.options.path, "-journal")).is_ok() {
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        Ok(())
    }
    pub(crate) fn close(self: &Arc<Self>) {
        // This finite gate is distinct from the connection's I/O mutex. The
        // original constructor/permit tail re-enters it on actual exit.
        let provider = self.provider.lock().expect("reference provider close");
        self.closed.store(true, Ordering::Release);
        if provider.opening || provider.busy {
            return;
        }
        if self.close_started.swap(true, Ordering::AcqRel) {
            return;
        }
        drop(provider);
        let owner = self.clone();
        self.runtime.spawn_blocking(move || {
            let mut state = owner.state.lock().expect("reference database");
            let Some(connection) = state.connection.take() else {
                state.runtime_charge.take();
                owner.close_complete.store(true, Ordering::Release);
                owner.changed.notify_waiters();
                return;
            };
            match connection.close() {
                Ok(()) => {
                    state.runtime_charge.take();
                    owner.close_complete.store(true, Ordering::Release);
                    owner.changed.notify_waiters();
                }
                Err((connection, _)) => {
                    state.connection = Some(connection);
                    owner.close_started.store(false, Ordering::Release);
                    owner.changed.notify_waiters();
                }
            }
        });
    }
}
#[async_trait]
impl OperationReferenceStore for SQLiteOperationReferenceStore {
    fn application_bytes(&self) -> u64 {
        32768
    }
    async fn save(
        &self,
        reference: OperationReference,
        context: ApplicationInvocationContext,
    ) -> Result<ReferenceSaveOutcome> {
        context.check_cancellation()?;
        let owner = self.0.clone();
        let permit = owner.admit()?;
        let outcome = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            context.check_cancellation()?;
            owner.root.sample()?;
            if owner.closed.load(Ordering::Acquire)
                || reference.target_domain() != owner.options.target_domain
            {
                return Err(failure(ServiceFailure::Closed));
            }
            let key = identity(&reference);
            let mut bytes = Zeroizing::new(vec![0; 4096]);
            let length = owner.codec.export(&reference, &mut bytes)?;
            bytes.truncate(length);
            let mut state = owner.state.lock().expect("reference database");
            owner.files(&state)?;
            let connection = state
                .connection
                .as_mut()
                .ok_or_else(|| failure(ServiceFailure::Closed))?;
            let transaction = database(
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate),
            )?;
            let previous: Option<Vec<u8>> = database(
                transaction
                    .query_row(
                        "SELECT canonical FROM operation_reference WHERE identity=?1",
                        params![key.as_slice()],
                        |row| row.get(0),
                    )
                    .optional(),
            )?;
            if let Some(previous) = previous {
                if previous.as_slice() != bytes.as_slice() {
                    return Err(failure(ServiceFailure::OperationConflict));
                }
            } else {
                let records: u64 = database(transaction.query_row(
                    "SELECT COUNT(*) FROM operation_reference",
                    [],
                    |row| row.get(0),
                ))?;
                if records >= u64::from(owner.options.max_records) {
                    return Err(failure(ServiceFailure::ResourceExhausted));
                }
                database(transaction.execute(
                    "INSERT INTO operation_reference VALUES (?1,?2)",
                    params![key.as_slice(), bytes.as_slice()],
                ))?;
            }
            // This continuation is the sole positive persistence fact. Caller
            // cancellation after COMMIT cannot rewrite it to NotSubmitted.
            match transaction.commit() {
                Ok(()) => Ok(ReferenceSaveOutcome::Confirmed),
                Err(_) => {
                    owner.closed.store(true, Ordering::Release);
                    Ok(ReferenceSaveOutcome::Unknown)
                }
            }
        })
        .await
        .map_err(|_| failure(ServiceFailure::ServiceUnavailable))??;
        Ok(outcome)
    }
}

// Installed immediately after registry publication. Local SQLite values are
// dropped before this guard, including unwinding, so Close never mistakes an
// unfinished constructor for an absent provider.
struct ReferenceOpening(Option<Arc<ReferenceOwner>>);
impl Drop for ReferenceOpening {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner
                .provider
                .lock()
                .expect("reference opening exit")
                .opening = false;
            owner.changed.notify_waiters();
            owner.close();
        }
    }
}

struct ProviderPermit(Arc<ReferenceOwner>);
impl Drop for ProviderPermit {
    fn drop(&mut self) {
        self.0
            .provider
            .lock()
            .expect("reference provider exit")
            .busy = false;
        self.0.changed.notify_waiters();
        if self.0.closed.load(Ordering::Acquire) {
            self.0.close();
        }
    }
}
