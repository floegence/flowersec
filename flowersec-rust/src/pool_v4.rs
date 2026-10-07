//! Local preauthorized-pool consumption. Only the original successful SQLite
//! COMMIT continuation may proceed; a stored row never grants activation.
use crate::{
    codec_v4::{self as codec, ActivationSource},
    environment_v4::{
        EnvironmentCharge, EnvironmentError, EnvironmentRoot, ResourceAccount, ResourceCharge,
        ResourceLimits,
    },
    namespace_v4::verifier::credential::CredentialAdmission,
};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, limits::Limit, params};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const PAGE: u64 = 4096;
const RETENTION: u64 = 604_800_000;
const MANIFEST: &str = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-rust-pool'), revision INTEGER NOT NULL CHECK(revision=3), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, spend_rows INTEGER NOT NULL CHECK(spend_rows>=0), winner_rows INTEGER NOT NULL CHECK(winner_rows>=0), admission_rows INTEGER NOT NULL CHECK(admission_rows>=0)) STRICT, WITHOUT ROWID";
#[path = "admission_v4.rs"]
pub(crate) mod admission;
#[path = "parent_winner_v4.rs"]
pub(crate) mod parent;
#[path = "pool_storage_records_v4.rs"]
mod records;
#[path = "relay_ledger_v4.rs"]
pub(crate) mod relay;
#[path = "pool_top_up_v4.rs"]
pub(crate) mod top_up;
const SPEND: &str = "CREATE TABLE spend (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), source INTEGER NOT NULL CHECK(source=1), state INTEGER NOT NULL CHECK(state=1), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576)) STRICT, WITHOUT ROWID";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolStoreFailure {
    Configuration,
    StorageUnavailable,
    StorageFormat,
    HistoryUnknown,
    Fenced,
    SpendConflict,
    AdmissionConflict,
    RelayPublicationConflict,
    RelayClaimConflict,
    RelayClaimUnknown,
    WinnerConflict,
    SpentUnknown,
    Capacity,
    OwnerUnavailable,
    Closed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolWriteState {
    NotSubmitted,
    Committed,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StorageFormatTransactionGroup {
    Pool,
    Relay,
    ExecutionHistory,
    OperationReference,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StorageWireFormat {
    FlowersecV4RustPool,
    FlowersecV4RustRelay,
    FlowersecExecution2,
    FlowersecOperationReference1,
    Other,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StorageFormatMismatchReason {
    BackendConfiguration,
    MissingManifest,
    WireFormat,
    Revision,
    IdentityMismatch,
    RevisionConflict,
    OlderRevision,
    NewerRevision,
    Schema,
    Configuration,
    Value,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum StorageFormatConversion {
    Never,
    ExactOnly,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageFormatIncompatibility {
    pub transaction_group: StorageFormatTransactionGroup,
    pub observed_wire: Option<StorageWireFormat>,
    pub required_wire: StorageWireFormat,
    pub observed_revision: Option<u32>,
    pub required_revision: u32,
    pub reason: StorageFormatMismatchReason,
    pub conversion: StorageFormatConversion,
}
impl StorageFormatIncompatibility {
    pub(crate) fn new(
        group: StorageFormatTransactionGroup,
        wire: StorageWireFormat,
        required: u32,
        observed: Option<u32>,
        reason: StorageFormatMismatchReason,
    ) -> Self {
        Self {
            transaction_group: group,
            observed_wire: observed.map(|_| wire),
            required_wire: wire,
            observed_revision: observed,
            required_revision: required,
            reason,
            conversion: StorageFormatConversion::Never,
        }
    }
    pub const fn code(&self) -> &'static str {
        "storage_format_incompatible"
    }
    pub const fn wire_profile(&self) -> &'static str {
        "flowersec-v4-transport-security"
    }
    pub const fn exact_conversion_available(&self) -> bool {
        false
    }
}
/// Detached evidence of this store's original irreversible consume attempt.
/// It grants no spend, connection, retry or replay authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolSpendState {
    NotSubmitted,
    CommitKnown,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolSpendObservation {
    pub state: PoolSpendState,
    pub artifact_digest: [u8; 32],
    pub activation_digest: [u8; 32],
    pub attempt_id: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Flowersec pool storage {code:?} ({write_state:?})")]
pub struct PoolStoreError {
    pub code: PoolStoreFailure,
    pub write_state: PoolWriteState,
    pub format: Option<StorageFormatIncompatibility>,
}
type Result<T> = std::result::Result<T, PoolStoreError>;
fn fail(code: PoolStoreFailure) -> PoolStoreError {
    PoolStoreError {
        code,
        write_state: PoolWriteState::NotSubmitted,
        format: None,
    }
}
impl From<EnvironmentError> for PoolStoreError {
    fn from(e: EnvironmentError) -> Self {
        fail(match e {
            EnvironmentError::Capacity => PoolStoreFailure::Capacity,
            EnvironmentError::Closed => PoolStoreFailure::Closed,
            _ => PoolStoreFailure::OwnerUnavailable,
        })
    }
}
impl From<rusqlite::Error> for PoolStoreError {
    fn from(_: rusqlite::Error) -> Self {
        fail(PoolStoreFailure::StorageUnavailable)
    }
}
impl From<std::io::Error> for PoolStoreError {
    fn from(_: std::io::Error) -> Self {
        fail(PoolStoreFailure::StorageUnavailable)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SQLitePoolIdentity {
    pub authority: String,
    pub store_id: [u8; 32],
    pub generation: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SQLitePoolBinding {
    pub tenant: String,
    pub issuer: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SQLitePoolLimits {
    pub max_pages: u32,
    pub max_records: u32,
    pub max_record_bytes: u32,
    /// Predeclared additional native allocator, statement and VFS working space.
    pub provider_runtime_bytes: u64,
    pub disk_overhead_bytes: u64,
}
impl SQLitePoolLimits {
    fn check(self) -> Result<()> {
        if !(16..=1 << 20).contains(&self.max_pages)
            || !(1..=1 << 20).contains(&self.max_records)
            || !(8192..=1 << 20).contains(&self.max_record_bytes)
            || self.provider_runtime_bytes < 262_144
            || self.disk_overhead_bytes < 65_536
        {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        self.runtime()?;
        self.disk()?;
        Ok(())
    }
    fn disk(self) -> Result<u64> {
        let pages = u64::from(self.max_pages);
        pages
            .checked_mul(2 * PAGE + 24)
            .and_then(|n| n.checked_add(32 + (1 + pages / 4096) * 32768))
            .and_then(|n| n.checked_add(self.disk_overhead_bytes))
            .ok_or(fail(PoolStoreFailure::Capacity))
    }
    fn runtime(self) -> Result<u64> {
        u64::from(self.max_pages)
            .checked_mul(PAGE * 2)
            .and_then(|n| n.checked_add(u64::from(self.max_record_bytes) * 2 + 32_768))
            .and_then(|n| n.checked_add(self.provider_runtime_bytes))
            .ok_or(fail(PoolStoreFailure::Capacity))
    }
}
/// Independent trusted host proof of complete, non-rolled-back history. This
/// check never executes a spend and cannot report a SQLite COMMIT result.
pub trait SQLitePoolContinuity: fmt::Debug + Send + Sync + 'static {
    fn check(&self, identity: &SQLitePoolIdentity, epoch: u64, provisioning: bool) -> Result<()>;
}
#[derive(Clone, Debug)]
pub struct SQLitePoolOptions {
    pub identity: SQLitePoolIdentity,
    pub continuity: Arc<dyn SQLitePoolContinuity>,
    pub bindings: Vec<SQLitePoolBinding>,
    pub create: bool,
}
#[derive(Debug)]
struct BackingState {
    charge: Option<EnvironmentCharge>,
    active: bool,
    closed: bool,
}
pub(crate) struct Backing {
    environment: Arc<EnvironmentRoot>,
    path: PathBuf,
    limits: SQLitePoolLimits,
    state: Mutex<BackingState>,
}
impl fmt::Debug for Backing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PoolBacking { <opaque> }")
    }
}
/// The Environment retains the persistent allocation even if this handle is
/// dropped. Storage removal is an explicit host action after history retirement.
#[derive(Clone, Debug)]
pub struct SQLitePoolBacking {
    inner: Arc<Backing>,
}
fn missing(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    PathBuf::from(p)
}
fn protected_file(path: &Path, limit: u64) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.len() > limit {
        return Err(fail(PoolStoreFailure::StorageUnavailable));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() != 1 || m.mode() & 0o077 != 0 {
            return Err(fail(PoolStoreFailure::StorageUnavailable));
        }
    }
    Ok(m)
}
impl SQLitePoolBacking {
    pub(crate) fn new(
        environment: Arc<EnvironmentRoot>,
        path: &Path,
        limits: SQLitePoolLimits,
    ) -> Result<Self> {
        limits.check()?;
        #[cfg(not(unix))]
        {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        if !path.is_absolute() || path.as_os_str().len() > 4096 || path.file_name().is_none() {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        let parent = path.parent().ok_or(fail(PoolStoreFailure::Configuration))?;
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || fs::canonicalize(parent)? != parent {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if m.mode() & 0o022 != 0 {
                return Err(fail(PoolStoreFailure::StorageUnavailable));
            }
        }
        environment.sample()?;
        let charge = environment.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            disk_bytes: limits.disk()?,
            items: u64::from(limits.max_records) + 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let inner = Arc::new(Backing {
            environment: environment.clone(),
            path: path.to_owned(),
            limits,
            state: Mutex::new(BackingState {
                charge: Some(charge),
                active: false,
                closed: false,
            }),
        });
        environment.register_pool_backing(inner.clone())?;
        Ok(Self { inner })
    }
    pub fn open(&self, options: SQLitePoolOptions) -> Result<Arc<SQLitePoolStore>> {
        SQLitePoolStore::open(self.inner.clone(), options)
    }
    /// A relay ledger has its own protected format and history. It shares the
    /// backing protection and continuity machinery, never the consumer table.
    pub fn open_relay(
        &self,
        options: relay::SQLiteRelayOptions,
    ) -> Result<Arc<relay::SQLiteRelayLedger>> {
        relay::SQLiteRelayLedger::open(self.inner.clone(), options)
    }
    pub fn close(&self) {
        self.inner.state.lock().expect("pool backing").closed = true;
    }
    pub fn retained_disk_bytes(&self) -> u64 {
        if self
            .inner
            .state
            .lock()
            .expect("pool backing")
            .charge
            .is_some()
        {
            self.inner.limits.disk().expect("validated disk charge")
        } else {
            0
        }
    }
    /// Call only after the host has discharged all retained history obligations
    /// and physically removed the database and every journal file.
    pub fn release_removed(&self) -> Result<()> {
        let mut state = self.inner.state.lock().expect("pool backing");
        if state.active {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            if !missing(&sibling(&self.inner.path, suffix))? {
                return Err(fail(PoolStoreFailure::HistoryUnknown));
            }
        }
        state.closed = true;
        state.charge = None;
        drop(state);
        self.inner.environment.release_pool_backing(&self.inner);
        Ok(())
    }
}
struct StoreState {
    database: Option<Connection>,
    charge: Option<EnvironmentCharge>,
    epoch: u64,
    inode: Option<(u64, u64)>,
    spend_observation: Option<PoolSpendObservation>,
}
pub struct SQLitePoolStore {
    relay_format: bool,
    backing: Arc<Backing>,
    identity: SQLitePoolIdentity,
    continuity: Arc<dyn SQLitePoolContinuity>,
    bindings: Vec<SQLitePoolBinding>,
    state: Mutex<StoreState>,
    closed: AtomicBool,
}
impl fmt::Debug for SQLitePoolStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SQLitePoolStore { <opaque> }")
    }
}
fn security_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/@-".contains(&b))
        && value.as_bytes()[0].is_ascii_alphanumeric()
}
fn nonzero(v: &[u8]) -> bool {
    v.iter().any(|b| *b != 0)
}
fn scalar<T: rusqlite::types::FromSql>(db: &Connection, sql: &str) -> Result<T> {
    Ok(db.query_row(sql, [], |row| row.get(0))?)
}
fn read_u64(value: Vec<u8>) -> Result<u64> {
    Ok(u64::from_be_bytes(
        value
            .try_into()
            .map_err(|_| fail(PoolStoreFailure::StorageFormat))?,
    ))
}
impl SQLitePoolStore {
    pub(crate) fn belongs_to(&self, root: &Arc<EnvironmentRoot>) -> bool {
        Arc::ptr_eq(&self.backing.environment, root) && !self.closed.load(Ordering::Acquire)
    }
    fn open(backing: Arc<Backing>, options: SQLitePoolOptions) -> Result<Arc<Self>> {
        Self::open_format(backing, options, false)
    }
    fn open_format(
        backing: Arc<Backing>,
        options: SQLitePoolOptions,
        relay_format: bool,
    ) -> Result<Arc<Self>> {
        if !security_id(&options.identity.authority)
            || !nonzero(&options.identity.store_id)
            || options.identity.generation == 0
            || options.bindings.is_empty()
            || options.bindings.len() > 64
        {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        for (i, b) in options.bindings.iter().enumerate() {
            if !security_id(&b.tenant) || !nonzero(&b.issuer) || options.bindings[..i].contains(b) {
                return Err(fail(PoolStoreFailure::Configuration));
            }
        }
        let mut owner = backing.state.lock().expect("pool backing");
        if owner.closed || owner.active || owner.charge.is_none() {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let charge = backing.environment.reserve_environment(ResourceLimits {
            // Current-record inspection owns bounded projection/hash scratch
            // independently of the provider's two simultaneous row buffers.
            sdk_bytes: 32_768 + records::SCRATCH_BYTES,
            provider_bytes: backing.limits.runtime()?,
            items: 1,
            work_slots: 1,
            tasks: 1,
            native_handles: 4,
            ..ResourceLimits::default()
        })?;
        owner.active = true;
        drop(owner);
        let store = Arc::new(Self {
            relay_format,
            backing,
            identity: options.identity,
            continuity: options.continuity,
            bindings: options.bindings,
            state: Mutex::new(StoreState {
                database: None,
                charge: Some(charge),
                epoch: 0,
                inode: None,
                spend_observation: None,
            }),
            closed: AtomicBool::new(false),
        });
        if let Err(e) = store.initialize(options.create).and_then(|()| {
            store
                .backing
                .environment
                .register_pool_store(&store)
                .map_err(Into::into)
        }) {
            if matches!(
                e.code,
                PoolStoreFailure::StorageFormat
                    | PoolStoreFailure::StorageUnavailable
                    | PoolStoreFailure::HistoryUnknown
                    | PoolStoreFailure::Fenced
            ) {
                store
                    .backing
                    .environment
                    .diagnostic_count(crate::diagnostics_v4::DiagnosticCounter::StoreFailures);
            }
            store.close();
            return Err(e);
        }
        Ok(store)
    }
    fn files(&self, state: &mut StoreState) -> Result<()> {
        let pages = u64::from(self.backing.limits.max_pages);
        for (suffix, cap) in [
            ("", pages * PAGE),
            ("-wal", 32 + pages * (PAGE + 24)),
            ("-shm", (1 + pages / 4096) * 32768),
            ("-journal", 0),
        ] {
            let path = sibling(&self.backing.path, suffix);
            if !suffix.is_empty() && missing(&path)? {
                continue;
            }
            if suffix == "-journal" {
                return Err(fail(PoolStoreFailure::StorageUnavailable));
            }
            let metadata = protected_file(&path, cap)?;
            #[cfg(unix)]
            if suffix.is_empty() {
                use std::os::unix::fs::MetadataExt;
                let inode = (metadata.dev(), metadata.ino());
                if state.inode.is_some_and(|old| old != inode) {
                    return Err(fail(PoolStoreFailure::HistoryUnknown));
                }
                state.inode = Some(inode);
            }
        }
        Ok(())
    }
    fn check(&self, state: &mut StoreState) -> Result<()> {
        if self.closed.load(Ordering::Acquire) || self.backing.environment.is_closed() {
            return Err(fail(PoolStoreFailure::Closed));
        }
        self.backing.environment.sample()?;
        self.files(state)
    }
    fn fence(&self, state: &StoreState) -> Result<()> {
        let db = state
            .database
            .as_ref()
            .ok_or(fail(PoolStoreFailure::Closed))?;
        if read_u64(scalar(db, "SELECT epoch FROM manifest WHERE id=1")?)? != state.epoch {
            return Err(fail(PoolStoreFailure::Fenced));
        }
        self.continuity.check(&self.identity, state.epoch, false)
    }
    fn initialize(&self, create: bool) -> Result<()> {
        self.initialize_current(create).map_err(|mut error| {
            if error.code == PoolStoreFailure::StorageFormat && error.format.is_none() {
                error.format = self
                    .format_error(None, StorageFormatMismatchReason::BackendConfiguration)
                    .format;
            }
            error
        })
    }
    fn initialize_current(&self, create: bool) -> Result<()> {
        let mut state = self.state.lock().expect("pool store");
        let c = self.backing.limits;
        if create {
            self.continuity.check(&self.identity, 0, true)?;
            for suffix in ["", "-wal", "-shm", "-journal"] {
                if !missing(&sibling(&self.backing.path, suffix))? {
                    return Err(fail(PoolStoreFailure::HistoryUnknown));
                }
            }
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&self.backing.path)?.sync_all()?;
        } else if missing(&self.backing.path)? {
            return Err(fail(PoolStoreFailure::HistoryUnknown));
        }
        self.files(&mut state)?;
        let db = Connection::open_with_flags(
            &self.backing.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(Duration::ZERO)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
        db.execute_batch("PRAGMA locking_mode=EXCLUSIVE")?;
        for (limit, bound) in [
            (
                Limit::SQLITE_LIMIT_LENGTH,
                c.max_record_bytes as i32 + 16_384,
            ),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 8192),
            (Limit::SQLITE_LIMIT_COLUMN, 64),
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
            (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
            (Limit::SQLITE_LIMIT_VDBE_OP, 100_000),
        ] {
            db.set_limit(limit, bound)?;
        }
        // Only connection-local defensive controls precede format inspection.
        // A rejected group must not checkpoint, change journal mode or fence
        // its epoch before the complete current reader accepts it.
        db.execute_batch("PRAGMA trusted_schema=OFF;")?;
        let inspected_epoch = if !create {
            db.execute_batch("PRAGMA query_only=ON; BEGIN")?;
            let inspected = self.validate_format(&db);
            let rolled_back = db.execute_batch("ROLLBACK");
            let epoch = inspected?;
            rolled_back?;
            self.continuity.check(&self.identity, epoch, false)?;
            self.files(&mut state)?;
            db.execute_batch("PRAGMA query_only=OFF")?;
            Some(epoch)
        } else {
            None
        };
        if create {
            db.execute_batch("PRAGMA page_size=4096; PRAGMA journal_mode=WAL;")?;
        }
        if scalar::<u64>(&db, "PRAGMA page_size")? != PAGE
            || scalar::<String>(&db, "PRAGMA journal_mode")? != "wal"
        {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA checkpoint_fullfsync=ON; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF; PRAGMA wal_autocheckpoint=0; PRAGMA locking_mode=EXCLUSIVE;")?;
        for (name, expected) in [
            ("synchronous", 2),
            ("fullfsync", 1),
            ("checkpoint_fullfsync", 1),
            ("foreign_keys", 1),
            ("trusted_schema", 0),
            ("temp_store", 2),
            ("cache_spill", 0),
            ("wal_autocheckpoint", 0),
            ("busy_timeout", 0),
        ] {
            if scalar::<u64>(&db, &format!("PRAGMA {name}"))? != expected {
                return Err(fail(PoolStoreFailure::StorageUnavailable));
            }
        }
        if scalar::<String>(&db, "PRAGMA locking_mode")? != "exclusive" {
            return Err(fail(PoolStoreFailure::StorageUnavailable));
        }
        db.execute_batch(&format!(
            "PRAGMA cache_size={}; PRAGMA max_page_count={}; PRAGMA journal_size_limit={};",
            c.max_pages,
            c.max_pages,
            32 + u64::from(c.max_pages) * (PAGE + 24)
        ))?;
        if scalar::<u64>(&db, "PRAGMA max_page_count")? != u64::from(c.max_pages)
            || scalar::<u64>(&db, "PRAGMA page_count")? > u64::from(c.max_pages)
        {
            return Err(fail(PoolStoreFailure::Capacity));
        }
        if !create {
            let checkpoint = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?;
            if checkpoint != (0, 0, 0) {
                return Err(fail(PoolStoreFailure::StorageUnavailable));
            }
        }
        state.database = Some(db);
        let result = (|| {
            let db = state.database.as_ref().expect("opened database");
            db.execute_batch("BEGIN IMMEDIATE")?;
            let epoch = if create && self.relay_format {
                relay::initialize(db, &self.identity, c)?;
                1
            } else if create {
                db.execute_batch(MANIFEST)?;
                db.execute_batch(SPEND)?;
                db.execute_batch(admission::WINNER)?;
                db.execute_batch(admission::ADMISSION)?;
                db.execute_batch(top_up::SOURCE)?;
                db.execute_batch(top_up::PENDING)?;
                db.execute_batch(top_up::MATERIAL)?;
                db.execute_batch("PRAGMA user_version=3")?;
                db.execute(
                    "INSERT INTO manifest VALUES(1,'flowersec-v4-rust-pool',3,?,?,?,?,?,?,?,0,0,0)",
                    params![
                        self.identity.authority,
                        &self.identity.store_id,
                        self.identity.generation.to_be_bytes(),
                        1u64.to_be_bytes(),
                        c.max_pages,
                        c.max_records,
                        c.max_record_bytes
                    ],
                )?;
                1
            } else {
                let old = inspected_epoch.ok_or(fail(PoolStoreFailure::StorageUnavailable))?;
                let next = old.checked_add(1).ok_or(fail(PoolStoreFailure::Fenced))?;
                if db.execute(
                    "UPDATE manifest SET epoch=? WHERE id=1 AND epoch=?",
                    params![next.to_be_bytes(), old.to_be_bytes()],
                )? != 1
                {
                    return Err(fail(PoolStoreFailure::Fenced));
                }
                next
            };
            self.continuity.check(&self.identity, epoch, false)?;
            if self.backing.environment.is_closed() {
                return Err(fail(PoolStoreFailure::Closed));
            }
            db.execute_batch("COMMIT").map_err(|_| PoolStoreError {
                code: if self.relay_format {
                    PoolStoreFailure::RelayClaimUnknown
                } else {
                    PoolStoreFailure::SpentUnknown
                },
                write_state: PoolWriteState::Unknown,
                format: None,
            })?;
            state.epoch = epoch;
            if create {
                File::open(
                    self.backing
                        .path
                        .parent()
                        .ok_or(fail(PoolStoreFailure::Configuration))?,
                )?
                .sync_all()?;
            }
            self.check(&mut state)?;
            state
                .database
                .as_ref()
                .expect("admitted database")
                .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)?;
            Ok(())
        })();
        if result.is_err()
            && let Some(db) = &state.database
        {
            let _ = db.execute_batch("ROLLBACK");
        }
        result
    }
    fn format_error(
        &self,
        observed: Option<u32>,
        reason: StorageFormatMismatchReason,
    ) -> PoolStoreError {
        let (group, wire, revision) = if self.relay_format {
            (
                StorageFormatTransactionGroup::Relay,
                StorageWireFormat::FlowersecV4RustRelay,
                1,
            )
        } else {
            (
                StorageFormatTransactionGroup::Pool,
                StorageWireFormat::FlowersecV4RustPool,
                3,
            )
        };
        PoolStoreError {
            code: PoolStoreFailure::StorageFormat,
            write_state: PoolWriteState::NotSubmitted,
            format: Some(StorageFormatIncompatibility::new(
                group, wire, revision, observed, reason,
            )),
        }
    }
    fn observe_transaction_failure(&self, error: PoolStoreError) {
        use crate::diagnostics_v4::DiagnosticCounter;
        let metric = match error.code {
            PoolStoreFailure::SpentUnknown | PoolStoreFailure::RelayClaimUnknown => {
                Some(DiagnosticCounter::SpendUnknown)
            }
            PoolStoreFailure::SpendConflict
            | PoolStoreFailure::AdmissionConflict
            | PoolStoreFailure::WinnerConflict
            | PoolStoreFailure::RelayClaimConflict
            | PoolStoreFailure::RelayPublicationConflict => {
                Some(DiagnosticCounter::ReservationConflicts)
            }
            PoolStoreFailure::StorageUnavailable
            | PoolStoreFailure::StorageFormat
            | PoolStoreFailure::HistoryUnknown
            | PoolStoreFailure::Fenced => Some(DiagnosticCounter::StoreFailures),
            _ => None,
        };
        if let Some(metric) = metric {
            self.backing.environment.diagnostic_count(metric);
        }
    }
    fn inspect_format(&self, db: &Connection) -> Result<u32> {
        let unknown = || self.format_error(None, StorageFormatMismatchReason::MissingManifest);
        let read_error = |error: rusqlite::Error| {
            if matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
            ) {
                fail(PoolStoreFailure::StorageUnavailable)
            } else {
                unknown()
            }
        };
        let (manifest, name, required) = if self.relay_format {
            (relay::MANIFEST, "flowersec-v4-rust-relay", 1u32)
        } else {
            (MANIFEST, "flowersec-v4-rust-pool", 3u32)
        };
        let prefix: Vec<u8> = db.query_row(
            "SELECT substr(CAST(sql AS BLOB),1,768) FROM sqlite_schema WHERE type='table' AND name='manifest'",
            [], |row| row.get(0)).map_err(read_error)?;
        let prefix = std::str::from_utf8(&prefix).map_err(|_| unknown())?;
        let marker = format!("CHECK(revision={required})");
        let (before, after) = manifest.split_once(&marker).ok_or_else(unknown)?;
        let after = after
            .split_once("epoch BLOB NOT NULL CHECK(length(epoch)=8),")
            .ok_or_else(unknown)?
            .0;
        let remaining = prefix
            .strip_prefix(before)
            .and_then(|s| s.strip_prefix("CHECK(revision="))
            .ok_or_else(unknown)?;
        let (digits, remaining) = remaining.split_once(')').ok_or_else(unknown)?;
        if digits.is_empty()
            || digits.len() > 10
            || digits.starts_with('0')
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(unknown());
        }
        let declared = digits.parse::<u32>().map_err(|_| unknown())?;
        if !remaining
            .strip_prefix(after)
            .is_some_and(|s| s.starts_with("epoch BLOB NOT NULL CHECK(length(epoch)=8),"))
        {
            return Err(unknown());
        }
        // SQL comparisons expose only bounded booleans, the declared revision
        // and the fixed eight-byte fence. No untrusted provider text escapes.
        let row = db.query_row(
            "SELECT (SELECT count(*) FROM (SELECT 1 FROM manifest LIMIT 2)),id=1,typeof(format)='text' AND format=?1,CASE WHEN typeof(revision)='integer' AND revision BETWEEN 1 AND 4294967295 THEN revision END,typeof(authority)='text' AND authority=?2,typeof(instance)='blob' AND instance=?3,typeof(generation)='blob' AND generation=?4,CASE WHEN typeof(epoch)='blob' AND length(epoch)=8 THEN epoch END FROM manifest LIMIT 1",
            params![name, self.identity.authority, self.identity.store_id, self.identity.generation.to_be_bytes()],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, bool>(1)?, row.get::<_, bool>(2)?, row.get::<_, Option<u32>>(3)?,
                row.get::<_, bool>(4)?, row.get::<_, bool>(5)?, row.get::<_, bool>(6)?, row.get::<_, Option<Vec<u8>>>(7)?)))
            .map_err(read_error)?;
        let epoch = row
            .7
            .and_then(|v| <[u8; 8]>::try_from(v).ok())
            .map(u64::from_be_bytes);
        if row.0 != 1 || !row.1 || !row.2 || epoch.is_none_or(|v| v == 0 || v == u64::MAX) {
            return Err(unknown());
        }
        if !row.4 || !row.5 || !row.6 {
            return Err(self.format_error(None, StorageFormatMismatchReason::IdentityMismatch));
        }
        let hint = db
            .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .ok();
        if row.3 != Some(declared) || hint != Some(declared) {
            return Err(self.format_error(None, StorageFormatMismatchReason::RevisionConflict));
        }
        if declared != required {
            return Err(self.format_error(
                Some(declared),
                if declared < required {
                    StorageFormatMismatchReason::OlderRevision
                } else {
                    StorageFormatMismatchReason::NewerRevision
                },
            ));
        }
        Ok(declared)
    }
    fn validate_format(&self, db: &Connection) -> Result<u64> {
        let observed = self.inspect_format(db)?;
        self.validate(db).map_err(|error| match error.code {
            PoolStoreFailure::StorageFormat | PoolStoreFailure::StorageUnavailable => {
                self.format_error(Some(observed), StorageFormatMismatchReason::Schema)
            }
            _ => error,
        })
    }
    fn validate(&self, db: &Connection) -> Result<u64> {
        let c = self.backing.limits;
        if self.relay_format {
            return relay::validate(db, &self.identity, c);
        }
        if scalar::<u64>(db, "PRAGMA user_version")? != 3
            || scalar::<u64>(db, "SELECT count(*) FROM sqlite_schema")? != 7
        {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        for (name, sql) in [
            ("manifest", MANIFEST),
            ("spend", SPEND),
            ("parent_winner", admission::WINNER),
            ("admission", admission::ADMISSION),
            ("top_up_source", top_up::SOURCE),
            ("top_up_pending", top_up::PENDING),
            ("top_up_material", top_up::MATERIAL),
        ] {
            let actual: Option<String> = db
                .query_row(
                    "SELECT sql FROM sqlite_schema WHERE name=? AND type='table'",
                    [name],
                    |r| r.get(0),
                )
                .optional()?;
            if actual.as_deref() != Some(sql) {
                return Err(fail(PoolStoreFailure::StorageFormat));
            }
        }
        if scalar::<u64>(db, "SELECT count(*) FROM manifest")? != 1 {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        let row=db.query_row("SELECT format,revision,authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,spend_rows FROM manifest WHERE id=1",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u64>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,u32>(6)?,r.get::<_,u32>(7)?,r.get::<_,u32>(8)?,r.get::<_,u32>(9)?)))?;
        let epoch = read_u64(row.5)?;
        if row.0 != "flowersec-v4-rust-pool"
            || row.1 != 3
            || row.2 != self.identity.authority
            || row.3 != self.identity.store_id
            || read_u64(row.4)? != self.identity.generation
            || epoch == 0
            || row.6 != c.max_pages
            || row.7 != c.max_records
            || row.8 != c.max_record_bytes
            || row.9 > c.max_records
            || scalar::<u64>(db, "SELECT count(*) FROM spend")? != u64::from(row.9)
        {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        let bad:u64=db.query_row("SELECT count(*) FROM spend WHERE length(projection)>? OR fence>? OR version<>? OR source<>1 OR state<>1",params![c.max_record_bytes,epoch.to_be_bytes(),1u64.to_be_bytes()],|r|r.get(0))?;
        if bad != 0 {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        records::validate_spend(db, &self.identity, c, epoch)?;
        let bad_top_up_sources: u64 = db.query_row(
            "SELECT count(*) FROM top_up_source WHERE length(tenant)=0 OR length(incarnation)<>16 OR length(generation)<>8 OR generation=zeroblob(8) OR length(next_sequence)<>8 OR next_sequence=zeroblob(8) OR length(artifact_frontier)<>8",
            [], |r| r.get(0))?;
        let bad_top_up_pending: u64 = db.query_row(
            "SELECT count(*) FROM top_up_pending p WHERE length(p.tenant)=0 OR length(p.incarnation)<>16 OR length(p.operation)<>16 OR length(p.request) NOT BETWEEN 1 AND 524288 OR length(p.request)>? OR length(p.request_digest)<>32 OR length(p.identity_digest)<>32 OR length(p.created_generation)<>8 OR p.created_generation=zeroblob(8) OR length(p.generation)<>8 OR (p.state IN (2,3) AND p.generation=zeroblob(8)) OR p.state NOT BETWEEN 1 AND 4 OR (p.state=1 AND (p.response IS NOT NULL OR p.applied_entries IS NOT NULL OR p.terminal IS NOT NULL)) OR (p.state IN (2,3) AND (p.response IS NULL OR length(p.response)=0 OR length(p.response)>? OR p.applied_entries IS NULL OR length(p.applied_entries) NOT BETWEEN 1 AND 1024 OR p.terminal IS NOT NULL)) OR (p.state=4 AND (p.terminal IS NULL OR p.terminal NOT IN ('top_up_request_expired','source_reset_required','capacity_exhausted','configuration_capacity','relink_required','spent_unknown') OR (p.response IS NULL)<>(p.applied_entries IS NULL) OR (p.response IS NOT NULL AND (p.terminal<>'source_reset_required' OR length(p.response) NOT BETWEEN 1 AND ? OR length(p.applied_entries) NOT BETWEEN 1 AND 1024)))) OR NOT EXISTS (SELECT 1 FROM top_up_source s WHERE s.tenant=p.tenant AND s.incarnation=p.incarnation)",
            params![c.max_record_bytes,c.max_record_bytes,c.max_record_bytes], |r| r.get(0))?;
        let bad_top_up_material: u64 = db.query_row(
            "SELECT count(*) FROM top_up_material m WHERE length(m.tenant)=0 OR length(m.incarnation)<>16 OR length(m.sequence)<>8 OR m.sequence=zeroblob(8) OR length(m.expiry)<>8 OR m.expiry=zeroblob(8) OR length(m.artifact_digest)<>32 OR length(m.material) NOT BETWEEN 1 AND 65536 OR length(m.material)>? OR NOT EXISTS (SELECT 1 FROM top_up_source s WHERE s.tenant=m.tenant AND s.incarnation=m.incarnation AND m.sequence<=s.artifact_frontier)",
            params![c.max_record_bytes], |r| r.get(0))?;
        let top_up_sources: u64 = scalar(db, "SELECT count(*) FROM top_up_source")?;
        let top_up_material: u64 = scalar(db, "SELECT count(*) FROM top_up_material")?;
        if bad_top_up_sources != 0
            || bad_top_up_pending != 0
            || bad_top_up_material != 0
            || top_up_sources > 8
            || top_up_material > 128
        {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        top_up::validate_terminal_applied(db)?;
        admission::validate(db, &self.identity, c, epoch)?;
        Ok(epoch)
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let mut state = self.state.lock().expect("pool store");
        self.cleanup(&mut state);
    }
    fn cleanup(&self, state: &mut StoreState) {
        if let Some(db) = state.database.take()
            && let Err((db, _)) = db.close()
        {
            state.database = Some(db);
            return;
        }
        state.charge = None;
        self.backing.state.lock().expect("pool backing").active = false;
    }
    pub fn spend_observation(&self) -> Option<PoolSpendObservation> {
        self.state
            .lock()
            .expect("original spend observation")
            .spend_observation
    }
    pub fn cleanup_complete(&self) -> bool {
        let state = self.state.lock().expect("pool store");
        self.closed.load(Ordering::Acquire) && state.database.is_none()
    }
}
impl Drop for SQLitePoolStore {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Debug)]
pub(crate) struct VerifiedPoolFacts {
    pub(crate) tenant: String,
    pub(crate) issuer: [u8; 16],
    pub(crate) lease: [u8; 16],
    pub(crate) authority: String,
    pub(crate) winner_authority: String,
    pub(crate) proof: Vec<u8>,
    pub(crate) selection: Vec<u8>,
    pub(crate) route_set: [u8; 32],
    pub(crate) candidate_index: u8,
    pub(crate) issued_at: u64,
    pub(crate) parent_initiation_end: u64,
    pub(crate) session_end: u64,
    pub(crate) session_nonce: [u8; 32],
    pub(crate) _charge: ResourceCharge,
}
/// Created by the original connection assembly after it owns the prepared
/// carrier. It has no public constructor, serialization or resume path.
#[derive(Debug)]
pub(crate) struct PoolSpendOwner {
    connect: [u8; 16],
    carrier: [u8; 16],
    generation: u64,
    deadline: Instant,
    cancel: CancellationToken,
    carrier_cancel: Option<CancellationToken>,
}
impl PoolSpendOwner {
    pub(crate) fn new(
        carrier: [u8; 16],
        generation: u64,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> Result<Self> {
        if !nonzero(&carrier) || generation == 0 || deadline <= Instant::now() {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let mut connect = [0; 16];
        SystemRandom::new()
            .fill(&mut connect)
            .map_err(|_| fail(PoolStoreFailure::OwnerUnavailable))?;
        Ok(Self {
            connect,
            carrier,
            generation,
            deadline,
            cancel,
            carrier_cancel: None,
        })
    }
    pub(crate) fn bind_carrier(mut self, cancel: CancellationToken) -> Self {
        self.carrier_cancel = Some(cancel);
        self
    }
    fn check(&self) -> Result<()> {
        if self.cancel.is_cancelled()
            || self
                .carrier_cancel
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            || Instant::now() >= self.deadline
        {
            Err(fail(PoolStoreFailure::OwnerUnavailable))
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
pub(crate) struct PoolActivation {
    store: Arc<SQLitePoolStore>,
    epoch: u64,
    owner: PoolSpendOwner,
    account: ResourceAccount,
    cutoff: u64,
    binding: [u8; 32],
    _charge: ResourceCharge,
}
fn activation_binding(admission: &CredentialAdmission) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"flowersec/local/rust-pool-owner\0");
    for value in [
        &admission.artifact_digest[..],
        &admission.activation_digest,
        &admission.candidate_id,
        &admission.route_digest,
        &admission.attempt_id,
        &admission.certificate_digests[0],
        &admission.certificate_digests[1],
    ] {
        hash.update(value);
    }
    hash.finalize().into()
}
impl PoolActivation {
    pub(crate) fn authorize(&self, admission: &CredentialAdmission) -> Result<()> {
        if !self.account.same_owner(&admission.account)
            || self.binding != activation_binding(admission)
            || self.cutoff != admission.initiation_not_after_ms
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        self.check()
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.owner.check()?;
        if self.account.security_time()?.upper_ms >= self.cutoff {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let mut state = self.store.state.lock().expect("pool store");
        self.store.check(&mut state)?;
        if state.epoch != self.epoch {
            return Err(fail(PoolStoreFailure::Fenced));
        }
        self.store.fence(&state)
    }
}
fn head(out: &mut Vec<u8>, value: u64) {
    codec::encode_head(out, 0, value)
}
fn data(out: &mut Vec<u8>, value: &[u8]) {
    codec::encode_head(out, 2, value.len() as u64);
    out.extend_from_slice(value)
}
fn text(out: &mut Vec<u8>, value: &str) {
    codec::encode_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes())
}
impl SQLitePoolStore {
    pub(crate) fn consume(
        self: &Arc<Self>,
        mut admission: CredentialAdmission,
        owner: PoolSpendOwner,
    ) -> Result<CredentialAdmission> {
        if admission.source != ActivationSource::PreauthorizedPool
            || admission.pool_activation.is_some()
            || !admission.account.belongs_to(&self.backing.environment)
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let facts = admission
            .pool
            .take()
            .ok_or(fail(PoolStoreFailure::OwnerUnavailable))?;
        if facts.authority != self.identity.authority
            || !self
                .bindings
                .iter()
                .any(|b| b.tenant == facts.tenant && b.issuer == facts.issuer)
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let charge = admission.account.reserve(ResourceLimits {
            sdk_bytes: 1024,
            items: 1,
            work_slots: 1,
            tasks: 0,
            sessions: 0,
            ..ResourceLimits::default()
        })?;
        let _work = admission.account.reserve(ResourceLimits {
            sdk_bytes: u64::from(self.backing.limits.max_record_bytes) * 2 + 16_384,
            items: 1,
            work_slots: 1,
            tasks: 1,
            sessions: 0,
            ..ResourceLimits::default()
        })?;
        let mut state = self.state.lock().expect("pool store");
        let check = |state: &mut StoreState| -> Result<()> {
            self.check(state)?;
            owner.check()?;
            let now = admission.account.security_time()?;
            if now.lower_ms < facts.issued_at || now.upper_ms >= admission.initiation_not_after_ms {
                return Err(fail(PoolStoreFailure::OwnerUnavailable));
            }
            Ok(())
        };
        check(&mut state)?;
        let now = admission.account.security_time()?;
        let retained = facts
            .parent_initiation_end
            .max(now.upper_ms)
            .checked_add(RETENTION)
            .ok_or(fail(PoolStoreFailure::Capacity))?;
        let mut lease = Zeroizing::new(Vec::with_capacity(161));
        lease.push(facts.tenant.len() as u8);
        lease.extend_from_slice(facts.tenant.as_bytes());
        lease.extend_from_slice(&facts.issuer);
        lease.extend_from_slice(&facts.lease);
        let mut projection = Zeroizing::new(Vec::new());
        projection
            .try_reserve_exact(self.backing.limits.max_record_bytes as usize)
            .map_err(|_| fail(PoolStoreFailure::Capacity))?;
        codec::encode_head(&mut projection, 5, 29);
        for key in 0..29 {
            head(&mut projection, key);
            match key {
                0 => head(&mut projection, 1),
                1 => data(&mut projection, &self.identity.store_id),
                2 => head(&mut projection, self.identity.generation),
                3 => head(&mut projection, state.epoch),
                4 => text(&mut projection, &facts.tenant),
                5 => data(&mut projection, &facts.issuer),
                6 => data(&mut projection, &facts.lease),
                7 => data(&mut projection, &admission.artifact_digest),
                8 => data(&mut projection, &facts.proof),
                9 => data(&mut projection, &admission.activation_digest),
                10 => data(&mut projection, &admission.candidate_id),
                11 => head(&mut projection, u64::from(facts.candidate_index)),
                12 => data(&mut projection, &admission.route_digest),
                13 => data(&mut projection, &admission.attempt_id),
                14 => data(&mut projection, &owner.connect),
                15 => data(&mut projection, &owner.carrier),
                16 => head(&mut projection, owner.generation),
                17 => data(&mut projection, &facts.selection),
                18 => data(&mut projection, &facts.route_set),
                19 => data(&mut projection, &facts.session_nonce),
                20 => head(&mut projection, facts.issued_at),
                21 => head(&mut projection, admission.initiation_not_after_ms),
                22 => head(&mut projection, facts.session_end),
                23 => head(&mut projection, now.upper_ms),
                24 => head(&mut projection, retained),
                25 => head(&mut projection, facts.parent_initiation_end),
                26 => text(&mut projection, &facts.authority),
                27 => text(&mut projection, &facts.winner_authority),
                28 => {
                    codec::encode_head(&mut projection, 4, 2);
                    for id in admission.certificate_digests {
                        data(&mut projection, &id)
                    }
                }
                _ => unreachable!(),
            }
        }
        if projection.len() > self.backing.limits.max_record_bytes as usize {
            return Err(fail(PoolStoreFailure::Capacity));
        }
        let mut committed = false;
        let mut uncertain = false;
        let result = (|| {
            let db = state
                .database
                .as_ref()
                .ok_or(fail(PoolStoreFailure::Closed))?;
            let checkpoint = db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((
                    r.get::<_, u64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?;
            if checkpoint != (0, 0, 0) {
                return Err(fail(PoolStoreFailure::StorageUnavailable));
            }
            check(&mut state)?;
            state
                .database
                .as_ref()
                .expect("original database")
                .execute_batch("BEGIN IMMEDIATE")?;
            self.fence(&state)?;
            check(&mut state)?;
            let db = state.database.as_ref().expect("original database");
            if db
                .query_row(
                    "SELECT 1 FROM spend WHERE lease=?",
                    [lease.as_slice()],
                    |r| r.get::<_, u8>(0),
                )
                .optional()?
                .is_some()
            {
                return Err(fail(PoolStoreFailure::SpendConflict));
            }
            if scalar::<u64>(
                db,
                "SELECT spend_rows+winner_rows+admission_rows+(SELECT count(*) FROM top_up_material) FROM manifest WHERE id=1",
            )? >= u64::from(self.backing.limits.max_records)
            {
                return Err(fail(PoolStoreFailure::Capacity));
            }
            db.execute(
                "INSERT INTO spend VALUES(?,1,1,?,?,?,?)",
                params![
                    lease.as_slice(),
                    1u64.to_be_bytes(),
                    state.epoch.to_be_bytes(),
                    retained.to_be_bytes(),
                    projection.as_slice()
                ],
            )?;
            if db.execute(
                "UPDATE manifest SET spend_rows=spend_rows+1 WHERE id=1 AND epoch=?",
                [state.epoch.to_be_bytes()],
            )? != 1
            {
                return Err(fail(PoolStoreFailure::Fenced));
            }
            check(&mut state)?;
            self.fence(&state)?;
            uncertain = true;
            state
                .database
                .as_ref()
                .expect("original database")
                .execute_batch("COMMIT")?;
            committed = true;
            state.spend_observation = Some(PoolSpendObservation {
                state: PoolSpendState::CommitKnown,
                artifact_digest: admission.artifact_digest,
                activation_digest: admission.activation_digest,
                attempt_id: admission.attempt_id,
            });
            uncertain = false;
            check(&mut state)?;
            self.fence(&state)?;
            Ok(())
        })();
        if let Err(mut error) = result {
            if !committed
                && let Some(db) = &state.database
                && db.execute_batch("ROLLBACK").is_err()
            {
                self.closed.store(true, Ordering::Release);
            }
            if uncertain {
                state.spend_observation = Some(PoolSpendObservation {
                    state: PoolSpendState::Unknown,
                    artifact_digest: admission.artifact_digest,
                    activation_digest: admission.activation_digest,
                    attempt_id: admission.attempt_id,
                });
                self.closed.store(true, Ordering::Release);
                error = PoolStoreError {
                    code: PoolStoreFailure::SpentUnknown,
                    write_state: PoolWriteState::Unknown,
                    format: None,
                };
            } else if committed {
                error.write_state = PoolWriteState::Committed;
            }
            if self.closed.load(Ordering::Acquire) {
                self.cleanup(&mut state);
            }
            self.observe_transaction_failure(error);
            return Err(error);
        }
        let epoch = state.epoch;
        drop(state);
        let activation = PoolActivation {
            store: self.clone(),
            epoch,
            owner,
            account: admission.account.clone(),
            cutoff: admission.initiation_not_after_ms,
            binding: activation_binding(&admission),
            _charge: charge,
        };
        activation.check().map_err(|mut e| {
            e.write_state = PoolWriteState::Committed;
            e
        })?;
        admission.pool_activation = Some(activation);
        Ok(admission)
    }
}

#[cfg(test)]
#[path = "pool_v4_tests.rs"]
pub(crate) mod tests;
