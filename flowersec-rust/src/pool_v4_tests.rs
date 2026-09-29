use super::*;
use crate::namespace_v4::verifier::credential::tests::Fixture;
use std::sync::atomic::AtomicU64;
#[derive(Debug, Default)]
pub(crate) struct Continuity {
    reject: AtomicBool,
    epoch: AtomicU64,
    calls: AtomicU64,
    cancel: Mutex<Option<(u64, CancellationToken)>>,
}
impl Continuity {
    pub(crate) fn cancel_after_checks(&self, checks: u64, cancel: CancellationToken) {
        let target = self.calls.load(Ordering::Acquire) + checks;
        *self.cancel.lock().unwrap() = Some((target, cancel));
    }
}
impl SQLitePoolContinuity for Continuity {
    fn check(&self, _: &SQLitePoolIdentity, epoch: u64, provisioning: bool) -> Result<()> {
        if self.reject.load(Ordering::Acquire) {
            return Err(fail(PoolStoreFailure::HistoryUnknown));
        }
        let previous = self.epoch.load(Ordering::Acquire);
        if !provisioning && epoch < previous {
            return Err(fail(PoolStoreFailure::HistoryUnknown));
        }
        if !provisioning {
            self.epoch.fetch_max(epoch, Ordering::AcqRel);
        }
        let count = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some((threshold, cancel)) = self.cancel.lock().unwrap().as_ref()
            && count >= *threshold
        {
            cancel.cancel();
        }
        Ok(())
    }
}
pub(crate) struct StoreFixture {
    pub(crate) store: Arc<SQLitePoolStore>,
    pub(crate) backing: SQLitePoolBacking,
    pub(crate) options: SQLitePoolOptions,
    pub(crate) proof: Arc<Continuity>,
    directory: tempfile::TempDir,
}
impl StoreFixture {
    pub(crate) fn new(fixture: &Fixture) -> Self {
        Self::with_authority(fixture, None)
    }
    pub(crate) fn with_authority(fixture: &Fixture, authority: Option<&str>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(directory.path())
            .unwrap()
            .join("pool.sqlite");
        let admission = fixture.reserve().unwrap();
        let facts = admission.pool.as_ref().unwrap();
        let proof = Arc::new(Continuity::default());
        let options = SQLitePoolOptions {
            identity: SQLitePoolIdentity {
                authority: authority.unwrap_or(&facts.authority).to_owned(),
                store_id: [61; 32],
                generation: 1,
            },
            continuity: proof.clone(),
            bindings: vec![SQLitePoolBinding {
                tenant: facts.tenant.clone(),
                issuer: facts.issuer,
            }],
            create: true,
        };
        let backing = fixture
            .environment
            .sqlite_pool_backing(
                path,
                SQLitePoolLimits {
                    max_pages: 64,
                    max_records: 8,
                    max_record_bytes: 8192,
                    provider_runtime_bytes: 262_144,
                    disk_overhead_bytes: 65_536,
                },
            )
            .unwrap();
        let store = backing.open(options.clone()).unwrap();
        Self {
            store,
            backing,
            options,
            proof,
            directory,
        }
    }
    pub(crate) fn consume(&self, admission: CredentialAdmission) -> CredentialAdmission {
        self.store.consume(admission, owner()).unwrap()
    }
    pub(crate) fn rows(&self) -> u64 {
        let state = self.store.state.lock().unwrap();
        scalar(
            state.database.as_ref().unwrap(),
            "SELECT count(*) FROM spend",
        )
        .unwrap()
    }
    pub(crate) fn admission_rows(&self) -> u64 {
        let state = self.store.state.lock().unwrap();
        scalar(
            state.database.as_ref().unwrap(),
            "SELECT count(*) FROM admission",
        )
        .unwrap()
    }
    pub(crate) fn reopen(&self) -> Result<Arc<SQLitePoolStore>> {
        let mut options = self.options.clone();
        options.create = false;
        self.backing.open(options)
    }
}
impl Drop for StoreFixture {
    fn drop(&mut self) {
        self.store.close();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = fs::remove_file(sibling(&self.backing.inner.path, suffix));
        }
        self.backing.release_removed().unwrap();
        let _ = &self.directory;
    }
}
fn fixture() -> Fixture {
    Fixture::with_identity(
        ActivationSource::PreauthorizedPool,
        "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
        None,
    )
}
fn owner() -> PoolSpendOwner {
    PoolSpendOwner::new(
        [71; 16],
        1,
        Instant::now() + Duration::from_secs(10),
        CancellationToken::new(),
    )
    .unwrap()
}
#[test]
fn real_transaction_persists_exact_pool_binding_and_reopen_never_activates() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    let admission = store.consume(f.reserve().unwrap());
    let activation = admission.pool_activation.as_ref().unwrap();
    activation.check().unwrap();
    // Equal signed material under a newly reserved account cannot adopt the
    // original successful transaction's continuation.
    assert!(activation.authorize(&f.reserve().unwrap()).is_err());
    {
        let state = store.store.state.lock().unwrap();
        let db = state.database.as_ref().unwrap();
        assert_eq!(scalar::<u64>(db, "SELECT count(*) FROM spend").unwrap(), 1);
        let (source, state, proof): (u64, u64, Vec<u8>) = db
            .query_row("SELECT source,state,projection FROM spend", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!((source, state), (1, 1));
        assert!(proof.windows(f.activation.len()).any(|p| p == f.activation));
        assert_eq!(scalar::<u64>(db, "PRAGMA synchronous").unwrap(), 2);
    }
    assert_eq!(
        store
            .store
            .consume(f.reserve().unwrap(), owner())
            .unwrap_err()
            .code,
        PoolStoreFailure::SpendConflict
    );
    store.store.close();
    assert!(activation.check().is_err());
    let reopened = store.reopen().unwrap();
    assert_eq!(
        reopened
            .consume(f.reserve().unwrap(), owner())
            .unwrap_err()
            .code,
        PoolStoreFailure::SpendConflict
    );
    assert!(activation.check().is_err());
    reopened.close();
}
#[test]
fn concurrent_claims_have_one_original_successful_commit() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    let first = f.reserve().unwrap();
    let second = f.reserve().unwrap();
    let a = store.store.clone();
    let b = store.store.clone();
    let one = std::thread::spawn(move || a.consume(first, owner()));
    let two = std::thread::spawn(move || b.consume(second, owner()));
    let a = one.join().unwrap();
    let b = two.join().unwrap();
    assert!(a.is_ok() != b.is_ok());
    let error = if let Err(e) = a { e } else { b.unwrap_err() };
    assert_eq!(error.code, PoolStoreFailure::SpendConflict);
}
#[test]
fn original_cancel_after_commit_burns_lease_without_continuation() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    let original = owner();
    let canceled = original.cancel.clone();
    let count = store.proof.calls.load(Ordering::Acquire);
    // Consume fences before work and COMMIT, then once after the actual COMMIT.
    *store.proof.cancel.lock().unwrap() = Some((count + 3, canceled));
    let error = store
        .store
        .consume(f.reserve().unwrap(), original)
        .unwrap_err();
    assert_eq!(error.write_state, PoolWriteState::Committed);
    *store.proof.cancel.lock().unwrap() = None;
    assert_eq!(
        store
            .store
            .consume(f.reserve().unwrap(), owner())
            .unwrap_err()
            .code,
        PoolStoreFailure::SpendConflict
    );
}
#[test]
fn missing_independent_history_and_mismatched_owner_refuse_before_consume() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    store.proof.reject.store(true, Ordering::Release);
    let error = store
        .store
        .consume(f.reserve().unwrap(), owner())
        .unwrap_err();
    assert_eq!(error.code, PoolStoreFailure::HistoryUnknown);
    assert_eq!(error.write_state, PoolWriteState::NotSubmitted);
    store.proof.reject.store(false, Ordering::Release);
    let other = fixture();
    assert_eq!(
        store
            .store
            .consume(other.reserve().unwrap(), owner())
            .unwrap_err()
            .code,
        PoolStoreFailure::OwnerUnavailable
    );
    let original = owner();
    original.cancel.cancel();
    assert_eq!(
        store
            .store
            .consume(f.reserve().unwrap(), original)
            .unwrap_err()
            .write_state,
        PoolWriteState::NotSubmitted
    );
    assert!(store.store.consume(f.reserve().unwrap(), owner()).is_ok());
}
#[test]
fn rollback_snapshot_and_schema_substitution_fail_closed() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    store.store.close();
    let snapshot = store.directory.path().join("snapshot.sqlite");
    fs::copy(&store.backing.inner.path, &snapshot).unwrap();
    let reopened = store.reopen().unwrap();
    reopened.close();
    fs::copy(&snapshot, &store.backing.inner.path).unwrap();
    assert_eq!(
        store.reopen().unwrap_err().code,
        PoolStoreFailure::HistoryUnknown
    );
    let db = Connection::open(&store.backing.inner.path).unwrap();
    db.execute_batch("CREATE TABLE unexpected (value TEXT)")
        .unwrap();
    drop(db);
    assert_eq!(
        store.reopen().unwrap_err().code,
        PoolStoreFailure::StorageFormat
    );
}
#[test]
fn persistent_allocation_survives_close_and_environment_closes_real_database() {
    let f = fixture();
    let baseline = f.environment.resource_usage();
    let store = StoreFixture::new(&f);
    let active = f.environment.resource_usage();
    assert!(active.sdk_bytes > baseline.sdk_bytes);
    assert!(active.provider_bytes > baseline.provider_bytes);
    assert!(active.disk_bytes > baseline.disk_bytes);
    assert!(store.backing.release_removed().is_err());
    let runtime = store.backing.inner.limits.runtime().unwrap();
    store.store.close();
    assert!(store.store.cleanup_complete());
    let closed = f.environment.resource_usage();
    assert_eq!(closed.sdk_bytes, active.sdk_bytes - 32_768);
    assert_eq!(closed.provider_bytes, active.provider_bytes - runtime);
    assert_eq!(closed.disk_bytes, active.disk_bytes);
    assert_eq!(closed.native_handles, active.native_handles - 4);
    assert!(store.backing.retained_disk_bytes() > 0);
    let reopened = store.reopen().unwrap();
    let activation = reopened.consume(f.reserve().unwrap(), owner()).unwrap();
    store.backing.inner.environment.close();
    assert!(reopened.cleanup_complete());
    assert!(activation.pool_activation.unwrap().check().is_err());
    assert!(store.backing.retained_disk_bytes() > 0);
}
#[test]
fn wrong_manifest_limits_and_symlink_are_never_reinterpreted_as_empty_history() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    store.store.close();
    let db = Connection::open(&store.backing.inner.path).unwrap();
    db.execute("UPDATE manifest SET max_records=max_records+1", [])
        .unwrap();
    drop(db);
    assert_eq!(
        store.reopen().unwrap_err().code,
        PoolStoreFailure::StorageFormat
    );
    #[cfg(unix)]
    {
        fs::remove_file(&store.backing.inner.path).unwrap();
        std::os::unix::fs::symlink("missing-original", &store.backing.inner.path).unwrap();
        assert_eq!(
            store.reopen().unwrap_err().code,
            PoolStoreFailure::StorageUnavailable
        );
    }
}
