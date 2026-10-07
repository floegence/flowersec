use super::*;
use crate::namespace_v4::verifier::credential::tests::Fixture;
use crate::sqlite_application_format_v4::tests::snapshot;
use std::sync::atomic::AtomicU64;
#[derive(Debug, Default)]
pub(crate) struct Continuity {
    reject: AtomicBool,
    unavailable: AtomicBool,
    epoch: AtomicU64,
    calls: AtomicU64,
    cancel: Mutex<Option<(u64, CancellationToken)>>,
}
impl Continuity {
    pub(crate) fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::Release);
    }
    pub(crate) fn cancel_after_checks(&self, checks: u64, cancel: CancellationToken) {
        let target = self.calls.load(Ordering::Acquire) + checks;
        *self.cancel.lock().unwrap() = Some((target, cancel));
    }
}
impl SQLitePoolContinuity for Continuity {
    fn check(&self, _: &SQLitePoolIdentity, epoch: u64, provisioning: bool) -> Result<()> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(fail(PoolStoreFailure::StorageUnavailable));
        }
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
    pub(crate) fn admitted_count(&self) -> u64 {
        let state = self.store.state.lock().unwrap();
        scalar(
            state.database.as_ref().unwrap(),
            "SELECT count(*) FROM admission WHERE state=1",
        )
        .unwrap()
    }
    pub(crate) fn winner_count(&self) -> u64 {
        let state = self.store.state.lock().unwrap();
        scalar(
            state.database.as_ref().unwrap(),
            "SELECT count(*) FROM parent_winner",
        )
        .unwrap()
    }

    pub(crate) fn new(fixture: &Fixture) -> Self {
        Self::with_authority(fixture, None)
    }
    pub(crate) fn with_authority(fixture: &Fixture, authority: Option<&str>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = fs::canonicalize(directory.path())
            .unwrap()
            .join("pool.sqlite");
        let admission = fixture.reserve().unwrap();
        let artifact = crate::codec_v4::decode(
            &fixture.artifact,
            "Artifact",
            crate::codec_v4::Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
        )
        .unwrap();
        let tenant = artifact
            .field("Artifact", "tenant_id")
            .unwrap()
            .text()
            .unwrap()
            .to_owned();
        let issuer = artifact.b("Artifact", "issuer_key_id").unwrap();
        let authority = authority
            .map(str::to_owned)
            .or_else(|| admission.pool.as_ref().map(|facts| facts.authority.clone()))
            .expect("live store requires its installed authority");
        let proof = Arc::new(Continuity::default());
        let options = SQLitePoolOptions {
            identity: SQLitePoolIdentity {
                authority,
                store_id: [61; 32],
                generation: 1,
            },
            continuity: proof.clone(),
            bindings: vec![SQLitePoolBinding { tenant, issuer }],
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
    let admission = f.reserve().unwrap();
    let expected = PoolSpendObservation {
        state: PoolSpendState::CommitKnown,
        artifact_digest: admission.artifact_digest,
        activation_digest: admission.activation_digest,
        attempt_id: admission.attempt_id,
    };
    let error = store.store.consume(admission, original).unwrap_err();
    assert_eq!(error.write_state, PoolWriteState::Committed);
    assert_eq!(store.store.spend_observation(), Some(expected));
    assert_eq!(store.rows(), 1);
    let connection = crate::TransportConnectError::from(error);
    assert!(matches!(connection, crate::TransportConnectError::Pool(actual) if actual == error));
    let facts = connection.connection_facts();
    assert_eq!(facts.spend_state, crate::ConnectionSpendState::Spent);
    assert_eq!(
        facts.admission_state,
        crate::ConnectionAdmissionState::NotStarted
    );
    assert_eq!(facts.phase, crate::ConnectionPhase::SpentNotAdmitted);
    assert_eq!(
        facts.source_profile,
        Some(crate::ConnectionSourceProfile::PreauthorizedPool)
    );
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
fn actual_commit_failure_preserves_unknown_spend_without_a_continuation() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    {
        let state = store.store.state.lock().unwrap();
        // A connection-local deferred constraint fails the production COMMIT,
        // after the real INSERT and before any activation can be returned. The
        // temporary objects disappear with this retired SQLite connection.
        state.database.as_ref().unwrap().execute_batch(
            "CREATE TEMP TABLE consume_parent (id INTEGER PRIMARY KEY);
             CREATE TEMP TABLE consume_child (id INTEGER REFERENCES consume_parent(id) DEFERRABLE INITIALLY DEFERRED);
             CREATE TEMP TRIGGER consume_commit_failure AFTER INSERT ON main.spend BEGIN INSERT INTO consume_child VALUES(1); END;"
        ).unwrap();
    }
    let admission = f.reserve().unwrap();
    let expected = PoolSpendObservation {
        state: PoolSpendState::Unknown,
        artifact_digest: admission.artifact_digest,
        activation_digest: admission.activation_digest,
        attempt_id: admission.attempt_id,
    };
    let error = store.store.consume(admission, owner()).unwrap_err();
    assert_eq!(error.code, PoolStoreFailure::SpentUnknown);
    assert_eq!(error.write_state, PoolWriteState::Unknown);
    assert_eq!(store.store.spend_observation(), Some(expected));
    assert!(store.store.cleanup_complete());
    let connection = crate::TransportConnectError::from(error);
    assert!(matches!(connection, crate::TransportConnectError::Pool(actual) if actual == error));
    let facts = connection.connection_facts();
    assert_eq!(facts.phase, crate::ConnectionPhase::Unknown);
    assert_eq!(facts.spend_state, crate::ConnectionSpendState::Unknown);
    assert_eq!(
        facts.admission_state,
        crate::ConnectionAdmissionState::NotStarted
    );
    assert_eq!(
        facts.network_ready,
        crate::ConnectionNetworkReady::NotStarted
    );
    assert_eq!(
        facts.source_profile,
        Some(crate::ConnectionSourceProfile::PreauthorizedPool)
    );
    assert_eq!(
        store
            .store
            .consume(f.reserve().unwrap(), owner())
            .unwrap_err()
            .code,
        PoolStoreFailure::Closed
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
    assert_eq!(store.store.spend_observation(), None);
    assert_eq!(store.rows(), 0);
    let facts = crate::TransportConnectError::from(error).connection_facts();
    assert_eq!(facts.spend_state, crate::ConnectionSpendState::Unspent);
    assert_eq!(facts.phase, crate::ConnectionPhase::NotStarted);
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
fn format_refusals_keep_bounded_header_evidence_without_changing_the_group() {
    for variant in ["older", "future", "identity", "hint", "schema", "corrupt"] {
        let f = fixture();
        let store = StoreFixture::new(&f);
        store.store.close();
        let db = Connection::open(&store.backing.inner.path).unwrap();
        db.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
        db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        if variant == "older" || variant == "future" {
            let revision = if variant == "older" { 2 } else { 4 };
            db.execute_batch("BEGIN IMMEDIATE; ALTER TABLE manifest RENAME TO original_manifest")
                .unwrap();
            db.execute_batch(
                &MANIFEST.replace("CHECK(revision=3)", &format!("CHECK(revision={revision})")),
            )
            .unwrap();
            db.execute(&format!("INSERT INTO manifest SELECT id,format,{revision},authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,spend_rows,winner_rows,admission_rows FROM original_manifest"), []).unwrap();
            // An incompatible revision has no usable current-format records.
            // Refusal must come entirely from its trustworthy fixed header.
            db.execute_batch(&format!("DROP TABLE original_manifest; DROP TABLE spend; CREATE TABLE incompatible_records(value TEXT); PRAGMA user_version={revision}; COMMIT")).unwrap();
        } else {
            db.execute_batch(match variant {
                "identity" => "UPDATE manifest SET authority='different-authority'",
                "hint" => "PRAGMA user_version=4",
                "schema" => "CREATE TABLE unexpected(value TEXT)",
                _ => "DELETE FROM manifest",
            })
            .unwrap();
        }
        db.execute_batch("BEGIN; SELECT name FROM sqlite_schema")
            .unwrap();
        assert!(
            fs::metadata(sibling(&store.backing.inner.path, "-wal"))
                .unwrap()
                .len()
                > 32
        );
        let occupied = snapshot(store.directory.path());
        assert_eq!(
            store.reopen().unwrap_err().code,
            PoolStoreFailure::StorageUnavailable
        );
        assert_eq!(snapshot(store.directory.path()), occupied);
        db.execute_batch("ROLLBACK").unwrap();
        db.close().unwrap();
        let before = snapshot(store.directory.path());
        let checks = store.proof.calls.load(Ordering::Acquire);
        let refusal = store.reopen().unwrap_err();
        assert_eq!(refusal.code, PoolStoreFailure::StorageFormat);
        assert_eq!(refusal.write_state, PoolWriteState::NotSubmitted);
        let projection = refusal.format.expect("fixed storage format projection");
        assert_eq!(projection.code(), "storage_format_incompatible");
        assert_eq!(projection.wire_profile(), "flowersec-v4-transport-security");
        assert_eq!(
            projection.transaction_group,
            StorageFormatTransactionGroup::Pool
        );
        assert_eq!(projection.required_revision, 3);
        assert_eq!(
            projection.required_wire,
            StorageWireFormat::FlowersecV4RustPool
        );
        assert!(!projection.exact_conversion_available());
        assert_eq!(
            (projection.observed_revision, projection.reason),
            match variant {
                "older" => (Some(2), StorageFormatMismatchReason::OlderRevision),
                "future" => (Some(4), StorageFormatMismatchReason::NewerRevision),
                "identity" => (None, StorageFormatMismatchReason::IdentityMismatch),
                "hint" => (None, StorageFormatMismatchReason::RevisionConflict),
                "schema" => (Some(3), StorageFormatMismatchReason::Schema),
                _ => (None, StorageFormatMismatchReason::MissingManifest),
            }
        );
        assert_eq!(
            projection.observed_wire,
            projection
                .observed_revision
                .map(|_| StorageWireFormat::FlowersecV4RustPool)
        );
        assert_eq!(store.proof.calls.load(Ordering::Acquire), checks);
        assert!(
            snapshot(store.directory.path()) == before,
            "refusal changed durable files"
        );
    }
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
fn current_pool_record_preserves_full_width_owner_generation() {
    let f = fixture();
    let store = StoreFixture::new(&f);
    let original = PoolSpendOwner::new(
        [71; 16],
        u64::MAX,
        Instant::now() + Duration::from_secs(10),
        CancellationToken::new(),
    )
    .unwrap();
    let admission = store.store.consume(f.reserve().unwrap(), original).unwrap();
    drop(admission);
    store.store.close();
    let reopened = store.reopen().unwrap();
    reopened.close();
}

#[test]
fn current_pool_record_refuses_detached_projection_changes_without_writing() {
    use crate::codec_v4::tests::{b, t, u};
    for field in [
        0u64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    ] {
        let f = fixture();
        let store = StoreFixture::new(&f);
        let admission = store.consume(f.reserve().unwrap());
        drop(admission);
        store.store.close();
        let db = Connection::open(&store.backing.inner.path).unwrap();
        db.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
            true,
        )
        .unwrap();
        db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        let wire: Vec<u8> = db
            .query_row("SELECT projection FROM spend", [], |row| row.get(0))
            .unwrap();
        let replacement = match field {
            // Owner generation is an opaque nonzero uint64, including MAX.
            // Unlike the store fence, it is not incremented when reopening.
            16 => u(0),
            0 | 2 | 3 | 11 | 20 | 21 | 22 | 23 | 24 | 25 => u(u64::MAX),
            4 | 26 | 27 => t("unrelated.authority"),
            5 | 6 | 14 | 15 => b(&[0; 16]),
            1 | 7 | 9 | 18 => b(&[0; 32]),
            _ => b(&[0]),
        };
        let changed = records::fixtures::alter_map(&wire, field, replacement);
        db.execute("UPDATE spend SET projection=?", [changed])
            .unwrap();
        db.execute_batch("BEGIN; SELECT name FROM sqlite_schema")
            .unwrap();
        assert!(
            fs::metadata(sibling(&store.backing.inner.path, "-wal"))
                .unwrap()
                .len()
                > 32
        );
        let occupied = snapshot(store.directory.path());
        assert_eq!(
            store.reopen().unwrap_err().code,
            PoolStoreFailure::StorageUnavailable
        );
        assert_eq!(snapshot(store.directory.path()), occupied);
        db.execute_batch("ROLLBACK").unwrap();
        db.close().unwrap();
        let before = snapshot(store.directory.path());
        let checks = store.proof.calls.load(Ordering::Acquire);
        let error = store
            .reopen()
            .expect_err(&format!("invalid spend field {field} was accepted"));
        assert_eq!(error.code, PoolStoreFailure::StorageFormat, "field {field}");
        assert_eq!(error.format.unwrap().observed_revision, Some(3));
        assert_eq!(store.proof.calls.load(Ordering::Acquire), checks);
        assert!(
            snapshot(store.directory.path()) == before,
            "refusal changed durable files"
        );
    }
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
    assert_eq!(
        closed.sdk_bytes,
        active.sdk_bytes - 32_768 - records::SCRATCH_BYTES
    );
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
