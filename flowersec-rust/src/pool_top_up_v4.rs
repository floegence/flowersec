//! Durable local TopUp intent, Applied material and acknowledgement facts.
//! This journal shares the pool's fixed SQLite backing and original epoch fence.
use super::*;

pub(crate) const SOURCE: &str = "CREATE TABLE top_up_source (tenant TEXT NOT NULL, incarnation BLOB NOT NULL CHECK(length(incarnation)=16), generation BLOB NOT NULL CHECK(length(generation)=8), next_sequence BLOB NOT NULL CHECK(length(next_sequence)=8), artifact_frontier BLOB NOT NULL CHECK(length(artifact_frontier)=8), PRIMARY KEY(tenant,incarnation)) STRICT, WITHOUT ROWID";
pub(crate) const PENDING: &str = "CREATE TABLE top_up_pending (tenant TEXT NOT NULL, incarnation BLOB NOT NULL CHECK(length(incarnation)=16), operation BLOB NOT NULL CHECK(length(operation)=16), request BLOB NOT NULL CHECK(length(request) BETWEEN 1 AND 524288), request_digest BLOB NOT NULL CHECK(length(request_digest)=32), identity_digest BLOB NOT NULL CHECK(length(identity_digest)=32), created_generation BLOB NOT NULL CHECK(length(created_generation)=8 AND created_generation<>zeroblob(8)), generation BLOB NOT NULL CHECK(length(generation)=8), state INTEGER NOT NULL CHECK(state BETWEEN 1 AND 4), response BLOB, applied_entries BLOB CHECK(applied_entries IS NULL OR length(applied_entries) BETWEEN 1 AND 1024), terminal TEXT, PRIMARY KEY(tenant,incarnation)) STRICT, WITHOUT ROWID";
pub(crate) const MATERIAL: &str = "CREATE TABLE top_up_material (tenant TEXT NOT NULL, incarnation BLOB NOT NULL CHECK(length(incarnation)=16), sequence BLOB NOT NULL CHECK(length(sequence)=8), expiry BLOB NOT NULL CHECK(length(expiry)=8), artifact_digest BLOB NOT NULL CHECK(length(artifact_digest)=32), material BLOB NOT NULL CHECK(length(material) BETWEEN 1 AND 65536), PRIMARY KEY(tenant,incarnation,sequence)) STRICT, WITHOUT ROWID";

#[derive(Clone)]
pub(crate) struct JournalRecord {
    pub(crate) operation: [u8; 16],
    pub(crate) request: Vec<u8>,
    pub(crate) digest: [u8; 32],
    pub(crate) identity: [u8; 32],
    pub(crate) created_generation: u64,
    pub(crate) generation: u64,
    pub(crate) state: u8,
    pub(crate) response: Option<Vec<u8>>,
    pub(crate) applied_entries: Option<Vec<u8>>,
    pub(crate) terminal: Option<String>,
}
impl Drop for JournalRecord {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.request.zeroize();
        if let Some(response) = &mut self.response {
            response.zeroize();
        }
    }
}
pub(crate) struct JournalSource {
    pub(crate) _generation: u64,
    pub(crate) next: u64,
    pub(crate) frontier: u64,
    pub(crate) record: Option<JournalRecord>,
}
pub(crate) struct InstalledMaterial {
    pub(crate) sequence: u64,
    pub(crate) expiry: u64,
    pub(crate) artifact: [u8; 32],
    pub(crate) bytes: Vec<u8>,
}
impl Drop for InstalledMaterial {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}
impl SQLitePoolStore {
    fn top_up_transaction<T>(&self, action: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        self.top_up_transaction_fenced(action, || Ok(()))
    }
    fn top_up_transaction_fenced<T>(
        &self,
        action: impl FnOnce(&Connection) -> Result<T>,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<T> {
        if self.relay_format {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        let mut state = self.state.lock().expect("original pool TopUp transaction");
        self.check(&mut state)?;
        self.fence(&state)?;
        let db = state
            .database
            .as_ref()
            .ok_or(fail(PoolStoreFailure::Closed))?;
        db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.fence(&state)?;
            let result = action(db)?;
            self.continuity.check(&self.identity, state.epoch, false)?;
            if self.closed.load(Ordering::Acquire) || self.backing.environment.is_closed() {
                return Err(fail(PoolStoreFailure::Closed));
            }
            before_commit()?;
            db.execute_batch("COMMIT").map_err(|_| PoolStoreError {
                code: PoolStoreFailure::HistoryUnknown,
                write_state: PoolWriteState::Unknown,
                format: None,
            })?;
            Ok(result)
        })();
        let result = result.map_err(|mut error| {
            let rollback_failed = db.execute_batch("ROLLBACK").is_err();
            if rollback_failed || error.write_state == PoolWriteState::Unknown {
                // A failed rollback or uncertain COMMIT retires this original
                // store gate. Never expose the transaction as reusable history.
                self.closed.store(true, Ordering::Release);
                error.write_state = PoolWriteState::Unknown;
            }
            error
        });
        if self.closed.load(Ordering::Acquire) {
            self.cleanup(&mut state);
        }
        result
    }
    pub(crate) fn top_up_source(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
        create: bool,
    ) -> Result<JournalSource> {
        self.top_up_transaction(|db| {
            let old: Option<Vec<u8>> = db
                .query_row(
                    "SELECT generation FROM top_up_source WHERE tenant=? AND incarnation=?",
                    params![tenant, source],
                    |r| r.get(0),
                )
                .optional()?;
            match old {
                Some(old) => {
                    let current = read_u64(old)?;
                    if current > generation {
                        return Err(fail(PoolStoreFailure::Fenced));
                    }
                    if current < generation {
                        // A newer trusted owner may advance the durable fence only
                        // when the previous operation has no unfinished claim.
                        // Pending or installed work remains takeover-fenced and
                        // must use top_up_takeover with its original operation and
                        // digest; terminal history and an empty journal are safe
                        // boundaries for an atomic monotonic owner advance.
                        let record = journal_source(db, tenant, source)?.record;
                        if record.as_ref().is_none_or(|record| record.state >= 3) {
                            db.execute(
                                "UPDATE top_up_source SET generation=? WHERE tenant=? AND incarnation=?",
                                params![generation.to_be_bytes(), tenant, source],
                            )?;
                        }
                    }
                }
                None if create => {
                    let count: u64 = scalar(db, "SELECT count(*) FROM top_up_source")?;
                    if count >= 8 {
                        return Err(fail(PoolStoreFailure::Capacity));
                    }
                    db.execute(
                        "INSERT INTO top_up_source VALUES(?,?,?,?,?)",
                        params![
                            tenant,
                            source,
                            generation.to_be_bytes(),
                            1u64.to_be_bytes(),
                            0u64.to_be_bytes()
                        ],
                    )?;
                }
                None => return Err(fail(PoolStoreFailure::HistoryUnknown)),
            }
            journal_source(db, tenant, source)
        })
    }
    pub(crate) fn top_up_takeover(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
        operation: &[u8; 16],
        digest: &[u8; 32],
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.top_up_transaction_fenced(
            |db| {
                let current: Vec<u8> = db.query_row(
                    "SELECT generation FROM top_up_source WHERE tenant=? AND incarnation=?",
                    params![tenant, source],
                    |row| row.get(0),
                )?;
                if read_u64(current)? > generation {
                    return Err(fail(PoolStoreFailure::Fenced));
                }
                let pending = journal_source(db, tenant, source)?
                    .record
                    .ok_or(fail(PoolStoreFailure::HistoryUnknown))?;
                if pending.operation != *operation
                    || pending.digest != *digest
                    || pending.state >= 3
                {
                    return Err(fail(PoolStoreFailure::SpendConflict));
                }
                if pending.created_generation == 0
                    || (pending.generation != 0
                        && (pending.generation < pending.created_generation
                            || pending.generation > generation))
                {
                    return Err(fail(PoolStoreFailure::StorageFormat));
                }
                // Takeover advances only the local owner fence. The pending
                // record's generation is the authority-authenticated original
                // submission generation and remains unknown until a verified
                // response binds it.
                db.execute(
                    "UPDATE top_up_source SET generation=? WHERE tenant=? AND incarnation=?",
                    params![generation.to_be_bytes(), tenant, source],
                )?;
                Ok(())
            },
            before_commit,
        )
    }
    pub(crate) fn top_up_begin(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
        record: &JournalRecord,
    ) -> Result<()> {
        self.top_up_transaction(|db| {
            require_generation(db, tenant, source, generation)?;
            let current = journal_source(db, tenant, source)?;
            if current.record.as_ref().is_some_and(|old| old.state < 3) {
                return Err(fail(PoolStoreFailure::SpendConflict));
            }
            let sequence = u64::from_be_bytes(
                record.operation[..8]
                    .try_into()
                    .map_err(|_| fail(PoolStoreFailure::StorageFormat))?,
            );
            let next = sequence
                .checked_add(1)
                .ok_or(fail(PoolStoreFailure::Capacity))?;
            if sequence != current.next
                || record.created_generation != generation
                || record.created_generation == 0
                || record.generation != 0
                || record.state != 1
                || record.request.len() > self.backing.limits.max_record_bytes as usize
            {
                return Err(fail(PoolStoreFailure::SpendConflict));
            }
            db.execute(
                "DELETE FROM top_up_pending WHERE tenant=? AND incarnation=?",
                params![tenant, source],
            )?;
            db.execute(
                "INSERT INTO top_up_pending VALUES(?,?,?,?,?,?,?,?,1,NULL,NULL,NULL)",
                params![
                    tenant,
                    source,
                    record.operation,
                    record.request,
                    record.digest,
                    record.identity,
                    record.created_generation.to_be_bytes(),
                    record.generation.to_be_bytes(),
                ],
            )?;
            db.execute(
                "UPDATE top_up_source SET next_sequence=? WHERE tenant=? AND incarnation=?",
                params![next.to_be_bytes(), tenant, source],
            )?;
            Ok(())
        })
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "One transaction compares the original operation, digest and generation before the guarded durable commit."
    )]
    pub(crate) fn top_up_install(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
        operation: &[u8; 16],
        digest: &[u8; 32],
        original_generation: u64,
        response: &[u8],
        applied_entries: &[u8],
        frontier: u64,
        material: &[InstalledMaterial],
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.top_up_transaction_fenced(|db| {
            require_generation(db, tenant, source, generation)?;
            let current = journal_source(db, tenant, source)?;
            let pending = current.record.ok_or(fail(PoolStoreFailure::HistoryUnknown))?;
            let desired_count = crate::top_up_v4::intent(&pending.request)
                .map_err(|_| fail(PoolStoreFailure::HistoryUnknown))?.options.desired_count;
            if pending.operation != *operation || pending.digest != *digest || pending.state != 1
                || pending.created_generation == 0
                || original_generation == 0
                || original_generation < pending.created_generation
                || original_generation > generation
                || (pending.generation != 0 && pending.generation != original_generation)
                || material.len() != usize::from(desired_count) || material.is_empty() || material.len() > 4
                || applied_entries.is_empty() || applied_entries.len() > 1024 || response.len() > self.backing.limits.max_record_bytes as usize { return Err(fail(PoolStoreFailure::SpendConflict)); }
            let top_up_material: u64 = scalar(db, "SELECT count(*) FROM top_up_material")?;
            let total: u64 = scalar(db, "SELECT spend_rows+winner_rows+admission_rows+(SELECT count(*) FROM top_up_material) FROM manifest WHERE id=1")?;
            if top_up_material.checked_add(material.len() as u64).is_none_or(|count| count > 128)
                || total.checked_add(material.len() as u64).is_none_or(|count| count > u64::from(self.backing.limits.max_records)) {
                return Err(fail(PoolStoreFailure::Capacity));
            }
            for item in material {
                if item.bytes.len() > self.backing.limits.max_record_bytes as usize {
                    return Err(fail(PoolStoreFailure::Capacity));
                }
                db.execute("INSERT INTO top_up_material VALUES(?,?,?,?,?,?)", params![tenant, source, item.sequence.to_be_bytes(), item.expiry.to_be_bytes(), item.artifact, item.bytes])?;
            }
            if db.execute("UPDATE top_up_pending SET generation=?,state=2,response=?,applied_entries=? WHERE tenant=? AND incarnation=? AND operation=? AND request_digest=? AND state=1",
                params![original_generation.to_be_bytes(), response, applied_entries, tenant, source, operation, digest])? != 1 {
                return Err(fail(PoolStoreFailure::SpendConflict));
            }
            if db.execute("UPDATE top_up_source SET artifact_frontier=? WHERE tenant=? AND incarnation=?", params![frontier.to_be_bytes(), tenant, source])? != 1 {
                return Err(fail(PoolStoreFailure::HistoryUnknown));
            }
            Ok(())
        }, before_commit)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "One transaction compares the original operation, digest and generation before the guarded durable commit."
    )]
    pub(crate) fn top_up_finish(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
        operation: &[u8; 16],
        digest: &[u8; 32],
        terminal: Option<&str>,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.top_up_transaction_fenced(|db| {
            require_generation(db, tenant, source, generation)?;
            let (next_state, first_state, last_state) = match terminal {
                None => (3, 2, 2),
                Some("top_up_request_expired") => (4, 1, 1),
                Some("source_reset_required") => (4, 1, 2),
                Some("capacity_exhausted")
                | Some("configuration_capacity")
                | Some("relink_required")
                | Some("spent_unknown") => (4, 1, 1),
                _ => return Err(fail(PoolStoreFailure::SpendConflict)),
            };
            // Terminal authority retirement preserves response, Applied
            // history, material rows and the installed artifact frontier.
            if db.execute("UPDATE top_up_pending SET generation=CASE WHEN generation=zeroblob(8) THEN ? ELSE generation END,state=?,terminal=? WHERE tenant=? AND incarnation=? AND operation=? AND request_digest=? AND state BETWEEN ? AND ?",
                params![generation.to_be_bytes(), next_state, terminal, tenant, source, operation, digest, first_state, last_state])? != 1 {
                return Err(fail(PoolStoreFailure::SpendConflict));
            }
            Ok(())
        }, before_commit)
    }
    pub(crate) fn top_up_materials(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
    ) -> Result<Vec<InstalledMaterial>> {
        self.top_up_transaction(|db| {
            require_generation(db, tenant, source, generation)?;
            let mut statement = db.prepare("SELECT sequence,expiry,artifact_digest,material FROM top_up_material WHERE tenant=? AND incarnation=? ORDER BY sequence LIMIT 129")?;
            let rows = statement.query_map(params![tenant, source], |r| Ok((r.get::<_, Vec<u8>>(0)?,r.get::<_, Vec<u8>>(1)?,r.get::<_, Vec<u8>>(2)?,r.get::<_, Vec<u8>>(3)?)))?;
            let mut items = Vec::new();
            for row in rows {
                let (sequence, expiry, artifact, bytes) = row?;
                if items.len() == 128 { return Err(fail(PoolStoreFailure::StorageFormat)); }
                items.push(InstalledMaterial { sequence: read_u64(sequence)?, expiry: read_u64(expiry)?,
                    artifact: artifact.try_into().map_err(|_| fail(PoolStoreFailure::StorageFormat))?, bytes });
            }
            Ok(items)
        })
    }
    pub(crate) fn top_up_consume(
        &self,
        tenant: &str,
        source: &[u8; 16],
        generation: u64,
        artifact: &[u8; 32],
    ) -> Result<()> {
        self.top_up_transaction(|db| {
            require_generation(db, tenant, source, generation)?;
            if db.execute("DELETE FROM top_up_material WHERE tenant=? AND incarnation=? AND artifact_digest=?", params![tenant, source, artifact])? != 1 {
                return Err(fail(PoolStoreFailure::SpendConflict));
            }
            Ok(())
        })
    }
}
fn require_generation(
    db: &Connection,
    tenant: &str,
    source: &[u8; 16],
    generation: u64,
) -> Result<()> {
    let current: Option<Vec<u8>> = db
        .query_row(
            "SELECT generation FROM top_up_source WHERE tenant=? AND incarnation=?",
            params![tenant, source],
            |r| r.get(0),
        )
        .optional()?;
    if current.map(read_u64).transpose()? != Some(generation) {
        return Err(fail(PoolStoreFailure::Fenced));
    }
    Ok(())
}
fn journal_source(db: &Connection, tenant: &str, source: &[u8; 16]) -> Result<JournalSource> {
    let (generation, next, frontier): (Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row("SELECT generation,next_sequence,artifact_frontier FROM top_up_source WHERE tenant=? AND incarnation=?", params![tenant,source], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let record = db.query_row("SELECT operation,request,request_digest,identity_digest,created_generation,generation,state,response,applied_entries,terminal FROM top_up_pending WHERE tenant=? AND incarnation=?", params![tenant, source], |r|
        Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,u8>(6)?,r.get::<_,Option<Vec<u8>>>(7)?,r.get::<_,Option<Vec<u8>>>(8)?,r.get::<_,Option<String>>(9)?))).optional()?;
    let record = record
        .map(
            |(
                operation,
                request,
                digest,
                identity,
                created_generation,
                generation,
                state,
                response,
                applied_entries,
                terminal,
            )|
             -> Result<JournalRecord> {
                Ok(JournalRecord {
                    operation: operation
                        .try_into()
                        .map_err(|_| fail(PoolStoreFailure::StorageFormat))?,
                    request,
                    digest: digest
                        .try_into()
                        .map_err(|_| fail(PoolStoreFailure::StorageFormat))?,
                    identity: identity
                        .try_into()
                        .map_err(|_| fail(PoolStoreFailure::StorageFormat))?,
                    created_generation: read_u64(created_generation)?,
                    generation: read_u64(generation)?,
                    state,
                    response,
                    applied_entries,
                    terminal,
                })
            },
        )
        .transpose()?;
    Ok(JournalSource {
        _generation: read_u64(generation)?,
        next: read_u64(next)?,
        frontier: read_u64(frontier)?,
        record,
    })
}

// Startup accepts retained Applied facts only for authenticated authority
// retirement, and rechecks the complete immutable request/Ack/history binding.
pub(crate) fn validate_terminal_applied(db: &Connection) -> Result<()> {
    let mut statement = db.prepare(
        "SELECT tenant,incarnation FROM top_up_pending WHERE state=4 AND response IS NOT NULL",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (tenant, source) = row?;
        let source: [u8; 16] = source
            .try_into()
            .map_err(|_| fail(PoolStoreFailure::StorageFormat))?;
        let snapshot = journal_source(db, &tenant, &source)?;
        let record = snapshot
            .record
            .ok_or(fail(PoolStoreFailure::StorageFormat))?;
        if record.terminal.as_deref() != Some("source_reset_required") {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
        crate::top_up_v4::validate_applied_record(&record, &tenant, &source, snapshot.frontier)
            .map_err(|_| fail(PoolStoreFailure::StorageFormat))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod terminal_tests {
    use super::*;
    use crate::namespace_v4::verifier::credential::tests::Fixture;
    use crate::pool_v4::tests::StoreFixture;

    fn fixture() -> (Fixture, StoreFixture) {
        let environment = Fixture::with_identity(
            crate::codec_v4::ActivationSource::PreauthorizedPool,
            "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
            None,
        );
        let store = StoreFixture::new(&environment);
        (environment, store)
    }

    pub(crate) fn seed_installed(
        store: &SQLitePoolStore,
        tenant: &str,
        source: &[u8; 16],
    ) -> JournalRecord {
        let original = crate::top_up_v4::applied_record_fixture(tenant, *source);
        let mut pending = original.clone();
        pending.state = 1;
        pending.response = None;
        pending.applied_entries = None;
        pending.generation = 0;
        store.top_up_source(tenant, source, 1, true).unwrap();
        store.top_up_begin(tenant, source, 1, &pending).unwrap();
        // Seed a canonical Installed snapshot to isolate terminal CAS and
        // startup binding validation from signed-material installation.
        store.top_up_transaction(|db| {
            db.execute(
                "UPDATE top_up_pending SET generation=?,state=2,response=?,applied_entries=? WHERE tenant=? AND incarnation=?",
                params![original.generation.to_be_bytes(), original.response, original.applied_entries, tenant, source],
            )?;
            db.execute(
                "INSERT INTO top_up_material VALUES(?,?,?,?,?,?)",
                params![tenant, source, 1u64.to_be_bytes(), 2000u64.to_be_bytes(), [45u8; 32], b"original material".as_slice()],
            )?;
            db.execute(
                "UPDATE top_up_source SET artifact_frontier=? WHERE tenant=? AND incarnation=?",
                params![1u64.to_be_bytes(), tenant, source],
            )?;
            Ok(())
        }).unwrap();
        original
    }

    #[test]
    fn installed_authority_reset_persists_without_erasing_applied_material() {
        let (_environment, fixture) = fixture();
        let tenant = &fixture.options.bindings[0].tenant;
        let source = [41; 16];
        let original = seed_installed(&fixture.store, tenant, &source);
        let operation = original.operation;
        let digest = original.digest;
        for code in [
            "source_unavailable",
            "source_contract_invalid",
            "top_up_request_expired",
        ] {
            let error = fixture
                .store
                .top_up_finish(tenant, &source, 1, &operation, &digest, Some(code), || {
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.code, PoolStoreFailure::SpendConflict);
            let snapshot = fixture
                .store
                .top_up_source(tenant, &source, 1, false)
                .unwrap();
            assert_eq!(snapshot.record.unwrap().state, 2);
        }
        let error = fixture
            .store
            .top_up_finish(
                tenant,
                &source,
                1,
                &operation,
                &digest,
                Some("source_reset_required"),
                || Err(fail(PoolStoreFailure::Fenced)),
            )
            .unwrap_err();
        assert_eq!(error.code, PoolStoreFailure::Fenced);
        assert_eq!(
            fixture
                .store
                .top_up_source(tenant, &source, 1, false)
                .unwrap()
                .record
                .unwrap()
                .state,
            2,
        );
        fixture
            .store
            .top_up_finish(
                tenant,
                &source,
                1,
                &operation,
                &digest,
                Some("source_reset_required"),
                || Ok(()),
            )
            .unwrap();
        fixture.store.close();
        let reopened = fixture.reopen().unwrap();
        let snapshot = reopened.top_up_source(tenant, &source, 1, false).unwrap();
        assert_eq!(snapshot.frontier, 1);
        assert_eq!(snapshot.next, 2);
        let terminal = snapshot.record.unwrap();
        assert_eq!(terminal.state, 4);
        assert_eq!(terminal.terminal.as_deref(), Some("source_reset_required"));
        assert_eq!(terminal.response, original.response);
        assert_eq!(terminal.applied_entries, original.applied_entries);
        let materials = reopened.top_up_materials(tenant, &source, 1).unwrap();
        assert_eq!(materials.len(), 1);
        assert_eq!(materials[0].sequence, 1);
        assert_eq!(materials[0].bytes.as_slice(), b"original material");
        reopened.close();
    }

    #[test]
    fn pending_authoritative_terminal_reopens_without_applied_fields() {
        for code in ["top_up_request_expired", "source_reset_required"] {
            let (_environment, fixture) = fixture();
            let tenant = &fixture.options.bindings[0].tenant;
            let source = [41; 16];
            let mut original = crate::top_up_v4::applied_record_fixture(tenant, source);
            original.state = 1;
            original.response = None;
            original.applied_entries = None;
            original.generation = 0;
            fixture
                .store
                .top_up_source(tenant, &source, 1, true)
                .unwrap();
            fixture
                .store
                .top_up_begin(tenant, &source, 1, &original)
                .unwrap();
            fixture
                .store
                .top_up_finish(
                    tenant,
                    &source,
                    1,
                    &original.operation,
                    &original.digest,
                    Some(code),
                    || Ok(()),
                )
                .unwrap();
            fixture.store.close();
            let reopened = fixture.reopen().unwrap();
            let terminal = reopened
                .top_up_source(tenant, &source, 1, false)
                .unwrap()
                .record
                .unwrap();
            assert_eq!(terminal.state, 4);
            assert_eq!(terminal.terminal.as_deref(), Some(code));
            assert!(terminal.response.is_none());
            assert!(terminal.applied_entries.is_none());
            reopened.close();
        }
    }

    #[test]
    fn terminal_applied_reopen_rejects_missing_or_inconsistent_history() {
        for corruption in [
            "missing_response",
            "missing_applied",
            "wrong_terminal",
            "wrong_request_digest",
            "wrong_ack_digest",
            "invalid_applied",
            "wrong_identity",
            "wrong_frontier",
        ] {
            let (_environment, fixture) = fixture();
            let tenant = &fixture.options.bindings[0].tenant;
            let source = [41; 16];
            let original = seed_installed(&fixture.store, tenant, &source);
            fixture
                .store
                .top_up_finish(
                    tenant,
                    &source,
                    1,
                    &original.operation,
                    &original.digest,
                    Some("source_reset_required"),
                    || Ok(()),
                )
                .unwrap();
            fixture
                .store
                .top_up_transaction(|db| {
                    match corruption {
                        "missing_response" => {
                            db.execute("UPDATE top_up_pending SET response=NULL", [])?;
                        }
                        "missing_applied" => {
                            db.execute("UPDATE top_up_pending SET applied_entries=NULL", [])?;
                        }
                        "wrong_terminal" => {
                            db.execute(
                                "UPDATE top_up_pending SET terminal='top_up_request_expired'",
                                [],
                            )?;
                        }
                        "wrong_request_digest" => {
                            db.execute(
                                "UPDATE top_up_pending SET request_digest=?",
                                params![[48u8; 32]],
                            )?;
                        }
                        "wrong_ack_digest" => {
                            let mut ack = original.response.clone().unwrap();
                            let offset = ack
                                .windows(32)
                                .position(|bytes| bytes == [47u8; 32])
                                .unwrap();
                            ack[offset..offset + 32].fill(48);
                            db.execute("UPDATE top_up_pending SET response=?", params![ack])?;
                        }
                        "invalid_applied" => {
                            db.execute(
                                "UPDATE top_up_pending SET applied_entries=?",
                                params![vec![0x80u8]],
                            )?;
                        }
                        "wrong_identity" => {
                            db.execute(
                                "UPDATE top_up_pending SET identity_digest=?",
                                params![[48u8; 32]],
                            )?;
                        }
                        "wrong_frontier" => {
                            db.execute("DELETE FROM top_up_material", [])?;
                            db.execute(
                                "UPDATE top_up_source SET artifact_frontier=?",
                                params![0u64.to_be_bytes()],
                            )?;
                        }
                        _ => unreachable!(),
                    }
                    Ok(())
                })
                .unwrap();
            fixture.store.close();
            let error = fixture.reopen().unwrap_err();
            assert_eq!(error.code, PoolStoreFailure::StorageFormat, "{corruption}");
        }
    }
}
