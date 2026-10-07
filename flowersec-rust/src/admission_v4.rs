//! Trusted server admission over the same protected SQLite owner. Consumer
//! spend, shared parent selection and local admission remain distinct facts.
use super::*;
use crate::codec_v4::{Context, Limits};

pub(super) const WINNER: &str = "CREATE TABLE parent_winner (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8)) STRICT, WITHOUT ROWID";
pub(super) const ADMISSION: &str = "CREATE TABLE admission (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 34 AND 161), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), state INTEGER NOT NULL CHECK(state IN (0,1)), version BLOB NOT NULL CHECK(length(version)=8), fence BLOB NOT NULL CHECK(length(fence)=8), owner BLOB NOT NULL CHECK(length(owner)=40), reservation BLOB NOT NULL CHECK(length(reservation)=32), retained_until BLOB NOT NULL CHECK(length(retained_until)=8)) STRICT, WITHOUT ROWID";

/// Immutable trusted service mapping. The host must preserve this mapping for
/// every issued parent until all retained once obligations have safely ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SQLiteAdmissionBinding {
    pub tenant: String,
    pub issuer: [u8; 16],
    pub server_identity_digest: [u8; 32],
    pub audience: String,
}
/// Explicit trusted server authority. This does not accept a store selected by
/// a peer and cannot convert a consumer's local spend into remote admission.
#[derive(Debug)]
pub struct SQLiteAdmissionAuthority {
    store: Arc<SQLitePoolStore>,
    parent: Arc<SQLitePoolStore>,
    bindings: Vec<SQLiteAdmissionBinding>,
    _charge: EnvironmentCharge,
}
// Shared durable admission facts are never a consumer spend capability.
// Both constructors below consume the original verified credential account.
struct AdmissionFacts<'a> {
    tenant: &'a str,
    issuer: [u8; 16],
    lease: [u8; 16],
    authority: &'a str,
    winner_authority: &'a str,
    proof: &'a [u8],
    selection: &'a [u8],
    route_set: [u8; 32],
    issued_at: u64,
    parent_initiation_end: u64,
    session_end: u64,
    session_nonce: [u8; 32],
}
impl SQLiteAdmissionAuthority {
    pub fn new(
        store: Arc<SQLitePoolStore>,
        parent: Arc<SQLitePoolStore>,
        bindings: Vec<SQLiteAdmissionBinding>,
    ) -> Result<Arc<Self>> {
        if !Arc::ptr_eq(&store.backing.environment, &parent.backing.environment)
            || bindings.is_empty()
            || bindings.len() > 64
        {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        for (i, binding) in bindings.iter().enumerate() {
            let pair = SQLitePoolBinding {
                tenant: binding.tenant.clone(),
                issuer: binding.issuer,
            };
            if !security_id(&binding.tenant)
                || !security_id(&binding.audience)
                || !nonzero(&binding.server_identity_digest)
                || !store.bindings.contains(&pair)
                || !parent.bindings.contains(&pair)
                || bindings[..i].contains(binding)
            {
                return Err(fail(PoolStoreFailure::Configuration));
            }
        }
        let charge = store
            .backing
            .environment
            .reserve_environment(ResourceLimits {
                sdk_bytes: 32768,
                items: bindings.len() as u64 + 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })?;
        Ok(Arc::new(Self {
            store,
            parent,
            bindings,
            _charge: charge,
        }))
    }
    pub(crate) fn belongs_to(&self, root: &Arc<EnvironmentRoot>) -> bool {
        Arc::ptr_eq(&self.store.backing.environment, root)
    }
    pub(crate) fn admit(
        self: &Arc<Self>,
        admission: &CredentialAdmission,
        artifact: &[u8],
        binding: [u8; 32],
        owner: PoolSpendOwner,
    ) -> Result<Admitted> {
        let facts = admission
            .pool
            .as_ref()
            .ok_or(fail(PoolStoreFailure::OwnerUnavailable))?;
        let facts = AdmissionFacts {
            tenant: &facts.tenant,
            issuer: facts.issuer,
            lease: facts.lease,
            authority: &facts.authority,
            winner_authority: &facts.winner_authority,
            proof: &facts.proof,
            selection: &facts.selection,
            route_set: facts.route_set,
            issued_at: facts.issued_at,
            parent_initiation_end: facts.parent_initiation_end,
            session_end: facts.session_end,
            session_nonce: facts.session_nonce,
        };
        if admission.source != ActivationSource::PreauthorizedPool
            || admission.pool_activation.is_some()
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        self.admit_facts(admission, artifact, facts, binding, owner)
    }
    pub(crate) fn admit_live(
        self: &Arc<Self>,
        admission: &CredentialAdmission,
        artifact: &[u8],
        activation: &[u8],
        binding: [u8; 32],
        owner: PoolSpendOwner,
    ) -> Result<Admitted> {
        if admission.source != ActivationSource::LiveAuthority
            || admission.pool.is_some()
            || admission.pool_activation.is_some()
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let configuration = || fail(PoolStoreFailure::Configuration);
        let a = codec::decode_context(
            artifact,
            "Artifact",
            Limits {
                bytes: 65536,
                nodes: 16384,
            },
            None,
            Context::default(),
        )
        .map_err(|_| configuration())?;
        let proof = codec::decode_context(
            activation,
            "ActivationAuthorization",
            Limits {
                bytes: 4096,
                nodes: 4096,
            },
            None,
            Context::with_activation_source(ActivationSource::LiveAuthority),
        )
        .map_err(|_| configuration())?;
        if codec::digest("activation_digest", proof).map_err(|_| configuration())?
            != admission.activation_digest
            || codec::digest("artifact_digest", a).map_err(|_| configuration())?
                != admission.artifact_digest
        {
            return Err(configuration());
        }
        let facts = AdmissionFacts {
            tenant: a
                .field("Artifact", "tenant_id")
                .and_then(codec::Value::text)
                .map_err(|_| configuration())?,
            issuer: a
                .b("Artifact", "issuer_key_id")
                .map_err(|_| configuration())?,
            lease: a.b("Artifact", "lease_id").map_err(|_| configuration())?,
            // The logical authority is a trusted service deployment binding,
            // never an identifier supplied by HELLO or selected by a caller.
            authority: &self.parent.identity.authority,
            winner_authority: &self.parent.identity.authority,
            proof: activation,
            selection: proof
                .field("ActivationAuthorization", "candidate_selection")
                .map_err(|_| configuration())?
                .raw(),
            route_set: admission.route_digest,
            issued_at: proof
                .u("ActivationAuthorization", "issued_at_ms")
                .map_err(|_| configuration())?,
            parent_initiation_end: a
                .u("Artifact", "initiation_not_after_ms")
                .map_err(|_| configuration())?,
            session_end: a
                .u("Artifact", "session_not_after_ms")
                .map_err(|_| configuration())?
                .min(
                    proof
                        .u("ActivationAuthorization", "session_not_after_ms")
                        .map_err(|_| configuration())?,
                ),
            session_nonce: a
                .b("Artifact", "session_nonce")
                .map_err(|_| configuration())?,
        };
        self.admit_facts(admission, artifact, facts, binding, owner)
    }
    fn admit_facts(
        self: &Arc<Self>,
        admission: &CredentialAdmission,
        artifact: &[u8],
        facts: AdmissionFacts<'_>,
        binding: [u8; 32],
        owner: PoolSpendOwner,
    ) -> Result<Admitted> {
        let a = codec::decode_context(
            artifact,
            "Artifact",
            Limits {
                bytes: 65536,
                nodes: 65536,
            },
            None,
            Context::default(),
        )
        .map_err(|_| fail(PoolStoreFailure::Configuration))?;
        let audience = a
            .field("Artifact", "audience")
            .and_then(codec::Value::text)
            .map_err(|_| fail(PoolStoreFailure::Configuration))?;
        if !admission
            .account
            .belongs_to(&self.store.backing.environment)
            || facts.winner_authority != self.parent.identity.authority
            || !self.bindings.iter().any(|b| {
                b.tenant == facts.tenant
                    && b.issuer == facts.issuer
                    && b.server_identity_digest == admission.certificate_digests[1]
                    && b.audience == audience
            })
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let maximum = self
            .store
            .backing
            .limits
            .max_record_bytes
            .min(self.parent.backing.limits.max_record_bytes);
        let charge = admission.account.reserve(ResourceLimits {
            sdk_bytes: u64::from(maximum) * 4 + 4096,
            items: 4,
            work_slots: 2,
            tasks: 1,
            timers: 1,
            ..ResourceLimits::default()
        })?;
        let account = admission.account.clone();
        let cutoff = admission.initiation_not_after_ms;
        let check = || -> Result<()> {
            owner.check()?;
            let time = account.security_time()?;
            if time.lower_ms < facts.issued_at || time.upper_ms >= cutoff {
                return Err(fail(PoolStoreFailure::OwnerUnavailable));
            }
            Ok(())
        };
        check()?;
        let retained = facts
            .parent_initiation_end
            .max(facts.session_end)
            .checked_add(RETENTION)
            .ok_or(fail(PoolStoreFailure::Capacity))?;
        let mut lease = Vec::with_capacity(161);
        lease.push(facts.tenant.len() as u8);
        lease.extend_from_slice(facts.tenant.as_bytes());
        lease.extend_from_slice(&facts.issuer);
        lease.extend_from_slice(&facts.lease);
        let mut projection = Zeroizing::new(Vec::with_capacity(maximum as usize));
        codec::encode_head(&mut projection, 4, 22);
        text(
            &mut projection,
            match admission.source {
                ActivationSource::PreauthorizedPool => "flowersec/rust-parent-admission/1",
                ActivationSource::LiveAuthority => "flowersec/rust-parent-live-admission/1",
            },
        );
        for value in [
            facts.tenant,
            facts.winner_authority,
            &self.store.identity.authority,
            audience,
            facts.authority,
        ] {
            text(&mut projection, value);
        }
        for value in [
            &admission.artifact_digest[..],
            &admission.activation_digest,
            facts.proof,
            facts.selection,
            &facts.route_set,
            &admission.candidate_id,
            &admission.route_digest,
            &admission.attempt_id,
            &binding,
            &admission.certificate_digests[0],
            &admission.certificate_digests[1],
            &facts.session_nonce,
        ] {
            data(&mut projection, value);
        }
        for value in [
            facts.issued_at,
            cutoff,
            facts.session_end,
            facts.parent_initiation_end,
        ] {
            head(&mut projection, value);
        }
        if projection.len() > maximum as usize {
            return Err(fail(PoolStoreFailure::Capacity));
        }
        let parent_projection = super::parent::ParentWinnerSelection {
            source: admission.source,
            tenant: facts.tenant,
            authority: facts.winner_authority,
            server_authority: &self.store.identity.authority,
            audience,
            artifact: admission.artifact_digest,
            activation: admission.activation_digest,
            proof: facts.proof,
            candidate: admission.candidate_id,
            route: admission.route_digest,
            attempt: admission.attempt_id,
            identities: admission.certificate_digests,
            parent_initiation_end: facts.parent_initiation_end,
            parent_session_end: a
                .u("Artifact", "session_not_after_ms")
                .map_err(|_| fail(PoolStoreFailure::Configuration))?,
        }
        .encode(maximum as usize)?;
        let mut any_committed = false;
        let result: Result<(u64, [u8; 32])> = (|| {
            // Equal rows establish only the immutable shared fact; local
            // reserve and admitted CAS still require this original invocation.
            self.parent.transaction(&check, |db, epoch| {
                let previous: Option<Vec<u8>> = db
                    .query_row(
                        "SELECT projection FROM parent_winner WHERE lease=?",
                        [&lease],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(previous) = previous {
                    if previous != parent_projection {
                        return Err(fail(PoolStoreFailure::WinnerConflict));
                    }
                    return Ok(());
                }
                capacity(db, self.parent.backing.limits)?;
                db.execute(
                    "INSERT INTO parent_winner VALUES(?,?,?,?)",
                    params![
                        lease,
                        parent_projection.as_slice(),
                        epoch.to_be_bytes(),
                        retained.to_be_bytes()
                    ],
                )?;
                db.execute(
                    "UPDATE manifest SET winner_rows=winner_rows+1 WHERE id=1",
                    [],
                )?;
                Ok(())
            })?;
            any_committed = true;
            let mut ownership = [0u8; 40];
            ownership[..16].copy_from_slice(&owner.connect);
            ownership[16..32].copy_from_slice(&owner.carrier);
            ownership[32..].copy_from_slice(&owner.generation.to_be_bytes());
            self.store.transaction(&check, |db, epoch| {
                if db
                    .query_row("SELECT 1 FROM admission WHERE lease=?", [&lease], |r| {
                        r.get::<_, u8>(0)
                    })
                    .optional()?
                    .is_some()
                {
                    return Err(fail(PoolStoreFailure::AdmissionConflict));
                }
                capacity(db, self.store.backing.limits)?;
                db.execute(
                    "INSERT INTO admission VALUES(?,?,0,?,?,?,?,?)",
                    params![
                        lease,
                        projection.as_slice(),
                        1u64.to_be_bytes(),
                        epoch.to_be_bytes(),
                        &ownership[..],
                        [0u8; 32],
                        retained.to_be_bytes()
                    ],
                )?;
                db.execute(
                    "UPDATE manifest SET admission_rows=admission_rows+1 WHERE id=1",
                    [],
                )?;
                Ok(())
            })?;
            let mut reservation = [0u8; 32];
            SystemRandom::new()
                .fill(&mut reservation)
                .map_err(|_| fail(PoolStoreFailure::OwnerUnavailable))?;
            let epoch = self.store.transaction(&check, |db, epoch| {
                if db.execute("UPDATE admission SET state=1,version=?,reservation=? WHERE lease=? AND state=0 AND version=? AND fence=? AND owner=? AND projection=?", params![2u64.to_be_bytes(), reservation, lease, 1u64.to_be_bytes(), epoch.to_be_bytes(), &ownership[..], projection.as_slice()])? != 1 {
                    return Err(fail(PoolStoreFailure::AdmissionConflict));
                }
                Ok(epoch)
            })?;
            check()?;
            Ok((epoch, reservation))
        })();
        let (epoch, reservation) = result.map_err(|mut e| {
            if any_committed && e.write_state == PoolWriteState::NotSubmitted {
                e.write_state = PoolWriteState::Committed;
            }
            e
        })?;
        let parent_epoch = self.parent.state.lock().expect("parent winner store").epoch;
        let admitted = Admitted {
            authority: self.clone(),
            account,
            owner,
            cutoff,
            epoch,
            parent_epoch,
            reservation,
            _charge: charge,
        };
        admitted.check().map_err(|mut e| {
            e.write_state = PoolWriteState::Committed;
            e
        })?;
        Ok(admitted)
    }
}
/// Never serialized, reconstructed from rows or returned to the host. Its
/// only constructor follows the original successful admitted CAS continuation.
#[derive(Debug)]
pub(crate) struct Admitted {
    authority: Arc<SQLiteAdmissionAuthority>,
    account: ResourceAccount,
    owner: PoolSpendOwner,
    cutoff: u64,
    pub(crate) epoch: u64,
    parent_epoch: u64,
    pub(crate) reservation: [u8; 32],
    _charge: ResourceCharge,
}
impl Admitted {
    pub(crate) fn check(&self) -> Result<()> {
        self.owner.check()?;
        if self.account.security_time()?.upper_ms >= self.cutoff {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        for (store, epoch) in [
            (&self.authority.parent, self.parent_epoch),
            (&self.authority.store, self.epoch),
        ] {
            let mut state = store.state.lock().expect("admission store");
            store.check(&mut state)?;
            if state.epoch != epoch {
                return Err(fail(PoolStoreFailure::Fenced));
            }
            store.fence(&state)?;
        }
        Ok(())
    }
}
fn capacity(db: &Connection, limits: SQLitePoolLimits) -> Result<()> {
    if scalar::<u64>(
        db,
        "SELECT spend_rows+winner_rows+admission_rows+(SELECT count(*) FROM top_up_material) FROM manifest WHERE id=1",
    )? >= u64::from(limits.max_records)
    {
        return Err(fail(PoolStoreFailure::Capacity));
    }
    Ok(())
}
pub(super) fn validate(
    db: &Connection,
    identity: &SQLitePoolIdentity,
    limits: SQLitePoolLimits,
    epoch: u64,
) -> Result<()> {
    let (winners, admissions): (u64, u64) = db.query_row(
        "SELECT winner_rows,admission_rows FROM manifest WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if scalar::<u64>(db, "SELECT count(*) FROM parent_winner")? != winners
        || scalar::<u64>(db, "SELECT count(*) FROM admission")? != admissions
        || scalar::<u64>(
            db,
            "SELECT spend_rows+winner_rows+admission_rows+(SELECT count(*) FROM top_up_material) FROM manifest WHERE id=1",
        )? > u64::from(limits.max_records)
    {
        return Err(fail(PoolStoreFailure::StorageFormat));
    }
    for table in ["parent_winner", "admission"] {
        let bad: u64 = db.query_row(
            &format!(
                "SELECT count(*) FROM {table} WHERE length(projection)>? OR fence>? OR fence=?"
            ),
            params![
                limits.max_record_bytes,
                epoch.to_be_bytes(),
                0u64.to_be_bytes()
            ],
            |r| r.get(0),
        )?;
        if bad != 0 {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
    }
    let bad:u64 = db.query_row("SELECT count(*) FROM admission WHERE (state=0 AND (version<>? OR reservation<>?)) OR (state=1 AND (version<>? OR reservation=?))",params![1u64.to_be_bytes(),[0u8;32],2u64.to_be_bytes(),[0u8;32]],|r|r.get(0))?;
    if bad != 0 {
        return Err(fail(PoolStoreFailure::StorageFormat));
    }
    super::records::validate_admission(db, identity, limits, epoch)
}
impl SQLitePoolStore {
    pub(crate) fn transaction<T>(
        &self,
        guard: &dyn Fn() -> Result<()>,
        action: impl FnOnce(&Connection, u64) -> Result<T>,
    ) -> Result<T> {
        guard()?;
        let mut state = self.state.lock().expect("admission transaction");
        self.check(&mut state)?;
        let mut committed = false;
        let mut uncertain = false;
        let result = (|| {
            let db = state
                .database
                .as_ref()
                .ok_or(fail(PoolStoreFailure::Closed))?;
            let checkpoint: (u64, u64, u64) =
                db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?;
            if checkpoint != (0, 0, 0) {
                return Err(fail(PoolStoreFailure::StorageUnavailable));
            }
            db.execute_batch("BEGIN IMMEDIATE")?;
            self.fence(&state)?;
            guard()?;
            let result = action(db, state.epoch)?;
            guard()?;
            self.fence(&state)?;
            uncertain = true;
            db.execute_batch("COMMIT")?;
            committed = true;
            uncertain = false;
            self.check(&mut state)?;
            self.fence(&state)?;
            guard()?;
            Ok(result)
        })();
        if let Err(mut error) = result {
            if !committed
                && let Some(db) = &state.database
                && db.execute_batch("ROLLBACK").is_err()
            {
                self.closed.store(true, Ordering::Release);
            }
            if uncertain {
                self.closed.store(true, Ordering::Release);
                error = PoolStoreError {
                    code: if self.relay_format {
                        PoolStoreFailure::RelayClaimUnknown
                    } else {
                        PoolStoreFailure::SpentUnknown
                    },
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
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_v4::verifier::credential::tests::Fixture;
    use crate::pool_v4::tests::StoreFixture;
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
    fn authority(
        f: &Fixture,
        local: &Arc<SQLitePoolStore>,
        parent: &Arc<SQLitePoolStore>,
    ) -> Arc<SQLiteAdmissionAuthority> {
        let admission = f.reserve().unwrap();
        let facts = admission.pool.as_ref().unwrap();
        SQLiteAdmissionAuthority::new(
            local.clone(),
            parent.clone(),
            vec![SQLiteAdmissionBinding {
                tenant: facts.tenant.clone(),
                issuer: facts.issuer,
                server_identity_digest: admission.certificate_digests[1],
                audience: "service".into(),
            }],
        )
        .unwrap()
    }
    fn pair(f: &Fixture) -> (StoreFixture, StoreFixture) {
        let admission = f.reserve().unwrap();
        let name = &admission.pool.as_ref().unwrap().winner_authority;
        (
            StoreFixture::with_authority(f, Some("accept.example")),
            StoreFixture::with_authority(f, Some(name)),
        )
    }
    #[test]
    fn same_parent_same_record_and_restart_never_adopt_original_admission() {
        let f = fixture();
        let (local, parent) = pair(&f);
        let a = authority(&f, &local.store, &parent.store);
        let admitted = a
            .admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
            .unwrap();
        assert_ne!(admitted.reservation, [0; 32]);
        assert_eq!(admitted.epoch, 1);
        assert_eq!(
            a.admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
                .unwrap_err()
                .code,
            PoolStoreFailure::AdmissionConflict
        );
        assert_eq!(
            a.admit(&f.reserve().unwrap(), &f.artifact, [82; 32], owner())
                .unwrap_err()
                .code,
            PoolStoreFailure::AdmissionConflict
        );
        local.store.close();
        assert!(admitted.check().is_err());
        let reopened = local.reopen().unwrap();
        let next = authority(&f, &reopened, &parent.store);
        assert_eq!(
            next.admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
                .unwrap_err()
                .code,
            PoolStoreFailure::AdmissionConflict
        );
        reopened.close();
    }
    #[test]
    fn current_admission_and_winner_reject_changed_original_projections() {
        for winner in [false, true] {
            let f = fixture();
            let (local, parent) = pair(&f);
            let a = authority(&f, &local.store, &parent.store);
            let admitted = a
                .admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
                .unwrap();
            drop(admitted);
            let target = if winner { &parent } else { &local };
            target.store.close();
            let db = Connection::open(&target.backing.inner.path).unwrap();
            let table = if winner { "parent_winner" } else { "admission" };
            let wire: Vec<u8> = db
                .query_row(&format!("SELECT projection FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            let changed = super::super::records::fixtures::alter_array(
                &wire,
                if winner { 6 } else { 7 },
                crate::codec_v4::tests::b(&[0; 32]),
            );
            db.execute(&format!("UPDATE {table} SET projection=?"), [changed])
                .unwrap();
            drop(db);
            let before = fs::read(&target.backing.inner.path).unwrap();
            assert_eq!(
                target.reopen().unwrap_err().code,
                PoolStoreFailure::StorageFormat
            );
            assert_eq!(fs::read(&target.backing.inner.path).unwrap(), before);
        }
    }
    #[test]
    fn winner_is_shared_before_different_service_admission() {
        let f = fixture();
        let (local, parent) = pair(&f);
        let a = authority(&f, &local.store, &parent.store);
        let other = StoreFixture::with_authority(&f, Some("different.service"));
        let b = authority(&f, &other.store, &parent.store);
        let admitted = a
            .admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
            .unwrap();
        assert!(admitted.check().is_ok());
        assert_eq!(
            b.admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
                .unwrap_err()
                .code,
            PoolStoreFailure::WinnerConflict
        );
        let state = other.store.state.lock().unwrap();
        assert_eq!(
            scalar::<u64>(
                state.database.as_ref().unwrap(),
                "SELECT count(*) FROM admission"
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn cancel_before_commit_does_not_claim_parent_or_admission() {
        let f = fixture();
        let (local, parent) = pair(&f);
        let a = authority(&f, &local.store, &parent.store);
        let o = owner();
        o.cancel.cancel();
        assert_eq!(
            a.admit(&f.reserve().unwrap(), &f.artifact, [81; 32], o)
                .unwrap_err()
                .write_state,
            PoolWriteState::NotSubmitted
        );
        let state = parent.store.state.lock().unwrap();
        assert_eq!(
            scalar::<u64>(
                state.database.as_ref().unwrap(),
                "SELECT count(*) FROM parent_winner"
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn late_cancellation_after_admitted_commit_preserves_durable_consumption() {
        let f = fixture();
        let (local, parent) = pair(&f);
        let a = authority(&f, &local.store, &parent.store);
        let original = owner();
        // Reserve has three continuity checks; admitted CAS cancels during
        // its third, after COMMIT, before any live continuation is returned.
        local.proof.cancel_after_checks(6, original.cancel.clone());
        let error = a
            .admit(&f.reserve().unwrap(), &f.artifact, [81; 32], original)
            .unwrap_err();
        assert_eq!(error.write_state, PoolWriteState::Committed);
        let state = local.store.state.lock().unwrap();
        assert_eq!(
            scalar::<u64>(
                state.database.as_ref().unwrap(),
                "SELECT count(*) FROM admission WHERE state=1"
            )
            .unwrap(),
            1
        );
        drop(state);
        assert_eq!(
            a.admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
                .unwrap_err()
                .code,
            PoolStoreFailure::AdmissionConflict
        );
    }
    #[test]
    fn tampered_admission_version_cannot_reopen_as_unused() {
        let f = fixture();
        let (local, parent) = pair(&f);
        let a = authority(&f, &local.store, &parent.store);
        a.admit(&f.reserve().unwrap(), &f.artifact, [81; 32], owner())
            .unwrap();
        local.store.close();
        let db = Connection::open(&local.backing.inner.path).unwrap();
        db.execute("UPDATE admission SET version=?", [1u64.to_be_bytes()])
            .unwrap();
        drop(db);
        assert_eq!(
            local.reopen().unwrap_err().code,
            PoolStoreFailure::StorageFormat
        );
    }
}
