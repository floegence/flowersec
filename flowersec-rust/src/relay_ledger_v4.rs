//! Protected relay publication and per-leg once history. Public row equality
//! never returns an original registration, possession or forwarding capability.
use super::*;
use crate::environment_v4::ResourceAccount;
use ring::rand::{SecureRandom, SystemRandom};

pub(super) const MANIFEST: &str = "CREATE TABLE manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-v4-rust-relay'), revision INTEGER NOT NULL CHECK(revision=1), authority TEXT NOT NULL CHECK(length(CAST(authority AS BLOB)) BETWEEN 1 AND 128), instance BLOB NOT NULL CHECK(length(instance)=32), generation BLOB NOT NULL CHECK(length(generation)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8), max_pages INTEGER NOT NULL, max_records INTEGER NOT NULL, max_record_bytes INTEGER NOT NULL, parent_rows INTEGER NOT NULL CHECK(parent_rows>=0), claim_rows INTEGER NOT NULL CHECK(claim_rows>=0)) STRICT, WITHOUT ROWID";
const PARENT: &str = "CREATE TABLE relay_parent (lease BLOB PRIMARY KEY CHECK(length(lease) BETWEEN 66 AND 193), publication BLOB NOT NULL CHECK(length(publication)=16), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8)) STRICT, WITHOUT ROWID";
const CLAIM: &str = "CREATE TABLE relay_claim (leg BLOB PRIMARY KEY CHECK(length(leg) BETWEEN 35 AND 162), parent BLOB NOT NULL CHECK(length(parent) BETWEEN 66 AND 193), publication BLOB NOT NULL CHECK(length(publication)=16), projection BLOB NOT NULL CHECK(length(projection) BETWEEN 1 AND 1048576), owner BLOB NOT NULL CHECK(length(owner)=56), fence BLOB NOT NULL CHECK(length(fence)=8), retained_until BLOB NOT NULL CHECK(length(retained_until)=8)) STRICT, WITHOUT ROWID";

/// These mappings are immutable trusted installation, independent of every
/// peer HELLO, Grant, activation response and stored registration row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SQLiteRelayBinding {
    pub tenant: String,
    pub parent_issuer: [u8; 16],
    pub server_admission_authority: String,
    pub service: String,
    pub relay_audience: String,
    pub relay_identity_digest: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct SQLiteRelayOptions {
    pub identity: SQLitePoolIdentity,
    pub continuity: Arc<dyn SQLitePoolContinuity>,
    pub bindings: Vec<SQLiteRelayBinding>,
    pub parent_authority: Arc<SQLitePoolStore>,
    pub create: bool,
}
#[derive(Debug)]
pub struct SQLiteRelayLedger {
    store: Arc<SQLitePoolStore>,
    bindings: Vec<SQLiteRelayBinding>,
    parent: Arc<SQLitePoolStore>,
    _charge: EnvironmentCharge,
}
/// Created only by the independent original-publication verifier. It holds
/// exact public evidence and original namespace accounts, never an Artifact,
/// PSK, Noise secret, endpoint admission or publication signer.
pub(crate) struct VerifiedRelayParent {
    pub(crate) binding: SQLiteRelayBinding,
    pub(crate) lease: [u8; 16],
    pub(crate) candidate: [u8; 16],
    pub(crate) attempt: [u8; 16],
    pub(crate) public_record: Vec<u8>,
    pub(crate) winner_projection: Vec<u8>,
    pub(crate) winner_authority: String,
    pub(crate) accounts: [ResourceAccount; 2],
    pub(crate) initiation_end: u64,
    pub(crate) session_end: u64,
}
impl fmt::Debug for VerifiedRelayParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedRelayParent { <opaque> }")
    }
}
/// An original publication handle is process-local and cannot be loaded by a
/// lookup, restored from a row or retried after cancellation/uncertain commit.
#[derive(Debug)]
pub(crate) struct RegisteredRelayParent {
    ledger: Arc<SQLiteRelayLedger>,
    facts: Arc<VerifiedRelayParent>,
    key: Vec<u8>,
    lease_key: Vec<u8>,
    publication: [u8; 16],
    epoch: u64,
    parent_epoch: u64,
    winner_continuation_taken: std::sync::atomic::AtomicBool,
    cancellation: CancellationToken,
    _charge: ResourceCharge,
}
/// Constructed only after proof verification on the same physical HOP owner.
#[derive(Debug)]
pub(crate) struct RelayPossession {
    pub(crate) role: u8,
    pub(crate) relay: [u8; 16],
    pub(crate) invocation: [u8; 16],
    pub(crate) carrier: [u8; 16],
    pub(crate) generation: u64,
    pub(crate) evidence: Vec<u8>,
    pub(crate) deadline: Instant,
    pub(crate) cancellation: CancellationToken,
    pub(crate) prepaid: Option<ResourceCharge>,
}
#[derive(Debug)]
pub(crate) struct OriginalRelayClaim {
    parent: Arc<RegisteredRelayParent>,
    possession: RelayPossession,
    _charge: ResourceCharge,
}
impl SQLiteRelayLedger {
    pub(super) fn open(backing: Arc<Backing>, options: SQLiteRelayOptions) -> Result<Arc<Self>> {
        if options.parent_authority.relay_format
            || !options.parent_authority.belongs_to(&backing.environment)
            || options.bindings.is_empty()
            || options.bindings.len() > 64
            || options.bindings.capacity() > 64
        {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        let mut pairs = Vec::new();
        for (index, binding) in options.bindings.iter().enumerate() {
            if !security_id(&binding.tenant)
                || !security_id(&binding.server_admission_authority)
                || !security_id(&binding.service)
                || !security_id(&binding.relay_audience)
                || !nonzero(&binding.parent_issuer)
                || !nonzero(&binding.relay_identity_digest)
                || options.bindings[..index].contains(binding)
            {
                return Err(fail(PoolStoreFailure::Configuration));
            }
            let pair = SQLitePoolBinding {
                tenant: binding.tenant.clone(),
                issuer: binding.parent_issuer,
            };
            if !options.parent_authority.bindings.contains(&pair) {
                return Err(fail(PoolStoreFailure::Configuration));
            }
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
        }
        let charge = backing.environment.reserve_environment(ResourceLimits {
            sdk_bytes: 32768,
            items: options.bindings.len() as u64 + 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let store = SQLitePoolStore::open_format(
            backing,
            SQLitePoolOptions {
                identity: options.identity,
                continuity: options.continuity,
                bindings: pairs,
                create: options.create,
            },
            true,
        )?;
        Ok(Arc::new(Self {
            store,
            bindings: options.bindings,
            parent: options.parent_authority,
            _charge: charge,
        }))
    }
    pub fn close(&self) {
        self.store.close();
    }
    pub fn cleanup_complete(&self) -> bool {
        self.store.cleanup_complete()
    }
    pub(crate) fn accepts_binding(&self, binding: &SQLiteRelayBinding) -> bool {
        self.bindings.contains(binding)
    }
    pub(crate) fn parent_authority_id(&self) -> &str {
        &self.parent.identity.authority
    }
    pub(crate) fn belongs_to(&self, environment: &Arc<EnvironmentRoot>) -> bool {
        self.store.belongs_to(environment)
    }
    pub(crate) fn register_original(
        self: &Arc<Self>,
        facts: VerifiedRelayParent,
        cancellation: CancellationToken,
    ) -> Result<Arc<RegisteredRelayParent>> {
        if !self.bindings.contains(&facts.binding)
            || facts.winner_authority != self.parent.identity.authority
            || !nonzero(&facts.lease)
            || !nonzero(&facts.candidate)
            || !nonzero(&facts.attempt)
            || facts.public_record.is_empty()
            || facts.public_record.len() > self.store.backing.limits.max_record_bytes as usize
            || facts.public_record.capacity() > self.store.backing.limits.max_record_bytes as usize
            || facts.winner_projection.is_empty()
            || facts.winner_projection.len() > self.parent.backing.limits.max_record_bytes as usize
            || facts.winner_projection.capacity()
                > self.parent.backing.limits.max_record_bytes as usize
            || facts
                .accounts
                .iter()
                .any(|account| !account.belongs_to(&self.store.backing.environment))
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let charge = facts.accounts[0].reserve(ResourceLimits {
            sdk_bytes: 4096,
            items: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        })?;
        let mut publication = [0; 16];
        SystemRandom::new()
            .fill(&mut publication)
            .map_err(|_| fail(PoolStoreFailure::OwnerUnavailable))?;
        if !nonzero(&publication) {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let lease_key = parent_key(
            &facts.binding.tenant,
            facts.binding.parent_issuer,
            facts.lease,
        );
        let mut key = lease_key.clone();
        key.extend_from_slice(&facts.candidate);
        key.extend_from_slice(&facts.attempt);
        let check = || {
            if cancellation.is_cancelled() {
                return Err(fail(PoolStoreFailure::OwnerUnavailable));
            }
            for account in &facts.accounts {
                let now = account.security_time()?;
                if now.upper_ms >= facts.initiation_end {
                    return Err(fail(PoolStoreFailure::OwnerUnavailable));
                }
            }
            Ok(())
        };
        let retained = facts
            .session_end
            .checked_add(RETENTION)
            .ok_or(fail(PoolStoreFailure::Capacity))?;
        let parent_epoch = {
            let mut state = self
                .parent
                .state
                .lock()
                .expect("relay installation parent epoch");
            self.parent.check(&mut state)?;
            self.parent.fence(&state)?;
            state.epoch
        };
        let epoch = self.store.transaction(&check, |db, epoch| {
            if db
                .query_row("SELECT 1 FROM relay_parent WHERE lease=?", [&key], |row| {
                    row.get::<_, u8>(0)
                })
                .optional()?
                .is_some()
            {
                return Err(fail(PoolStoreFailure::RelayPublicationConflict));
            }
            capacity(db, self.store.backing.limits, 1)?;
            db.execute(
                "INSERT INTO relay_parent VALUES(?,?,?,?,?)",
                params![
                    &key,
                    publication,
                    &facts.public_record,
                    epoch.to_be_bytes(),
                    retained.to_be_bytes()
                ],
            )?;
            db.execute(
                "UPDATE manifest SET parent_rows=parent_rows+1 WHERE id=1",
                [],
            )?;
            Ok(epoch)
        })?;
        check().map_err(|mut error| {
            error.write_state = PoolWriteState::Committed;
            error
        })?;
        Ok(Arc::new(RegisteredRelayParent {
            ledger: self.clone(),
            facts: Arc::new(facts),
            key,
            lease_key,
            publication,
            epoch,
            parent_epoch,
            winner_continuation_taken: std::sync::atomic::AtomicBool::new(false),
            cancellation,
            _charge: charge,
        }))
    }
}
impl RegisteredRelayParent {
    pub(crate) fn check(&self) -> Result<()> {
        if self.cancellation.is_cancelled() || self.ledger.store.closed.load(Ordering::Acquire) {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        for account in &self.facts.accounts {
            account.check()?;
        }
        let mut state = self
            .ledger
            .store
            .state
            .lock()
            .expect("original relay publication fence");
        self.ledger.store.check(&mut state)?;
        self.ledger.store.fence(&state)?;
        if state.epoch != self.epoch {
            return Err(fail(PoolStoreFailure::Fenced));
        }
        drop(state);
        let mut parent = self
            .ledger
            .parent
            .state
            .lock()
            .expect("original relay parent fence");
        self.ledger.parent.check(&mut parent)?;
        self.ledger.parent.fence(&parent)?;
        if parent.epoch != self.parent_epoch {
            return Err(fail(PoolStoreFailure::Fenced));
        }
        Ok(())
    }
    pub(crate) fn take_pool_winner_control(&self) -> Result<(Vec<u8>, Vec<u8>, Instant)> {
        self.check()?;
        self.winner_continuation_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| fail(PoolStoreFailure::OwnerUnavailable))?;
        let local = codec::decode_control_array(
            &self.facts.winner_projection,
            codec::Limits {
                bytes: 16384,
                nodes: 128,
            },
        )
        .map_err(|_| fail(PoolStoreFailure::Configuration))?;
        let invalid = || fail(PoolStoreFailure::Configuration);
        if local.len().map_err(|_| invalid())? != 15
            || local.at(0).and_then(|v| v.text()).map_err(|_| invalid())?
                != "flowersec/rust-parent-pool-selection/1"
        {
            return Err(invalid());
        }
        let proof = codec::decode_context(
            local.at(7).and_then(|v| v.bytes()).map_err(|_| invalid())?,
            "ActivationAuthorization",
            codec::Limits {
                bytes: 4096,
                nodes: 256,
            },
            None,
            codec::Context::with_activation_source(ActivationSource::PreauthorizedPool),
        )
        .map_err(|_| invalid())?;
        let field = |name| {
            proof
                .field("ActivationAuthorization", name)
                .map_err(|_| invalid())
        };
        let mut projection = Vec::with_capacity(1024);
        codec::encode_head(&mut projection, 4, 18);
        for value in [
            "flowersec/parent-winner/1",
            "preauthorized_pool",
            &self.facts.binding.tenant,
            &self.facts.winner_authority,
            local.at(4).and_then(|v| v.text()).map_err(|_| invalid())?,
        ] {
            text(&mut projection, value);
        }
        for value in [
            self.facts.binding.parent_issuer.as_slice(),
            self.facts.lease.as_slice(),
            local.at(5).and_then(|v| v.bytes()).map_err(|_| invalid())?,
            local.at(6).and_then(|v| v.bytes()).map_err(|_| invalid())?,
            field("candidate_selection")?
                .field("PoolSelectionRef", "candidate_set_digest")
                .and_then(|v| v.bytes())
                .map_err(|_| invalid())?,
            self.facts.candidate.as_slice(),
            local.at(9).and_then(|v| v.bytes()).map_err(|_| invalid())?,
            self.facts.attempt.as_slice(),
            local
                .at(11)
                .and_then(|v| v.bytes())
                .map_err(|_| invalid())?,
            local
                .at(12)
                .and_then(|v| v.bytes())
                .map_err(|_| invalid())?,
        ] {
            data(&mut projection, value);
        }
        for name in [
            "issued_at_ms",
            "activation_not_after_ms",
            "session_not_after_ms",
        ] {
            head(&mut projection, field(name)?.uint().map_err(|_| invalid())?);
        }
        let remaining = self
            .facts
            .initiation_end
            .checked_sub(self.facts.accounts[0].security_time()?.upper_ms)
            .filter(|n| *n > 0)
            .ok_or(fail(PoolStoreFailure::OwnerUnavailable))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or_else(invalid)?;
        Ok((self.lease_key.clone(), projection, deadline))
    }
    pub(crate) fn match_original_pool_winner(&self) -> Result<()> {
        let check = || {
            self.check()?;
            for account in &self.facts.accounts {
                if account.security_time()?.upper_ms >= self.facts.initiation_end {
                    return Err(fail(PoolStoreFailure::OwnerUnavailable));
                }
            }
            Ok(())
        };
        check()?;
        let mut state = self
            .ledger
            .parent
            .state
            .lock()
            .expect("original remote winner continuation");
        self.ledger.parent.check(&mut state)?;
        self.ledger.parent.fence(&state)?;
        if state.epoch != self.parent_epoch {
            return Err(fail(PoolStoreFailure::Fenced));
        }
        let db = state
            .database
            .as_ref()
            .ok_or(fail(PoolStoreFailure::OwnerUnavailable))?;
        let matched = db
            .query_row(
                "SELECT projection=? FROM parent_winner WHERE lease=?",
                params![&self.facts.winner_projection, &self.lease_key],
                |row| row.get::<_, bool>(0),
            )
            .optional()?;
        if matched != Some(true) {
            return Err(fail(PoolStoreFailure::WinnerConflict));
        }
        drop(state);
        check()
    }
    pub(crate) fn accounts(&self) -> &[ResourceAccount; 2] {
        &self.facts.accounts
    }
    pub(crate) fn belongs_to_ledger(&self, ledger: &Arc<SQLiteRelayLedger>) -> bool {
        Arc::ptr_eq(&self.ledger, ledger)
    }
    pub(crate) fn account(&self, role: u8) -> Result<ResourceAccount> {
        self.check()?;
        self.facts
            .accounts
            .get(role as usize)
            .cloned()
            .ok_or(fail(PoolStoreFailure::Configuration))
    }
    pub(crate) fn claim_original(
        self: &Arc<Self>,
        mut possession: RelayPossession,
    ) -> Result<OriginalRelayClaim> {
        if possession.role > 1
            || !nonzero(&possession.relay)
            || !nonzero(&possession.invocation)
            || !nonzero(&possession.carrier)
            || possession.generation == 0
            || possession.evidence.is_empty()
            || possession.evidence.len() > 4096
            || possession.evidence.capacity() > 4096
        {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        let account = self.account(possession.role)?;
        let vector = ResourceLimits {
            sdk_bytes: 8192,
            items: 2,
            work_slots: 1,
            ..ResourceLimits::default()
        };
        let charge = possession
            .prepaid
            .take()
            .ok_or(fail(PoolStoreFailure::Configuration))?;
        if !charge.matches(&account, vector) {
            return Err(fail(PoolStoreFailure::Configuration));
        }
        let check = || {
            // The enclosing transaction owns the store mutex; do not acquire it
            // recursively through this original publication's public check.
            if self.cancellation.is_cancelled()
                || possession.cancellation.is_cancelled()
                || Instant::now() >= possession.deadline
            {
                return Err(fail(PoolStoreFailure::OwnerUnavailable));
            }
            for account in &self.facts.accounts {
                let now = account.security_time()?;
                if now.upper_ms >= self.facts.initiation_end {
                    return Err(fail(PoolStoreFailure::OwnerUnavailable));
                }
            }
            Ok(())
        };
        let mut leg = self.lease_key.clone();
        leg.push(possession.role);
        let mut owner = [0; 56];
        owner[..16].copy_from_slice(&possession.relay);
        owner[16..32].copy_from_slice(&possession.invocation);
        owner[32..48].copy_from_slice(&possession.carrier);
        owner[48..].copy_from_slice(&possession.generation.to_be_bytes());
        let retained = self
            .facts
            .session_end
            .checked_add(RETENTION)
            .ok_or(fail(PoolStoreFailure::Capacity))?;
        // Original verified possession, never registration alone, fixes the
        // pool winner at the independently installed common parent authority.
        self.ledger.parent.transaction(&check, |db, epoch| {
            if epoch != self.parent_epoch {
                return Err(fail(PoolStoreFailure::Fenced));
            }
            let previous: Option<Vec<u8>> = db
                .query_row(
                    "SELECT projection FROM parent_winner WHERE lease=?",
                    [&self.lease_key],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(previous) = previous {
                if previous != self.facts.winner_projection {
                    return Err(fail(PoolStoreFailure::WinnerConflict));
                }
            } else {
                if scalar::<u64>(
                    db,
                    "SELECT spend_rows+winner_rows+admission_rows FROM manifest WHERE id=1",
                )? >= self.ledger.parent.backing.limits.max_records as u64
                {
                    return Err(fail(PoolStoreFailure::Capacity));
                }
                db.execute(
                    "INSERT INTO parent_winner VALUES(?,?,?,?)",
                    params![
                        &self.lease_key,
                        &self.facts.winner_projection,
                        epoch.to_be_bytes(),
                        retained.to_be_bytes()
                    ],
                )?;
                db.execute(
                    "UPDATE manifest SET winner_rows=winner_rows+1 WHERE id=1",
                    [],
                )?;
            }
            Ok(())
        })?;
        let local_claim = self.ledger.store.transaction(&check, |db, epoch| {
            if epoch != self.epoch {
                return Err(fail(PoolStoreFailure::Fenced));
            }
            let parent: Option<(Vec<u8>, Vec<u8>)> = db
                .query_row(
                    "SELECT publication,projection FROM relay_parent WHERE lease=?",
                    [&self.key],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if parent.as_ref().is_none_or(|(publication, projection)| {
                publication != &self.publication || projection != &self.facts.public_record
            }) {
                return Err(fail(PoolStoreFailure::RelayPublicationConflict));
            }
            if db
                .query_row("SELECT 1 FROM relay_claim WHERE leg=?", [&leg], |row| {
                    row.get::<_, u8>(0)
                })
                .optional()?
                .is_some()
            {
                return Err(fail(PoolStoreFailure::RelayClaimConflict));
            }
            capacity(db, self.ledger.store.backing.limits, 1)?;
            db.execute(
                "INSERT INTO relay_claim VALUES(?,?,?,?,?,?,?)",
                params![
                    &leg,
                    &self.key,
                    self.publication,
                    &possession.evidence,
                    &owner[..],
                    epoch.to_be_bytes(),
                    retained.to_be_bytes()
                ],
            )?;
            db.execute("UPDATE manifest SET claim_rows=claim_rows+1 WHERE id=1", [])?;
            Ok(())
        });
        local_claim.map_err(|mut error| {
            if error.write_state == PoolWriteState::NotSubmitted {
                error.write_state = PoolWriteState::Committed;
            }
            error
        })?;
        check().and_then(|()| self.check()).map_err(|mut error| {
            if error.write_state == PoolWriteState::NotSubmitted {
                error.write_state = PoolWriteState::Committed;
            }
            error
        })?;
        Ok(OriginalRelayClaim {
            parent: self.clone(),
            possession,
            _charge: charge,
        })
    }
}
impl OriginalRelayClaim {
    pub(crate) fn check(&self) -> Result<()> {
        self.parent.check()?;
        if self.possession.cancellation.is_cancelled() {
            return Err(fail(PoolStoreFailure::OwnerUnavailable));
        }
        Ok(())
    }
    pub(crate) fn carrier(&self) -> [u8; 16] {
        self.possession.carrier
    }
    pub(crate) fn role(&self) -> u8 {
        self.possession.role
    }
}
fn parent_key(tenant: &str, issuer: [u8; 16], lease: [u8; 16]) -> Vec<u8> {
    let mut result = Vec::with_capacity(tenant.len() + 33);
    result.push(tenant.len() as u8);
    result.extend_from_slice(tenant.as_bytes());
    result.extend_from_slice(&issuer);
    result.extend_from_slice(&lease);
    result
}
fn capacity(db: &Connection, limits: SQLitePoolLimits, positions: u64) -> Result<()> {
    let used: u64 = scalar(db, "SELECT parent_rows+claim_rows FROM manifest WHERE id=1")?;
    if used
        .checked_add(positions)
        .is_none_or(|total| total > limits.max_records as u64)
    {
        return Err(fail(PoolStoreFailure::Capacity));
    }
    Ok(())
}
pub(super) fn initialize(
    db: &Connection,
    identity: &SQLitePoolIdentity,
    limits: SQLitePoolLimits,
) -> Result<()> {
    for sql in [MANIFEST, PARENT, CLAIM] {
        db.execute_batch(sql)?;
    }
    db.execute_batch("PRAGMA user_version=1")?;
    db.execute(
        "INSERT INTO manifest VALUES(1,'flowersec-v4-rust-relay',1,?,?,?,?,?,?,?,0,0)",
        params![
            &identity.authority,
            identity.store_id,
            identity.generation.to_be_bytes(),
            1u64.to_be_bytes(),
            limits.max_pages,
            limits.max_records,
            limits.max_record_bytes
        ],
    )?;
    Ok(())
}
pub(super) fn validate(
    db: &Connection,
    identity: &SQLitePoolIdentity,
    limits: SQLitePoolLimits,
) -> Result<u64> {
    if scalar::<u64>(db, "PRAGMA user_version")? != 1
        || scalar::<u64>(db, "SELECT count(*) FROM sqlite_schema")? != 3
        || scalar::<u64>(db, "SELECT count(*) FROM manifest")? != 1
    {
        return Err(fail(PoolStoreFailure::StorageFormat));
    }
    for (name, expected) in [
        ("manifest", MANIFEST),
        ("relay_parent", PARENT),
        ("relay_claim", CLAIM),
    ] {
        let actual: Option<String> = db
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name=? AND type='table'",
                [name],
                |row| row.get(0),
            )
            .optional()?;
        if actual.as_deref() != Some(expected) {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
    }
    let row = db.query_row("SELECT authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,parent_rows,claim_rows FROM manifest WHERE id=1", [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?,
            row.get::<_, u32>(4)?, row.get::<_, u32>(5)?, row.get::<_, u32>(6)?, row.get::<_, u64>(7)?, row.get::<_, u64>(8)?)))?;
    let epoch = read_u64(row.3)?;
    if row.0 != identity.authority
        || row.1 != identity.store_id
        || read_u64(row.2)? != identity.generation
        || epoch == 0
        || row.4 != limits.max_pages
        || row.5 != limits.max_records
        || row.6 != limits.max_record_bytes
        || row
            .7
            .checked_add(row.8)
            .is_none_or(|total| total > limits.max_records as u64)
        || scalar::<u64>(db, "SELECT count(*) FROM relay_parent")? != row.7
        || scalar::<u64>(db, "SELECT count(*) FROM relay_claim")? != row.8
    {
        return Err(fail(PoolStoreFailure::StorageFormat));
    }
    for table in ["relay_parent", "relay_claim"] {
        let bad: u64 = db.query_row(&format!("SELECT count(*) FROM {table} WHERE length(projection)>? OR fence>? OR fence=? OR publication=? OR retained_until=?"),
            params![limits.max_record_bytes, epoch.to_be_bytes(), 0u64.to_be_bytes(), [0u8; 16], 0u64.to_be_bytes()], |row| row.get(0))?;
        if bad != 0 {
            return Err(fail(PoolStoreFailure::StorageFormat));
        }
    }
    let orphaned: u64 = scalar(
        db,
        "SELECT count(*) FROM relay_claim c LEFT JOIN relay_parent p ON p.lease=c.parent AND p.publication=c.publication WHERE p.lease IS NULL OR substr(c.leg,1,length(c.leg)-1)<>substr(c.parent,1,length(c.parent)-32) OR substr(c.leg,-1,1) NOT IN (x'00',x'01')",
    )?;
    if orphaned != 0 {
        return Err(fail(PoolStoreFailure::StorageFormat));
    }
    super::records::validate_relay(db, identity, limits, epoch)?;
    Ok(epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace_v4::verifier::credential::tests::Fixture;
    use crate::pool_v4::tests::StoreFixture;
    use std::sync::atomic::AtomicU64;

    // These tests isolate the protected ledger transition boundary. The sealed
    // verified facts and possession are constructed here only; none of these
    // fixtures is an endpoint/HOP/relay integration acceptance result.
    #[derive(Debug, Default)]
    struct History {
        epoch: AtomicU64,
        calls: AtomicU64,
        reject_at: AtomicU64,
    }
    impl SQLitePoolContinuity for History {
        fn check(&self, _: &SQLitePoolIdentity, epoch: u64, provisioning: bool) -> Result<()> {
            let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
            let reject = self.reject_at.load(Ordering::Acquire);
            if reject != 0 && call >= reject {
                return Err(fail(PoolStoreFailure::HistoryUnknown));
            }
            if !provisioning && epoch < self.epoch.load(Ordering::Acquire) {
                return Err(fail(PoolStoreFailure::HistoryUnknown));
            }
            if !provisioning {
                self.epoch.fetch_max(epoch, Ordering::AcqRel);
            }
            Ok(())
        }
    }
    struct Harness {
        ledger: Arc<SQLiteRelayLedger>,
        backing: SQLitePoolBacking,
        options: SQLiteRelayOptions,
        history: Arc<History>,
        parent: StoreFixture,
        _directory: tempfile::TempDir,
    }
    impl Harness {
        fn new(f: &Fixture, records: u32) -> Self {
            let facts = f.reserve().unwrap();
            let pool = facts.pool.as_ref().unwrap();
            let parent = StoreFixture::with_authority(f, Some(&pool.winner_authority));
            let directory = tempfile::tempdir().unwrap();
            let path = fs::canonicalize(directory.path())
                .unwrap()
                .join("relay.sqlite");
            let backing = f
                .environment
                .sqlite_pool_backing(
                    path,
                    SQLitePoolLimits {
                        max_pages: 64,
                        max_records: records,
                        max_record_bytes: 8192,
                        provider_runtime_bytes: 262144,
                        disk_overhead_bytes: 65536,
                    },
                )
                .unwrap();
            let history = Arc::new(History::default());
            let options = SQLiteRelayOptions {
                identity: SQLitePoolIdentity {
                    authority: "relay".into(),
                    store_id: [73; 32],
                    generation: 1,
                },
                continuity: history.clone(),
                bindings: vec![SQLiteRelayBinding {
                    tenant: pool.tenant.clone(),
                    parent_issuer: pool.issuer,
                    server_admission_authority: "accept".into(),
                    service: "relay".into(),
                    relay_audience: "relay".into(),
                    relay_identity_digest: [74; 32],
                }],
                parent_authority: parent.store.clone(),
                create: true,
            };
            let ledger = backing.open_relay(options.clone()).unwrap();
            Self {
                ledger,
                backing,
                options,
                history,
                parent,
                _directory: directory,
            }
        }
        fn facts(&self, f: &Fixture) -> VerifiedRelayParent {
            let a = f.reserve().unwrap();
            let pool = a.pool.as_ref().unwrap();
            let (public_record, winner_projection) =
                super::super::records::fixtures::relay_publication(f, &self.options.bindings[0]);
            let artifact = codec::decode_context(
                &f.artifact,
                "Artifact",
                crate::codec_v4::Limits {
                    bytes: 65536,
                    nodes: 16384,
                },
                None,
                crate::codec_v4::Context::default(),
            )
            .unwrap();
            VerifiedRelayParent {
                binding: self.options.bindings[0].clone(),
                lease: pool.lease,
                candidate: a.candidate_id,
                attempt: a.attempt_id,
                public_record,
                winner_projection,
                winner_authority: pool.winner_authority.clone(),
                accounts: [a.account.clone(), a.account],
                initiation_end: a.initiation_not_after_ms,
                session_end: artifact.u("Artifact", "session_not_after_ms").unwrap(),
            }
        }
        fn count(&self, table: &str) -> u64 {
            let state = self.ledger.store.state.lock().unwrap();
            scalar(
                state.database.as_ref().unwrap(),
                &format!("SELECT count(*) FROM {table}"),
            )
            .unwrap()
        }
        fn reopen(&self) -> Arc<SQLiteRelayLedger> {
            let mut options = self.options.clone();
            options.create = false;
            self.backing.open_relay(options).unwrap()
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            self.ledger.close();
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = fs::remove_file(sibling(&self.backing.inner.path, suffix));
            }
            self.backing.release_removed().unwrap();
        }
    }
    fn fixture() -> Fixture {
        Fixture::with_identity(
            ActivationSource::PreauthorizedPool,
            "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
            None,
        )
    }
    #[test]
    fn relay_format_refusals_preserve_the_original_manifest_and_epoch() {
        for future in [false, true] {
            let f = fixture();
            let harness = Harness::new(&f, 8);
            harness.ledger.close();
            let db = Connection::open(&harness.backing.inner.path).unwrap();
            db.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
            db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
            if future {
                db.execute_batch(
                    "BEGIN IMMEDIATE; ALTER TABLE manifest RENAME TO original_manifest",
                )
                .unwrap();
                db.execute_batch(&MANIFEST.replace("CHECK(revision=1)", "CHECK(revision=2)"))
                    .unwrap();
                db.execute("INSERT INTO manifest SELECT id,format,2,authority,instance,generation,epoch,max_pages,max_records,max_record_bytes,parent_rows,claim_rows FROM original_manifest", []).unwrap();
                db.execute_batch("DROP TABLE original_manifest; DROP TABLE relay_claim; CREATE TABLE future_claims(value TEXT); PRAGMA user_version=2; COMMIT").unwrap();
            } else {
                db.execute_batch("CREATE TABLE unexpected(value TEXT)")
                    .unwrap();
            }
            db.execute_batch("BEGIN; SELECT name FROM sqlite_schema")
                .unwrap();
            assert!(
                fs::metadata(sibling(&harness.backing.inner.path, "-wal"))
                    .unwrap()
                    .len()
                    > 32
            );
            let before =
                crate::sqlite_application_format_v4::tests::snapshot(harness._directory.path());
            let checks = harness.history.calls.load(Ordering::Acquire);
            let mut options = harness.options.clone();
            options.create = false;
            assert_eq!(
                harness
                    .backing
                    .open_relay(options.clone())
                    .unwrap_err()
                    .code,
                PoolStoreFailure::StorageUnavailable
            );
            assert_eq!(
                crate::sqlite_application_format_v4::tests::snapshot(harness._directory.path()),
                before
            );
            db.execute_batch("ROLLBACK").unwrap();
            db.close().unwrap();
            let before =
                crate::sqlite_application_format_v4::tests::snapshot(harness._directory.path());
            let failure = harness.backing.open_relay(options).unwrap_err();
            let format = failure.format.unwrap();
            assert_eq!(format.code(), "storage_format_incompatible");
            assert_eq!(
                format.transaction_group,
                StorageFormatTransactionGroup::Relay
            );
            assert_eq!(
                format.required_wire,
                StorageWireFormat::FlowersecV4RustRelay
            );
            assert_eq!(format.required_revision, 1);
            assert_eq!(format.observed_revision, Some(if future { 2 } else { 1 }));
            assert_eq!(
                format.reason,
                if future {
                    StorageFormatMismatchReason::NewerRevision
                } else {
                    StorageFormatMismatchReason::Schema
                }
            );
            assert_eq!(harness.history.calls.load(Ordering::Acquire), checks);
            assert!(
                crate::sqlite_application_format_v4::tests::snapshot(harness._directory.path())
                    == before,
                "refusal changed durable files"
            );
        }
    }
    fn possession(original: &Arc<RegisteredRelayParent>, role: u8, carrier: u8) -> RelayPossession {
        RelayPossession {
            role,
            relay: [75; 16],
            invocation: [76; 16],
            carrier: [carrier; 16],
            generation: 1,
            evidence: super::super::records::fixtures::relay_evidence(
                &original.facts.public_record,
                role,
                carrier,
            ),
            prepaid: Some(
                original.facts.accounts[role as usize]
                    .reserve(ResourceLimits {
                        sdk_bytes: 8192,
                        items: 2,
                        work_slots: 1,
                        ..ResourceLimits::default()
                    })
                    .unwrap(),
            ),
            deadline: Instant::now() + Duration::from_secs(10),
            cancellation: CancellationToken::new(),
        }
    }
    #[test]
    fn registration_does_not_choose_winner_or_claim_and_both_original_legs_are_once_only() {
        let f = fixture();
        let h = Harness::new(&f, 8);
        let original = h
            .ledger
            .register_original(h.facts(&f), CancellationToken::new())
            .unwrap();
        assert_eq!(h.parent.winner_count(), 0);
        assert_eq!(h.count("relay_parent"), 1);
        assert_eq!(h.count("relay_claim"), 0);
        let a = original
            .claim_original(possession(&original, 0, 77))
            .unwrap();
        let b = original
            .claim_original(possession(&original, 1, 78))
            .unwrap();
        assert!(a.check().is_ok());
        assert!(b.check().is_ok());
        assert_eq!(h.parent.winner_count(), 1);
        assert_eq!(h.count("relay_claim"), 2);
        assert_eq!(
            original
                .claim_original(possession(&original, 0, 79))
                .unwrap_err()
                .code,
            PoolStoreFailure::RelayClaimConflict
        );
        assert_eq!(
            original
                .claim_original(possession(&original, 1, 80))
                .unwrap_err()
                .code,
            PoolStoreFailure::RelayClaimConflict
        );
        assert_eq!(
            h.ledger
                .register_original(h.facts(&f), CancellationToken::new())
                .unwrap_err()
                .code,
            PoolStoreFailure::RelayPublicationConflict
        );
    }
    #[test]
    fn registered_alternative_remains_public_only_and_cannot_create_a_second_parent_root() {
        let f = fixture();
        let h = Harness::new(&f, 8);
        let a = h
            .ledger
            .register_original(h.facts(&f), CancellationToken::new())
            .unwrap();
        let mut alternative = h.facts(&f);
        alternative.candidate[0] ^= 1;
        alternative.winner_projection.push(1);
        let b = h
            .ledger
            .register_original(alternative, CancellationToken::new())
            .unwrap();
        assert_eq!(h.count("relay_parent"), 2);
        assert_eq!(h.parent.winner_count(), 0);
        let original = a.claim_original(possession(&a, 0, 77)).unwrap();
        assert!(original.check().is_ok());
        assert_eq!(
            b.claim_original(possession(&b, 1, 78)).unwrap_err().code,
            PoolStoreFailure::WinnerConflict
        );
        assert_eq!(h.count("relay_claim"), 1);
        assert_eq!(h.parent.winner_count(), 1);
    }
    #[test]
    fn reopen_fences_original_handles_and_registration_rows_never_recreate_them() {
        let f = fixture();
        let h = Harness::new(&f, 8);
        let original = h
            .ledger
            .register_original(h.facts(&f), CancellationToken::new())
            .unwrap();
        let claim = original
            .claim_original(possession(&original, 0, 77))
            .unwrap();
        h.ledger.close();
        assert!(claim.check().is_err());
        let reopened = h.reopen();
        assert_eq!(
            reopened
                .register_original(h.facts(&f), CancellationToken::new())
                .unwrap_err()
                .code,
            PoolStoreFailure::RelayPublicationConflict
        );
        assert!(
            original
                .claim_original(possession(&original, 1, 78))
                .is_err()
        );
        let state = reopened.store.state.lock().unwrap();
        assert_eq!(
            scalar::<u64>(
                state.database.as_ref().unwrap(),
                "SELECT count(*) FROM relay_claim"
            )
            .unwrap(),
            1
        );
        drop(state);
        reopened.close();
    }
    #[test]
    fn current_relay_history_refuses_public_record_and_claim_mismatches() {
        for claim in [false, true] {
            let f = fixture();
            let h = Harness::new(&f, 8);
            let original = h
                .ledger
                .register_original(h.facts(&f), CancellationToken::new())
                .unwrap();
            let handle = original
                .claim_original(possession(&original, 0, 77))
                .unwrap();
            drop(handle);
            h.ledger.close();
            let db = Connection::open(&h.backing.inner.path).unwrap();
            db.set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                true,
            )
            .unwrap();
            db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
            let table = if claim { "relay_claim" } else { "relay_parent" };
            let wire: Vec<u8> = db
                .query_row(&format!("SELECT projection FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            let changed = super::super::records::fixtures::alter_array(
                &wire,
                if claim { 0 } else { 10 },
                crate::codec_v4::tests::b(if claim { &[0; 32][..] } else { &[16][..] }),
            );
            db.execute(&format!("UPDATE {table} SET projection=?"), [changed])
                .unwrap();
            db.execute_batch("BEGIN; SELECT name FROM sqlite_schema")
                .unwrap();
            assert!(
                fs::metadata(sibling(&h.backing.inner.path, "-wal"))
                    .unwrap()
                    .len()
                    > 32
            );
            let before = crate::sqlite_application_format_v4::tests::snapshot(h._directory.path());
            let mut options = h.options.clone();
            options.create = false;
            assert_eq!(
                h.backing.open_relay(options.clone()).unwrap_err().code,
                PoolStoreFailure::StorageUnavailable
            );
            assert_eq!(
                crate::sqlite_application_format_v4::tests::snapshot(h._directory.path()),
                before
            );
            db.execute_batch("ROLLBACK").unwrap();
            db.close().unwrap();
            let before = crate::sqlite_application_format_v4::tests::snapshot(h._directory.path());
            let error = h.backing.open_relay(options).unwrap_err();
            assert_eq!(error.code, PoolStoreFailure::StorageFormat);
            assert_eq!(
                error.format.unwrap().transaction_group,
                StorageFormatTransactionGroup::Relay
            );
            assert!(
                crate::sqlite_application_format_v4::tests::snapshot(h._directory.path()) == before,
                "refusal changed durable files"
            );
        }
    }
    #[test]
    fn no_local_claim_capability_after_capacity_failure_or_cancel() {
        let f = fixture();
        let h = Harness::new(&f, 1);
        let cancel = CancellationToken::new();
        let original = h
            .ledger
            .register_original(h.facts(&f), cancel.clone())
            .unwrap();
        let failure = original
            .claim_original(possession(&original, 0, 77))
            .unwrap_err();
        assert_eq!(failure.code, PoolStoreFailure::Capacity);
        assert_eq!(failure.write_state, PoolWriteState::Committed);
        assert_eq!(h.count("relay_claim"), 0);
        assert_eq!(h.parent.winner_count(), 1);
        cancel.cancel();
        assert!(
            original
                .claim_original(possession(&original, 1, 78))
                .is_err()
        );
    }
    #[test]
    fn post_commit_continuity_failure_keeps_publication_tombstone_without_returning_handle() {
        let f = fixture();
        let h = Harness::new(&f, 8);
        // Register observes the parent store first (different continuity owner).
        // The relay transaction's third local check is after real COMMIT.
        h.history.reject_at.store(
            h.history.calls.load(Ordering::Acquire) + 3,
            Ordering::Release,
        );
        let failure = h
            .ledger
            .register_original(h.facts(&f), CancellationToken::new())
            .unwrap_err();
        assert_eq!(failure.code, PoolStoreFailure::HistoryUnknown);
        assert_eq!(failure.write_state, PoolWriteState::Committed);
        assert_eq!(h.count("relay_parent"), 1);
        assert_eq!(h.count("relay_claim"), 0);
        assert_eq!(h.parent.winner_count(), 0);
        h.ledger.close();
        h.history.reject_at.store(0, Ordering::Release);
        let reopened = h.reopen();
        assert_eq!(
            reopened
                .register_original(h.facts(&f), CancellationToken::new())
                .unwrap_err()
                .code,
            PoolStoreFailure::RelayPublicationConflict
        );
        reopened.close();
    }
    #[test]
    fn claim_commit_without_original_continuity_receipt_never_returns_forwarding_right() {
        let f = fixture();
        let h = Harness::new(&f, 8);
        let original = h
            .ledger
            .register_original(h.facts(&f), CancellationToken::new())
            .unwrap();
        // Original account checks the relay fence once before the local claim
        // transaction; its third transaction check follows actual COMMIT.
        h.history.reject_at.store(
            h.history.calls.load(Ordering::Acquire) + 4,
            Ordering::Release,
        );
        let failure = original
            .claim_original(possession(&original, 0, 77))
            .unwrap_err();
        assert_eq!(failure.code, PoolStoreFailure::HistoryUnknown);
        assert_eq!(failure.write_state, PoolWriteState::Committed);
        assert_eq!(h.count("relay_claim"), 1);
        h.ledger.close();
        h.history.reject_at.store(0, Ordering::Release);
        let reopened = h.reopen();
        assert!(
            original
                .claim_original(possession(&original, 0, 77))
                .is_err()
        );
        assert_eq!(
            reopened
                .register_original(h.facts(&f), CancellationToken::new())
                .unwrap_err()
                .code,
            PoolStoreFailure::RelayPublicationConflict
        );
        reopened.close();
    }
}
