//! Read-only current physical facts. No parser here creates a credential,
//! registration, admission continuation, or original relay possession owner.
use super::*;
use crate::codec_v4::{Context, Limits, Value};

pub(super) const SCRATCH_BYTES: u64 = 3 * 65_536;
type FactsResult<T> = std::result::Result<T, &'static str>;

fn invalid(_: impl fmt::Debug) -> PoolStoreError {
    fail(PoolStoreFailure::StorageFormat)
}
fn blob<'a>(row: &'a rusqlite::Row<'_>, index: usize) -> Result<&'a [u8]> {
    row.get_ref(index)?.as_blob().map_err(invalid)
}
fn uint_blob(row: &rusqlite::Row<'_>, index: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(
        blob(row, index)?.try_into().map_err(invalid)?,
    ))
}
fn map<const N: usize>(wire: &[u8], maximum: usize) -> FactsResult<[Value<'_>; N]> {
    let value = codec::decode_storage_map(
        wire,
        Limits {
            bytes: maximum,
            nodes: 256,
        },
    )?;
    if value.len()? != N {
        return Err("storage_map_fields");
    }
    let mut fields = [value; N];
    let mut children = value.children()?;
    for (index, field) in fields.iter_mut().enumerate() {
        if children.next().ok_or("storage_map_field")??.uint()? != index as u64 {
            return Err("storage_map_field");
        }
        *field = children.next().ok_or("storage_map_field")??;
    }
    Ok(fields)
}
fn array<const N: usize>(wire: &[u8], maximum: usize) -> FactsResult<[Value<'_>; N]> {
    let value = codec::decode_control_array(
        wire,
        Limits {
            bytes: maximum,
            nodes: 256,
        },
    )?;
    if value.len()? != N {
        return Err("storage_array_fields");
    }
    let mut fields = [value; N];
    for (dst, value) in fields.iter_mut().zip(value.children()?) {
        *dst = value?;
    }
    Ok(fields)
}
fn bytes<const N: usize>(value: Value<'_>) -> FactsResult<[u8; N]> {
    value
        .bytes()?
        .try_into()
        .map_err(|_| "storage_field_length")
}
fn decode<'a>(
    wire: &'a [u8],
    schema: &str,
    source: Option<ActivationSource>,
) -> FactsResult<Value<'a>> {
    codec::decode_context(
        wire,
        schema,
        Limits {
            bytes: 65536,
            nodes: 16384,
        },
        None,
        source
            .map(Context::with_activation_source)
            .unwrap_or_default(),
    )
}
fn lease_key(key: &[u8], tenant: &str, issuer: [u8; 16], lease: [u8; 16]) -> bool {
    security_id(tenant)
        && key.len() == 33 + tenant.len()
        && key[0] as usize == tenant.len()
        && &key[1..1 + tenant.len()] == tenant.as_bytes()
        && key[1 + tenant.len()..17 + tenant.len()] == issuer
        && key[17 + tenant.len()..] == lease
}
fn retention(end: u64) -> FactsResult<u64> {
    end.checked_add(RETENTION).ok_or("storage_retention")
}
fn proof(wire: &[u8], source: ActivationSource) -> FactsResult<Value<'_>> {
    decode(wire, "ActivationAuthorization", Some(source))
}
#[expect(
    clippy::too_many_arguments,
    reason = "Every durable proof selector is checked against its independently supplied original identity."
)]
fn proof_matches(
    p: Value<'_>,
    tenant: &str,
    artifact: [u8; 32],
    activation: [u8; 32],
    candidate: [u8; 16],
    route: [u8; 32],
    attempt: [u8; 16],
    identities: [[u8; 32]; 2],
    source: ActivationSource,
) -> FactsResult<()> {
    if p.field("ActivationAuthorization", "tenant_id")?.text()? != tenant
        || p.b::<32>("ActivationAuthorization", "artifact_digest")? != artifact
        || codec::digest("activation_digest", p)? != activation
        || p.b::<16>("ActivationAuthorization", "attempt_id")? != attempt
        || p.b::<32>("ActivationAuthorization", "client_identity_digest")? != identities[0]
        || p.b::<32>("ActivationAuthorization", "server_identity_digest")? != identities[1]
        || (source == ActivationSource::LiveAuthority
            && (p.b::<16>("ActivationAuthorization", "candidate_selection")? != candidate
                || p.b::<32>("ActivationAuthorization", "route_selection")? != route))
    {
        return Err("storage_activation_binding");
    }
    Ok(())
}

pub(super) fn validate_spend(
    db: &Connection,
    identity: &SQLitePoolIdentity,
    limits: SQLitePoolLimits,
    epoch: u64,
) -> Result<()> {
    let mut statement = db.prepare("SELECT lease,version,fence,retained_until,CASE WHEN length(projection) BETWEEN 1 AND ?1 THEN projection ELSE NULL END FROM spend ORDER BY lease")?;
    let mut rows = statement.query([limits.max_record_bytes])?;
    let mut count = 0u32;
    while let Some(row) = rows.next()? {
        count = count.checked_add(1).ok_or_else(|| invalid("count"))?;
        if count > limits.max_records {
            return Err(invalid("count"));
        }
        let key = blob(row, 0)?;
        let version = uint_blob(row, 1)?;
        let fence = uint_blob(row, 2)?;
        let retained = uint_blob(row, 3)?;
        let check = || -> FactsResult<()> {
            let f = map::<29>(
                blob(row, 4).map_err(|_| "storage_blob")?,
                limits.max_record_bytes as usize,
            )?;
            let tenant = f[4].text()?;
            let p = proof(f[8].bytes()?, ActivationSource::PreauthorizedPool)?;
            let certificates = array::<2>(f[28].raw(), 128)?;
            proof_matches(
                p,
                tenant,
                bytes(f[7])?,
                bytes(f[9])?,
                bytes(f[10])?,
                bytes(f[12])?,
                bytes(f[13])?,
                [bytes(certificates[0])?, bytes(certificates[1])?],
                ActivationSource::PreauthorizedPool,
            )?;
            let issuer = bytes::<16>(f[5])?;
            let lease = bytes::<16>(f[6])?;
            let selection = p.field("ActivationAuthorization", "candidate_selection")?;
            let once = selection.field("PoolSelectionRef", "once_authority_ref")?;
            let index = f[11].uint()?;
            let mut selected = false;
            for item in selection
                .field("PoolSelectionRef", "candidate_indices")?
                .children()?
            {
                selected |= item?.uint()? == index;
            }
            let issued = f[20].uint()?;
            let cutoff = f[21].uint()?;
            let session = f[22].uint()?;
            let consumed = f[23].uint()?;
            let parent_end = f[25].uint()?;
            let _ = bytes::<32>(f[19])?;
            if f[0].uint()? != 1
                || version != 1
                || bytes::<32>(f[1])? != identity.store_id
                || f[2].uint()? != identity.generation
                || f[3].uint()? != fence
                || fence == 0
                || fence > epoch
                || !lease_key(key, tenant, issuer, lease)
                || issuer != p.b("ActivationAuthorization", "artifact_issuer_key_id")?
                || lease != p.b("ActivationAuthorization", "lease_id")?
                || !nonzero(&bytes::<16>(f[14])?)
                || !nonzero(&bytes::<16>(f[15])?)
                || f[16].uint()? == 0
                || f[17].bytes()? != selection.raw()
                || bytes::<32>(f[18])? != p.b("ActivationAuthorization", "route_selection")?
                || index >= 16
                || !selected
                || issued != p.u("ActivationAuthorization", "issued_at_ms")?
                || consumed < issued
                || consumed >= cutoff
                || cutoff > p.u("ActivationAuthorization", "activation_not_after_ms")?
                || cutoff > parent_end
                || cutoff > session
                || session > p.u("ActivationAuthorization", "session_not_after_ms")?
                || f[24].uint()? != retained
                || retained != retention(parent_end.max(consumed))?
                || f[26].text()? != identity.authority
                || f[26].text()?
                    != once
                        .field("OnceAuthorityRef", "spend_authority_id")?
                        .text()?
                || f[27].text()?
                    != once
                        .field("OnceAuthorityRef", "winner_authority_id")?
                        .text()?
            {
                return Err("storage_spend_binding");
            }
            Ok(())
        };
        check().map_err(invalid)?;
    }
    Ok(())
}

pub(super) fn validate_admission(
    db: &Connection,
    identity: &SQLitePoolIdentity,
    limits: SQLitePoolLimits,
    epoch: u64,
) -> Result<()> {
    for table in ["parent_winner", "admission"] {
        let columns = if table == "admission" {
            "state,version,owner,reservation"
        } else {
            "0,zeroblob(8),zeroblob(40),zeroblob(32)"
        };
        let mut statement = db.prepare(&format!("SELECT lease,fence,retained_until,CASE WHEN length(projection) BETWEEN 1 AND ?1 THEN projection ELSE NULL END,{columns} FROM {table} ORDER BY lease"))?;
        let mut rows = statement.query([limits.max_record_bytes])?;
        let mut count = 0u32;
        while let Some(row) = rows.next()? {
            count = count.checked_add(1).ok_or_else(|| invalid("count"))?;
            if count > limits.max_records {
                return Err(invalid("count"));
            }
            let key = blob(row, 0)?;
            let fence = uint_blob(row, 1)?;
            let retained = uint_blob(row, 2)?;
            let wire = blob(row, 3)?;
            if fence == 0 || fence > epoch {
                return Err(invalid("fence"));
            }
            if table == "parent_winner" {
                check_winner(wire, key, identity, retained).map_err(invalid)?;
                continue;
            }
            let state: u64 = row.get(4)?;
            let version = uint_blob(row, 5)?;
            let owner = blob(row, 6)?;
            let reservation = blob(row, 7)?;
            if owner.len() != 40
                || !nonzero(&owner[..16])
                || !nonzero(&owner[16..32])
                || !nonzero(&owner[32..])
                || reservation.len() != 32
                || (state == 0 && (version != 1 || nonzero(reservation)))
                || (state == 1 && (version != 2 || !nonzero(reservation)))
                || state > 1
            {
                return Err(invalid("admission_owner"));
            }
            let check = || -> FactsResult<()> {
                let f = array::<22>(wire, limits.max_record_bytes as usize)?;
                let source = match f[0].text()? {
                    "flowersec/rust-parent-admission/1" => ActivationSource::PreauthorizedPool,
                    "flowersec/rust-parent-live-admission/1" => ActivationSource::LiveAuthority,
                    _ => return Err("storage_admission_tag"),
                };
                let tenant = f[1].text()?;
                let p = proof(f[8].bytes()?, source)?;
                proof_matches(
                    p,
                    tenant,
                    bytes(f[6])?,
                    bytes(f[7])?,
                    bytes(f[11])?,
                    bytes(f[12])?,
                    bytes(f[13])?,
                    [bytes(f[15])?, bytes(f[16])?],
                    source,
                )?;
                let issued = f[18].uint()?;
                let cutoff = f[19].uint()?;
                let session = f[20].uint()?;
                let parent_end = f[21].uint()?;
                let _ = bytes::<32>(f[14])?;
                let _ = bytes::<32>(f[17])?;
                if !lease_key(
                    key,
                    tenant,
                    p.b("ActivationAuthorization", "artifact_issuer_key_id")?,
                    p.b("ActivationAuthorization", "lease_id")?,
                ) || !security_id(f[2].text()?)
                    || f[3].text()? != identity.authority
                    || f[4].text()? != p.field("ActivationAuthorization", "audience")?.text()?
                    || !security_id(f[5].text()?)
                    || f[9].bytes()?
                        != p.field("ActivationAuthorization", "candidate_selection")?
                            .raw()
                    || bytes::<32>(f[10])? != p.b("ActivationAuthorization", "route_selection")?
                    || issued != p.u("ActivationAuthorization", "issued_at_ms")?
                    || cutoff <= issued
                    || cutoff > p.u("ActivationAuthorization", "activation_not_after_ms")?
                    || cutoff > parent_end
                    || cutoff > session
                    || session > p.u("ActivationAuthorization", "session_not_after_ms")?
                    || retained != retention(parent_end.max(session))?
                {
                    return Err("storage_admission_binding");
                }
                if source == ActivationSource::PreauthorizedPool {
                    let once = p
                        .field("ActivationAuthorization", "candidate_selection")?
                        .field("PoolSelectionRef", "once_authority_ref")?;
                    if f[2].text()?
                        != once
                            .field("OnceAuthorityRef", "winner_authority_id")?
                            .text()?
                        || f[5].text()?
                            != once
                                .field("OnceAuthorityRef", "spend_authority_id")?
                                .text()?
                    {
                        return Err("storage_admission_authority");
                    }
                } else if f[2].text()? != f[5].text()? {
                    return Err("storage_admission_authority");
                }
                Ok(())
            };
            check().map_err(invalid)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "pool_storage_records_v4_tests.rs"]
pub(super) mod fixtures;

fn check_winner(
    wire: &[u8],
    key: &[u8],
    identity: &SQLitePoolIdentity,
    retained: u64,
) -> FactsResult<()> {
    let f = array::<15>(wire, 65536)?;
    let source = match f[0].text()? {
        "flowersec/rust-parent-pool-selection/1" => ActivationSource::PreauthorizedPool,
        "flowersec/rust-parent-live-selection/1" => ActivationSource::LiveAuthority,
        _ => return Err("storage_winner_tag"),
    };
    let tenant = f[1].text()?;
    let p = proof(f[7].bytes()?, source)?;
    proof_matches(
        p,
        tenant,
        bytes(f[5])?,
        bytes(f[6])?,
        bytes(f[8])?,
        bytes(f[9])?,
        bytes(f[10])?,
        [bytes(f[11])?, bytes(f[12])?],
        source,
    )?;
    let initiation = f[13].uint()?;
    let end = f[14].uint()?;
    if !lease_key(
        key,
        tenant,
        p.b("ActivationAuthorization", "artifact_issuer_key_id")?,
        p.b("ActivationAuthorization", "lease_id")?,
    ) || f[2].text()? != identity.authority
        || !security_id(f[3].text()?)
        || f[4].text()? != p.field("ActivationAuthorization", "audience")?.text()?
        || initiation < p.u("ActivationAuthorization", "activation_not_after_ms")?
        || end < p.u("ActivationAuthorization", "session_not_after_ms")?
        || initiation > end
        || (retained != retention(end)?
            && retained
                != retention(
                    initiation.max(p.u("ActivationAuthorization", "session_not_after_ms")?),
                )?)
    {
        return Err("storage_winner_binding");
    }
    if source == ActivationSource::PreauthorizedPool
        && f[2].text()?
            != p.field("ActivationAuthorization", "candidate_selection")?
                .field("PoolSelectionRef", "once_authority_ref")?
                .field("OnceAuthorityRef", "winner_authority_id")?
                .text()?
    {
        return Err("storage_winner_authority");
    }
    Ok(())
}

struct RelayFacts {
    grants: [[u8; 32]; 2],
    route: [u8; 32],
    legs: [([u8; 16], u64, u64); 2],
}

fn check_relay_parent(wire: &[u8], key: &[u8], retained: u64) -> FactsResult<RelayFacts> {
    let f = array::<11>(wire, 65536)?;
    let source = match f[0].text()? {
        "flowersec/rust-relay-pool-publication/2" => ActivationSource::PreauthorizedPool,
        "flowersec/rust-relay-live-publication/1" => ActivationSource::LiveAuthority,
        _ => return Err("storage_relay_tag"),
    };
    let p = proof(f[1].bytes()?, source)?;
    let grants = [
        decode(f[2].bytes()?, "Grant", None)?,
        decode(f[3].bytes()?, "Grant", None)?,
    ];
    let certificates = [
        decode(f[4].bytes()?, "IdentityCertificate", None)?,
        decode(f[5].bytes()?, "IdentityCertificate", None)?,
    ];
    let relay = decode(f[6].bytes()?, "IdentityCertificate", None)?;
    let candidate = decode(f[7].bytes()?, "Candidate", None)?;
    let contract = decode(f[9].bytes()?, "SessionContract", None)?;
    let [index] = bytes::<1>(f[10])?;
    if index >= 16 || candidate.u("Candidate", "path_kind")? != 1 {
        return Err("storage_relay_candidate");
    }
    let parent = grants[0].field("Grant", "parent_ref")?;
    let tenant = p.field("ActivationAuthorization", "tenant_id")?.text()?;
    let issuer = p.b::<16>("ActivationAuthorization", "artifact_issuer_key_id")?;
    let lease = p.b::<16>("ActivationAuthorization", "lease_id")?;
    let selected = candidate.b::<16>("Candidate", "candidate_id")?;
    let attempt = p.b::<16>("ActivationAuthorization", "attempt_id")?;
    if key.len() < 66
        || !lease_key(&key[..key.len() - 32], tenant, issuer, lease)
        || key[key.len() - 32..key.len() - 16] != selected
        || key[key.len() - 16..] != attempt
    {
        return Err("storage_relay_key");
    }
    let mut scratch = Vec::with_capacity(65536);
    codec::encode_head(&mut scratch, 5, 4);
    for (id, field) in [
        (0, "path_kind"),
        (1, "candidate_id"),
        (3, "client_leg"),
        (4, "server_leg"),
    ] {
        codec::encode_head(&mut scratch, 0, id);
        scratch.extend_from_slice(candidate.field("Candidate", field)?.raw());
    }
    let route = decode(&scratch, "Route", None)?;
    let route_digest = codec::digest("route_digest", route)?;
    let identities = [
        codec::digest("certificate_digest", certificates[0])?,
        codec::digest("certificate_digest", certificates[1])?,
    ];
    let relay_digest = codec::digest("certificate_digest", relay)?;
    proof_matches(
        p,
        tenant,
        parent.b("GrantParentRef", "artifact_digest")?,
        codec::digest("activation_digest", p)?,
        selected,
        route_digest,
        attempt,
        identities,
        source,
    )?;
    let initiation = parent.u("GrantParentRef", "initiation_not_after_ms")?;
    let end = parent.u("GrantParentRef", "session_not_after_ms")?;
    if parent.field("GrantParentRef", "tenant_id")?.text()? != tenant
        || parent.b::<16>("GrantParentRef", "artifact_issuer_key_id")? != issuer
        || parent.b::<16>("GrantParentRef", "lease_id")? != lease
        || p.u("ActivationAuthorization", "issued_at_ms")?
            < parent.u("GrantParentRef", "issued_at_ms")?
        || p.u("ActivationAuthorization", "activation_not_after_ms")? > initiation
        || p.u("ActivationAuthorization", "session_not_after_ms")? > end
        || retained != retention(end)?
        || relay.u("IdentityCertificate", "role")? != 2
        || relay.field("IdentityCertificate", "tenant_id")?.text()? != tenant
    {
        return Err("storage_relay_parent");
    }
    if source == ActivationSource::PreauthorizedPool {
        let set = decode(f[8].bytes()?, "PoolSelectionSet", None)?;
        let selection = p.field("ActivationAuthorization", "candidate_selection")?;
        if set.b::<32>("PoolSelectionSet", "artifact_digest")?
            != p.b("ActivationAuthorization", "artifact_digest")?
            || codec::digest("candidate_set_digest", set)?
                != selection.b("PoolSelectionRef", "candidate_set_digest")?
            || codec::digest("route_set_digest", set)?
                != p.b("ActivationAuthorization", "route_selection")?
        {
            return Err("storage_relay_selection");
        }
        let indices = selection.field("PoolSelectionRef", "candidate_indices")?;
        let entries = set.field("PoolSelectionSet", "entries")?;
        if indices.len()? != entries.len()? {
            return Err("storage_relay_selection");
        }
        let mut found = false;
        for (i, entry) in indices.children()?.zip(entries.children()?) {
            let i = i?.uint()?;
            let entry = entry?;
            if entry.u("PoolRouteRef", "candidate_index")? != i {
                return Err("storage_relay_selection");
            }
            if i == u64::from(index) {
                found = entry.b::<16>("PoolRouteRef", "candidate_id")? == selected
                    && entry.b::<32>("PoolRouteRef", "route_digest")? == route_digest;
            }
        }
        if !found {
            return Err("storage_relay_selection");
        }
    } else if !f[8].bytes()?.is_empty() {
        return Err("storage_relay_selection");
    }
    let mut result = RelayFacts {
        grants: [[0; 32]; 2],
        route: route_digest,
        legs: [([0; 16], 0, 0); 2],
    };
    for side in 0..2 {
        let grant = grants[side];
        let certificate = certificates[side];
        let leg = route.field(
            "Route",
            if side == 0 {
                "client_leg"
            } else {
                "server_leg"
            },
        )?;
        result.legs[side] = (
            leg.b("Leg", "leg_id")?,
            leg.u("Leg", "dialer_role")?,
            leg.u("Leg", "listener_role")?,
        );
        let ids = grant.field("Grant", "identity_digests")?;
        if certificate.u("IdentityCertificate", "role")? != side as u64
            || certificate
                .field("IdentityCertificate", "tenant_id")?
                .text()?
                != tenant
            || certificate
                .field("IdentityCertificate", "audience")?
                .text()?
                != p.field("ActivationAuthorization", "audience")?.text()?
            || certificate
                .field("IdentityCertificate", "crypto_profile_id")?
                .text()?
                != certificates[0]
                    .field("IdentityCertificate", "crypto_profile_id")?
                    .text()?
            || grant.field("Grant", "parent_ref")?.raw() != parent.raw()
            || grant.field("Grant", "route_descriptor")?.raw() != route.raw()
            || grant.field("Grant", "tenant_id")?.text()? != tenant
            || grant.b::<16>("Grant", "attempt_id")? != attempt
            || grant.b::<32>("Grant", "session_contract_digest")?
                != codec::digest("session_contract_digest", contract)?
            || grant.b::<32>("Grant", "relay_identity_digest")? != relay_digest
            || bytes::<32>(ids.at(0)?)? != identities[0]
            || bytes::<32>(ids.at(1)?)? != identities[1]
            || grant
                .field("Grant", "namespace")?
                .u("GrantNamespace", "role_mask")?
                != 4 | (1u64 << side)
            || grant.field("Grant", "audience")?.text()?
                != relay.field("IdentityCertificate", "audience")?.text()?
            || contract.u("SessionContract", "max_frame")?.checked_add(8)
                != Some(
                    grant
                        .field("Grant", "limits")?
                        .u("GrantLimits", "max_envelope_bytes")?,
                )
            || grant.b::<16>("Grant", "pairing_id")? != grants[0].b("Grant", "pairing_id")?
            || grant.field("Grant", "legs")?.raw() != grants[0].field("Grant", "legs")?.raw()
            || grant.field("Grant", "limits")?.raw() != grants[0].field("Grant", "limits")?.raw()
        {
            return Err("storage_relay_grant");
        }
    }
    for (side, grant) in grants.into_iter().enumerate() {
        result.grants[side] = codec::digest("grant_digest", grant)?;
    }
    Ok(result)
}

pub(super) fn validate_relay(
    db: &Connection,
    _identity: &SQLitePoolIdentity,
    limits: SQLitePoolLimits,
    epoch: u64,
) -> Result<()> {
    let mut statement = db.prepare("SELECT lease,publication,fence,retained_until,CASE WHEN length(projection) BETWEEN 1 AND ?1 AND length(projection)<=65536 THEN projection ELSE NULL END FROM relay_parent ORDER BY lease")?;
    let mut rows = statement.query([limits.max_record_bytes])?;
    let mut count = 0u32;
    while let Some(row) = rows.next()? {
        count = count.checked_add(1).ok_or_else(|| invalid("count"))?;
        let fence = uint_blob(row, 2)?;
        if count > limits.max_records
            || blob(row, 1)?.len() != 16
            || !nonzero(blob(row, 1)?)
            || fence == 0
            || fence > epoch
        {
            return Err(invalid("relay_parent"));
        }
        check_relay_parent(blob(row, 4)?, blob(row, 0)?, uint_blob(row, 3)?).map_err(invalid)?;
    }
    drop(rows);
    drop(statement);
    let mut statement = db.prepare("SELECT c.leg,c.parent,c.owner,c.fence,c.retained_until,CASE WHEN length(c.projection) BETWEEN 1 AND 4096 AND length(c.projection)<=?1 THEN c.projection ELSE NULL END,p.fence,p.retained_until,CASE WHEN length(p.projection) BETWEEN 1 AND 65536 AND length(p.projection)<=?1 THEN p.projection ELSE NULL END FROM relay_claim c JOIN relay_parent p ON p.lease=c.parent AND p.publication=c.publication ORDER BY c.leg")?;
    let mut rows = statement.query([limits.max_record_bytes])?;
    let mut count = 0u32;
    while let Some(row) = rows.next()? {
        count = count.checked_add(1).ok_or_else(|| invalid("count"))?;
        if count > limits.max_records {
            return Err(invalid("count"));
        }
        let key = blob(row, 0)?;
        let parent = blob(row, 1)?;
        let owner = blob(row, 2)?;
        let fence = uint_blob(row, 3)?;
        let retained = uint_blob(row, 4)?;
        if key.len() < 35
            || parent.len() < 66
            || key.len() + 31 != parent.len()
            || key[..key.len() - 1] != parent[..parent.len() - 32]
            || owner.len() != 56
            || !nonzero(&owner[..16])
            || !nonzero(&owner[16..32])
            || !nonzero(&owner[32..48])
            || !nonzero(&owner[48..])
            || fence == 0
            || fence > epoch
            || fence != uint_blob(row, 6)?
            || retained != uint_blob(row, 7)?
        {
            return Err(invalid("relay_claim"));
        }
        let facts = check_relay_parent(blob(row, 8)?, parent, retained).map_err(invalid)?;
        let check = || -> FactsResult<()> {
            let side = *key.last().ok_or("storage_relay_side")? as usize;
            if side > 1 {
                return Err("storage_relay_side");
            }
            let f = array::<4>(blob(row, 5).map_err(|_| "storage_blob")?, 4096)?;
            let context = decode(f[2].bytes()?, "HopChallengeContext", None)?;
            let proof = bytes::<64>(f[3])?;
            let (leg, dialer, listener) = facts.legs[side];
            let carrier = if dialer == 2 {
                context.b::<16>("HopChallengeContext", "dialer_incarnation")?
            } else {
                context.b::<16>("HopChallengeContext", "listener_incarnation")?
            };
            if bytes::<32>(f[0])? != facts.grants[side]
                || bytes::<32>(f[1])? != facts.route
                || !nonzero(&proof)
                || context.b::<16>("HopChallengeContext", "leg_id")? != leg
                || context.u("HopChallengeContext", "dialer_role")? != dialer
                || context.u("HopChallengeContext", "listener_role")? != listener
                || carrier != owner[32..48]
            {
                return Err("storage_relay_possession");
            }
            Ok(())
        };
        check().map_err(invalid)?;
    }
    Ok(())
}
