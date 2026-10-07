//! Verification of a public projection received from an independently installed
//! original issuer. No Artifact, PSK, Session nonce or endpoint owner is decoded.
use super::tunnel::{TunnelHopInput, VerifiedTunnelHop, verify_public_hop};
use super::*;

pub(crate) struct RelayPublicInput<'a> {
    pub(crate) source: ActivationSource,
    pub(crate) live_winner_authority: Option<&'a str>,
    pub(crate) activation: &'a [u8],
    pub(crate) grants: [&'a [u8]; 2],
    pub(crate) certificates: [&'a [u8]; 2],
    pub(crate) relay_certificate: &'a [u8],
    pub(crate) candidate: &'a [u8],
    pub(crate) selection_set: &'a [u8],
    pub(crate) contract: &'a [u8],
    pub(crate) candidate_index: u8,
    pub(crate) service: &'a str,
    pub(crate) relay_audience: &'a str,
}
/// Public evidence for exactly one endpoint role received by the original
/// authenticated control invocation. No peer receipt or row can construct the
/// invocation that owns this verification result.
pub(crate) struct RelayPublicLegInput<'a> {
    pub(crate) source: ActivationSource,
    pub(crate) live_winner_authority: Option<&'a str>,
    pub(crate) activation: &'a [u8],
    pub(crate) grant: &'a [u8],
    pub(crate) certificates: [&'a [u8]; 2],
    pub(crate) relay_certificate: &'a [u8],
    pub(crate) candidate: &'a [u8],
    pub(crate) selection_set: &'a [u8],
    pub(crate) contract: &'a [u8],
    pub(crate) candidate_index: u8,
    pub(crate) service: &'a str,
    pub(crate) relay_audience: &'a str,
    pub(crate) endpoint_role: u8,
    pub(crate) prepared_account: Option<&'a ResourceAccount>,
}
pub(crate) struct RelayPublicLegAdmission {
    pub(crate) account: ResourceAccount,
    pub(crate) hop: VerifiedTunnelHop,
    pub(crate) tenant: String,
    pub(crate) issuer: [u8; 16],
    pub(crate) lease: [u8; 16],
    pub(crate) artifact: [u8; 32],
    pub(crate) activation: [u8; 32],
    pub(crate) identities: [[u8; 32]; 2],
    pub(crate) candidate: [u8; 16],
    pub(crate) route: [u8; 32],
    pub(crate) attempt: [u8; 16],
    pub(crate) audience: String,
    pub(crate) winner_authority: String,
    pub(crate) parent_initiation: u64,
    pub(crate) parent_end: u64,
    pub(crate) initiation: u64,
    pairing_projection: Vec<u8>,
    _charge: crate::environment_v4::ResourceCharge,
}
pub(crate) struct RelayPublicAdmission {
    pub(crate) accounts: [ResourceAccount; 2],
    pub(crate) hops: [VerifiedTunnelHop; 2],
    pub(crate) tenant: String,
    pub(crate) issuer: [u8; 16],
    pub(crate) lease: [u8; 16],
    pub(crate) artifact: [u8; 32],
    pub(crate) activation: [u8; 32],
    pub(crate) identities: [[u8; 32]; 2],
    pub(crate) candidate: [u8; 16],
    pub(crate) route: [u8; 32],
    pub(crate) attempt: [u8; 16],
    pub(crate) audience: String,
    pub(crate) winner_authority: String,
    pub(crate) parent_initiation: u64,
    pub(crate) parent_end: u64,
    pub(crate) initiation: u64,
    _charges: [crate::environment_v4::ResourceCharge; 2],
}

/// This verifier establishes signatures and facts only. Its caller must own
/// the authenticated original mTLS invocation; these bytes confer no adoption,
/// row lookup, retry, replay or original publication capability.
pub(crate) fn reserve_original_publication(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: RelayPublicInput<'_>,
) -> Result<RelayPublicAdmission, EnvironmentError> {
    let verification = environment.reserve_environment(ResourceLimits {
        sdk_bytes: 65536,
        items: 2,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let grants = [
        decode(input.grants[0], "Grant", 9302, Context::default())?,
        decode(input.grants[1], "Grant", 9302, Context::default())?,
    ];
    if grants[0]
        .field("Grant", "parent_ref")
        .map_err(invalid)?
        .raw()
        != grants[1]
            .field("Grant", "parent_ref")
            .map_err(invalid)?
            .raw()
        || grants[0]
            .field("Grant", "route_descriptor")
            .map_err(invalid)?
            .raw()
            != grants[1]
                .field("Grant", "route_descriptor")
                .map_err(invalid)?
                .raw()
        || grants[0].field("Grant", "legs").map_err(invalid)?.raw()
            != grants[1].field("Grant", "legs").map_err(invalid)?.raw()
        || grants[0].field("Grant", "limits").map_err(invalid)?.raw()
            != grants[1].field("Grant", "limits").map_err(invalid)?.raw()
        || bytes::<32>(grants[0], "Grant", "session_contract_digest")?
            != bytes::<32>(grants[1], "Grant", "session_contract_digest")?
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    drop(verification);
    let admit = |role: u8| {
        reserve_original_leg(
            environment,
            verifiers,
            RelayPublicLegInput {
                source: input.source,
                live_winner_authority: input.live_winner_authority,
                activation: input.activation,
                grant: input.grants[usize::from(role)],
                certificates: input.certificates,
                relay_certificate: input.relay_certificate,
                candidate: input.candidate,
                selection_set: input.selection_set,
                contract: input.contract,
                candidate_index: input.candidate_index,
                service: input.service,
                relay_audience: input.relay_audience,
                endpoint_role: role,
                prepared_account: None,
            },
        )
    };
    let a = admit(0)?;
    let b = admit(1)?;
    pair_original_legs(a, b)
}

/// Join only the two verified leg owners retained by this original control
/// invocation. Pairing neither reparses receipts nor allocates new Accounts.
pub(crate) fn pair_original_legs(
    a: RelayPublicLegAdmission,
    b: RelayPublicLegAdmission,
) -> Result<RelayPublicAdmission, EnvironmentError> {
    a.account.check()?;
    b.account.check()?;
    if a.tenant != b.tenant
        || a.issuer != b.issuer
        || a.lease != b.lease
        || a.artifact != b.artifact
        || a.activation != b.activation
        || a.identities != b.identities
        || a.candidate != b.candidate
        || a.route != b.route
        || a.attempt != b.attempt
        || a.audience != b.audience
        || a.winner_authority != b.winner_authority
        || a.parent_initiation != b.parent_initiation
        || a.parent_end != b.parent_end
        || a.hop.endpoint_role != 0
        || b.hop.endpoint_role != 1
        || a.hop.pairing_id != b.hop.pairing_id
        || a.hop.relay_identity_digest != b.hop.relay_identity_digest
        || a.hop.relay_key != b.hop.relay_key
        || a.hop.limits != b.hop.limits
        || a.pairing_projection != b.pairing_projection
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let initiation = a.initiation.min(b.initiation);
    Ok(RelayPublicAdmission {
        accounts: [a.account, b.account],
        hops: [a.hop, b.hop],
        tenant: a.tenant,
        issuer: a.issuer,
        lease: a.lease,
        artifact: a.artifact,
        activation: a.activation,
        identities: a.identities,
        candidate: a.candidate,
        route: a.route,
        attempt: a.attempt,
        audience: a.audience,
        winner_authority: a.winner_authority,
        parent_initiation: a.parent_initiation,
        parent_end: a.parent_end,
        initiation,
        _charges: [a._charge, b._charge],
    })
}

pub(crate) fn reserve_original_leg(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    input: RelayPublicLegInput<'_>,
) -> Result<RelayPublicLegAdmission, EnvironmentError> {
    if input.prepared_account.is_some() && input.source != ActivationSource::LiveAuthority
        || verifiers.is_empty()
        || verifiers.len() > 8
        || input.candidate_index >= 16
        || input.endpoint_role > 1
        || verifiers.iter().enumerate().any(|(index, verifier)| {
            verifiers[..index]
                .iter()
                .any(|old| std::ptr::eq(*old, *verifier))
        })
    {
        return Err(EnvironmentError::Configuration);
    }
    for verifier in verifiers {
        if !Arc::ptr_eq(environment, &verifier.environment) || !verifier.bootstrapped {
            return Err(EnvironmentError::Configuration);
        }
        verifier.check()?;
    }
    // Decode/signature work and all retained exact public evidence are charged
    // before allocation. The returned accounts fund the physical relay owners.
    let _verification = environment.reserve_environment(ResourceLimits {
        sdk_bytes: 393216,
        items: 16,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let now = environment.sample()?;
    let mut signature = Vec::new();
    signature
        .try_reserve_exact(ARTIFACT_BYTES + 128)
        .map_err(|_| EnvironmentError::Capacity)?;
    let mut route_scratch = Vec::new();
    route_scratch
        .try_reserve_exact(ARTIFACT_BYTES)
        .map_err(|_| EnvironmentError::Capacity)?;
    let grant = decode(input.grant, "Grant", 9302, Context::default())?;
    let parent = grant.field("Grant", "parent_ref").map_err(invalid)?;
    let context = NamespaceContext::resolve_namespace(
        environment,
        verifiers,
        parent,
        "GrantParentRef",
        "authority_generation",
        now,
    )?;
    let tenant = text(parent, "GrantParentRef", "tenant_id")?;
    let issuer = bytes::<16>(parent, "GrantParentRef", "artifact_issuer_key_id")?;
    let lease = bytes::<16>(parent, "GrantParentRef", "lease_id")?;
    let artifact = bytes::<32>(parent, "GrantParentRef", "artifact_digest")?;
    let parent_issued = uint(parent, "GrantParentRef", "issued_at_ms")?;
    let parent_initiation = uint(parent, "GrantParentRef", "initiation_not_after_ms")?;
    let parent_end = uint(parent, "GrantParentRef", "session_not_after_ms")?;
    super::super::interval(now, parent_issued, parent_initiation)?;
    let cohort = context.issuance(
        parent,
        "GrantParentRef",
        CredentialKind::Connection,
        parent_end,
    )?;
    let proof = decode(
        input.activation,
        "ActivationAuthorization",
        ACTIVATION_BYTES,
        Context::with_activation_source(input.source),
    )?;
    if text(proof, "ActivationAuthorization", "tenant_id")? != tenant
        || bytes::<16>(proof, "ActivationAuthorization", "artifact_issuer_key_id")? != issuer
        || bytes::<16>(proof, "ActivationAuthorization", "lease_id")? != lease
        || bytes::<32>(proof, "ActivationAuthorization", "artifact_digest")? != artifact
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let audience = text(proof, "ActivationAuthorization", "audience")?;
    let certificates = [
        decode(
            input.certificates[0],
            "IdentityCertificate",
            CERTIFICATE_BYTES,
            Context::default(),
        )?,
        decode(
            input.certificates[1],
            "IdentityCertificate",
            CERTIFICATE_BYTES,
            Context::default(),
        )?,
    ];
    let profile = text(certificates[0], "IdentityCertificate", "crypto_profile_id")?;
    verify_parent_issuer(
        context,
        issuer,
        cohort,
        parent_issued,
        parent_end,
        audience,
        profile,
    )?;
    let (max_staleness_ms, max_head_signer_lifetime_ms) =
        context.policy(parent, "GrantParentRef")?;
    let binding = NamespaceBinding {
        namespace: context.verifier.key,
        generation: context.generation,
        kind: CredentialKind::Connection,
        cohort,
        issuer,
        credential: artifact,
        lease: Some((issuer, lease)),
        max_staleness_ms,
        max_head_signer_lifetime_ms,
    };
    let client_context = NamespaceContext::resolve(
        environment,
        verifiers,
        certificates[0],
        "IdentityCertificate",
        now,
    )?;
    let server_context = NamespaceContext::resolve(
        environment,
        verifiers,
        certificates[1],
        "IdentityCertificate",
        now,
    )?;
    let identities = [
        bytes(proof, "ActivationAuthorization", "client_identity_digest")?,
        bytes(proof, "ActivationAuthorization", "server_identity_digest")?,
    ];
    let (client_binding, client_start, client_end) = verify_public_certificate(
        client_context,
        certificates[0],
        tenant,
        audience,
        profile,
        0,
        identities[0],
        now,
        &mut signature,
    )?;
    let (server_binding, server_start, server_end) = verify_public_certificate(
        server_context,
        certificates[1],
        tenant,
        audience,
        profile,
        1,
        identities[1],
        now,
        &mut signature,
    )?;
    let (activation_binding, activation_start, activation_end, session_end) =
        verify_public_activation(
            context,
            proof,
            input.source,
            binding,
            parent_issued,
            parent_initiation,
            parent_end,
            now,
            &mut signature,
        )?;
    let candidate = decode(
        input.candidate,
        "Candidate",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    if uint(candidate, "Candidate", "path_kind")? != 1 {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let contract = decode(
        input.contract,
        "SessionContract",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    let route = route_digest(candidate, &mut route_scratch)?;
    let candidate_id = bytes::<16>(candidate, "Candidate", "candidate_id")?;
    let winner_authority = match input.source {
        ActivationSource::PreauthorizedPool => {
            if input.live_winner_authority.is_some() {
                return Err(EnvironmentError::Configuration);
            }
            let authority = once_authority(context, issuer)?;
            verify_pool_selection(
                proof,
                authority,
                input.selection_set,
                input.candidate_index,
                candidate_id,
                route,
            )?;
            text(authority, "OnceAuthorityRef", "winner_authority_id")?.to_owned()
        }
        ActivationSource::LiveAuthority => {
            let authority = input
                .live_winner_authority
                .ok_or(EnvironmentError::Configuration)?;
            if authority.is_empty()
                || authority.len() > 128
                || !authority.bytes().all(|byte| byte.is_ascii_graphic())
                || input.candidate_index != 0
                || !input.selection_set.is_empty()
                || bytes::<16>(proof, "ActivationAuthorization", "candidate_selection")?
                    != candidate_id
                || bytes::<32>(proof, "ActivationAuthorization", "route_selection")? != route
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            authority.to_owned()
        }
    };
    let contexts = [context, client_context, server_context];
    let bindings = [binding, client_binding, server_binding];
    let hop = verify_public_hop(
        environment,
        verifiers,
        TunnelHopInput {
            grant: input.grant,
            relay_certificate: input.relay_certificate,
            endpoint_role: input.endpoint_role,
            service: input.service,
            audience: input.relay_audience,
        },
        candidate,
        contexts,
        bindings,
        certificates,
        tenant,
        profile,
        contract,
        now,
        &mut signature,
        &mut route_scratch,
    )?;
    let attempt = bytes::<16>(proof, "ActivationAuthorization", "attempt_id")?;
    if hop.facts.attempt_id != attempt {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let initiation = parent_initiation.min(activation_end).min(hop.not_after_ms);
    let bounds = AuthorizationBounds {
        not_before_ms: parent_issued
            .max(activation_start)
            .max(client_start)
            .max(server_start)
            .max(hop.not_before_ms),
        not_after_ms: session_end
            .min(client_end)
            .min(server_end)
            .min(hop.not_after_ms),
        freshness_not_after_ms: initiation,
    };
    let account = match input.prepared_account {
        Some(account) if account.belongs_to(environment) => account.clone(),
        Some(_) => return Err(EnvironmentError::Configuration),
        None => environment.admit(binding.namespace.tenant, bounds)?,
    };
    let mut installed = Vec::with_capacity(6);
    for entry in [binding, client_binding, server_binding, activation_binding]
        .into_iter()
        .chain(hop.bindings)
    {
        if !installed.contains(&entry) {
            installed.push(entry);
        }
    }
    if input.prepared_account.is_some() {
        // Preparation binds these exact two installed endpoint certificates.
        // Every new authority dependency tightens this same Account; its native
        // reservations and monotonic cutoff remain owned by the original leg.
        for dependency in installed
            .iter()
            .filter(|dependency| **dependency != client_binding && **dependency != server_binding)
        {
            account.install_live_activation(*dependency, bounds)?;
        }
    } else {
        account.bind_namespaces(&installed)?;
    }
    account.check()?;
    // Keep the returned facts and metadata charged across the original control
    // handoff. The caller may later transfer them into a paired publication.
    let charge = account.reserve(ResourceLimits {
        sdk_bytes: 16384,
        items: 2,
        work_slots: 1,
        ..ResourceLimits::default()
    })?;
    let mut pairing_projection = Vec::new();
    pairing_projection
        .try_reserve_exact(9430)
        .map_err(|_| EnvironmentError::Capacity)?;
    codec::encode_head(&mut pairing_projection, 4, 5);
    for field in ["parent_ref", "route_descriptor", "legs", "limits"] {
        let original = grant.field("Grant", field).map_err(invalid)?.raw();
        codec::encode_head(&mut pairing_projection, 2, original.len() as u64);
        pairing_projection.extend_from_slice(original);
    }
    put_bytes(
        &mut pairing_projection,
        &bytes::<32>(grant, "Grant", "session_contract_digest")?,
    );
    if pairing_projection.len() > 9430 {
        return Err(EnvironmentError::Capacity);
    }
    super::super::interval(
        environment.sample()?,
        parent_issued.max(activation_start),
        initiation,
    )?;
    Ok(RelayPublicLegAdmission {
        account,
        hop: hop.facts,
        tenant: tenant.to_owned(),
        issuer,
        lease,
        artifact,
        activation: codec::digest("activation_digest", proof).map_err(invalid)?,
        identities,
        candidate: candidate_id,
        route,
        attempt,
        audience: audience.to_owned(),
        winner_authority,
        parent_initiation,
        parent_end,
        initiation,
        pairing_projection,
        _charge: charge,
    })
}

fn verify_parent_issuer(
    context: NamespaceContext<'_>,
    issuer: [u8; 16],
    cohort: u64,
    issued: u64,
    end: u64,
    audience: &str,
    profile: &str,
) -> Result<(), EnvironmentError> {
    if context.is_retired(issuer)? {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    for raw in context.verifier.history.iter().rev() {
        let trust = decode(
            raw,
            "TrustConfig",
            super::super::TRUST_BYTES,
            Context::default(),
        )?;
        for entry in trust
            .field("TrustConfig", "issuer_authorizations")
            .and_then(Value::children)
            .map_err(invalid)?
        {
            let entry = entry.map_err(invalid)?;
            let schema = "CredentialIssuerAuthorization";
            if bytes::<16>(entry, schema, "issuer_key_id")? == issuer
                && uint(entry, schema, "credential_kind")? == 1
                && text(entry, schema, "tenant_id")? == context.verifier.root.tenant
                && text(entry, schema, "revocation_authority_id")?
                    == context.verifier.root.authority
                && bytes::<32>(entry, schema, "namespace_capacity_digest")?
                    == context.capacity_digest
                && uint(entry, schema, "authority_generation")? == context.generation
                && text(entry, schema, "audience")? == audience
                && text(entry, schema, "crypto_profile_id")? == profile
                && issued >= uint(entry, schema, "signing_not_before_ms")?
                && issued < uint(entry, schema, "signing_not_after_ms")?
                && cohort >= uint(entry, schema, "first_cohort")?
                && cohort <= uint(entry, schema, "last_cohort")?
                && end <= uint(entry, schema, "max_credential_not_after_ms")?
            {
                return Ok(());
            }
        }
    }
    Err(EnvironmentError::AuthorizationDenied)
}

fn verify_pool_selection(
    proof: Value<'_>,
    authority: Value<'_>,
    wire: &[u8],
    index: u8,
    candidate: [u8; 16],
    route: [u8; 32],
) -> Result<(), EnvironmentError> {
    let set = decode(wire, "PoolSelectionSet", SET_BYTES, Context::default())?;
    let selection = proof
        .field("ActivationAuthorization", "candidate_selection")
        .map_err(invalid)?;
    if selection
        .field("PoolSelectionRef", "once_authority_ref")
        .map_err(invalid)?
        .raw()
        != authority.raw()
        || bytes::<32>(set, "PoolSelectionSet", "artifact_digest")?
            != bytes(proof, "ActivationAuthorization", "artifact_digest")?
        || codec::digest("candidate_set_digest", set).map_err(invalid)?
            != bytes(selection, "PoolSelectionRef", "candidate_set_digest")?
        || codec::digest("route_set_digest", set).map_err(invalid)?
            != bytes(proof, "ActivationAuthorization", "route_selection")?
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let indices = selection
        .field("PoolSelectionRef", "candidate_indices")
        .map_err(invalid)?;
    let entries = set.field("PoolSelectionSet", "entries").map_err(invalid)?;
    if indices.len().map_err(invalid)? != entries.len().map_err(invalid)? {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let mut found = false;
    for (selected, entry) in indices
        .children()
        .map_err(invalid)?
        .zip(entries.children().map_err(invalid)?)
    {
        let selected = selected.and_then(Value::uint).map_err(invalid)?;
        let entry = entry.map_err(invalid)?;
        if uint(entry, "PoolRouteRef", "candidate_index")? != selected {
            return Err(EnvironmentError::AuthorizationDenied);
        }
        if selected == u64::from(index) {
            if bytes::<16>(entry, "PoolRouteRef", "candidate_id")? != candidate
                || bytes::<32>(entry, "PoolRouteRef", "route_digest")? != route
            {
                return Err(EnvironmentError::AuthorizationDenied);
            }
            found = true;
        }
    }
    if !found {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    Ok(())
}

/// Exact original signed set witness retained by the trusted issuance owner.
pub(crate) fn pool_set(artifact: Value<'_>, proof: Value<'_>) -> Result<Vec<u8>, EnvironmentError> {
    let indices = proof
        .field("ActivationAuthorization", "candidate_selection")
        .and_then(|value| value.field("PoolSelectionRef", "candidate_indices"))
        .map_err(invalid)?;
    let candidates = artifact.field("Artifact", "candidates").map_err(invalid)?;
    let mut output = Vec::with_capacity(SET_BYTES);
    let mut route_scratch = Vec::with_capacity(ARTIFACT_BYTES);
    codec::encode_head(&mut output, 5, 2);
    codec::encode_head(&mut output, 0, 0);
    put_bytes(
        &mut output,
        &bytes::<32>(proof, "ActivationAuthorization", "artifact_digest")?,
    );
    codec::encode_head(&mut output, 0, 1);
    codec::encode_head(&mut output, 4, indices.len().map_err(invalid)? as u64);
    for index in indices.children().map_err(invalid)? {
        let index = index.and_then(Value::uint).map_err(invalid)?;
        let candidate = candidates.at(index as usize).map_err(invalid)?;
        let route = route_digest(candidate, &mut route_scratch)?;
        codec::encode_head(&mut output, 5, 3);
        codec::encode_head(&mut output, 0, 0);
        codec::encode_head(&mut output, 0, index);
        codec::encode_head(&mut output, 0, 1);
        put_bytes(
            &mut output,
            &bytes::<16>(candidate, "Candidate", "candidate_id")?,
        );
        codec::encode_head(&mut output, 0, 2);
        put_bytes(&mut output, &route);
    }
    if output.len() > SET_BYTES {
        return Err(EnvironmentError::Capacity);
    }
    Ok(output)
}

/// Admit only independently installed public endpoint certificates for bounded
/// native preparation. This creates no parent winner, HOP or forwarding permit.
pub(crate) fn reserve_live_preparation(
    environment: &Arc<EnvironmentRoot>,
    verifiers: &[&NamespaceVerifier],
    certificates: [&[u8]; 2],
    tenant: &str,
    initiation_end: u64,
    session_end: u64,
) -> Result<[ResourceAccount; 2], EnvironmentError> {
    let _verification = environment.reserve_environment(ResourceLimits {
        sdk_bytes: 196608,
        items: 6,
        work_slots: 2,
        ..ResourceLimits::default()
    })?;
    let now = environment.sample()?;
    let client = decode(
        certificates[0],
        "IdentityCertificate",
        8192,
        Context::default(),
    )?;
    let audience = text(client, "IdentityCertificate", "audience")?;
    let profile = text(client, "IdentityCertificate", "crypto_profile_id")?;
    let mut signature = Vec::with_capacity(ARTIFACT_BYTES);
    let mut bindings = Vec::with_capacity(2);
    let mut start = 0;
    let mut end = session_end;
    for (role, certificate) in certificates.iter().enumerate() {
        let certificate = decode(certificate, "IdentityCertificate", 8192, Context::default())?;
        let context = NamespaceContext::resolve(
            environment,
            verifiers,
            certificate,
            "IdentityCertificate",
            now,
        )?;
        let digest = codec::digest("certificate_digest", certificate).map_err(invalid)?;
        let (binding, issued, expires) = verify_public_certificate(
            context,
            certificate,
            tenant,
            audience,
            profile,
            role as u64,
            digest,
            now,
            &mut signature,
        )?;
        bindings.push(binding);
        start = start.max(issued);
        end = end.min(expires);
    }
    super::super::interval(now, start, initiation_end.min(end))?;
    let admit = || -> Result<ResourceAccount, EnvironmentError> {
        let account = environment.admit(
            bindings[0].namespace.tenant,
            AuthorizationBounds {
                not_before_ms: start,
                not_after_ms: end,
                freshness_not_after_ms: initiation_end,
            },
        )?;
        account.bind_namespaces(&bindings)?;
        account.check()?;
        Ok(account)
    };
    Ok([admit()?, admit()?])
}
/// Match the first actual Connect request against installed public preparation
/// policy. Its random attempt belongs to the original client invocation; the
/// relay neither predicts it nor constructs a replacement endpoint permit.
#[expect(
    clippy::too_many_arguments,
    reason = "The live request is matched against every independently authenticated parent identity and time bound."
)]
pub(crate) fn match_live_preparation_request(
    request_wire: &[u8],
    certificates: [&[u8]; 2],
    candidate_wire: &[u8],
    tenant: &str,
    issuer: [u8; 16],
    artifact: [u8; 32],
    lease: [u8; 16],
    maximum_initiation_end: u64,
) -> Result<u64, EnvironmentError> {
    let request = codec::decode_control_array(
        request_wire,
        Limits {
            bytes: 1024,
            nodes: 64,
        },
    )
    .map_err(invalid)?;
    let candidate = decode(
        candidate_wire,
        "Candidate",
        ARTIFACT_BYTES,
        Context::default(),
    )?;
    if request.len().map_err(invalid)? != 13
        || request.at(0).and_then(Value::text).map_err(invalid)? != "live-authorization-1"
        || request.at(1).and_then(Value::text).map_err(invalid)? != tenant
        || request.at(4).and_then(Value::bytes).map_err(invalid)? != issuer
        || request.at(5).and_then(Value::bytes).map_err(invalid)? != lease
        || request.at(7).and_then(Value::bytes).map_err(invalid)? != artifact
        || request.at(12).and_then(Value::uint).map_err(invalid)? != 1
        || uint(candidate, "Candidate", "path_kind")? != 1
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let attempt: [u8; 16] = request
        .at(6)
        .and_then(Value::bytes)
        .map_err(invalid)?
        .try_into()
        .map_err(|_| EnvironmentError::AuthorizationDenied)?;
    let cutoff = request.at(11).and_then(Value::uint).map_err(invalid)?;
    if attempt == [0; 16] || cutoff == 0 || cutoff > maximum_initiation_end {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    let winner = request.at(10).map_err(invalid)?;
    let mut route_scratch = Vec::with_capacity(ARTIFACT_BYTES);
    if winner.raw().first().map(|byte| byte >> 5) != Some(4)
        || winner.len().map_err(invalid)? != 3
        || winner.at(0).and_then(Value::uint).map_err(invalid)? != 0
        || winner.at(1).and_then(Value::bytes).map_err(invalid)?
            != bytes::<16>(candidate, "Candidate", "candidate_id")?
        || winner.at(2).and_then(Value::bytes).map_err(invalid)?
            != route_digest(candidate, &mut route_scratch)?
    {
        return Err(EnvironmentError::AuthorizationDenied);
    }
    for (role, certificate) in certificates.into_iter().enumerate() {
        let certificate = decode(certificate, "IdentityCertificate", 8192, Context::default())?;
        if request.at(2).and_then(Value::text).map_err(invalid)?
            != text(certificate, "IdentityCertificate", "audience")?
            || request.at(3).and_then(Value::text).map_err(invalid)?
                != text(certificate, "IdentityCertificate", "crypto_profile_id")?
            || request
                .at(8 + role)
                .and_then(Value::bytes)
                .map_err(invalid)?
                != codec::digest("certificate_digest", certificate).map_err(invalid)?
        {
            return Err(EnvironmentError::AuthorizationDenied);
        }
    }
    Ok(cutoff)
}

pub(crate) fn preparation_route_digest(candidate: &[u8]) -> Result<[u8; 32], EnvironmentError> {
    let candidate = decode(candidate, "Candidate", ARTIFACT_BYTES, Context::default())?;
    route_digest(candidate, &mut Vec::with_capacity(ARTIFACT_BYTES))
}
