import type { VerifiedRelayCredentials } from "./relayCredentials.js";
import type { CredentialResources } from "./credentialSupport.js";
import type { CredentialVerifierConfig, CredentialInput, CarrierPreparationFields, AuthorizedCarrierCandidate } from "./credentialVerifier.js";
import { candidateRouteBytes, validateActivation, checkSelection } from "./credentialVerifier.js";
import type { CredentialEvidence } from "./credentialNamespace.js";
import { CredentialWork, credentialWorkCharge, checkCredentialTime, credentialDigest, credentialOwner, equalCredential, requireCredential } from "./credentialSupport.js";
import { TrustedDeadline } from "./deadline.js";
import type { ResourceReference } from "./resources.js";
const capability = Symbol("original signed registry carrier preparation");
/** This owner contains only verified signed carrier metadata. It cannot supply
 * activation, a Grant, an admission continuation, Noise keys or a Session. */
export class RegisteredCarrierPreparation {
  readonly #reference: ResourceReference; readonly #evidence: CredentialEvidence[] = []; #fields: CarrierPreparationFields; readonly #candidates: AuthorizedCarrierCandidate[] = []; #selected = false;
  readonly #resources: CredentialResources; readonly #role: 0 | 1;
  #closed = false;
  constructor(token: symbol, config: CredentialVerifierConfig, input: CredentialInput, workMS: bigint, reference: ResourceReference) {
    requireCredential(token === capability && config.tunnel !== undefined && typeof workMS === "bigint" && workMS > 0n && workMS <= 60000n && Number.isSafeInteger(input.candidateIndex) && input.candidateIndex >= 0 && input.candidateIndex < 16 && (input.source === "preauthorized_pool" || input.source === "live_authority"), "configuration_capacity");
    this.#reference = reference.borrow();
    this.#resources = config.resources; this.#role = config.tunnel!.role;
    let work: CredentialWork | undefined, route: Uint8Array | undefined;
    try {
      work = new CredentialWork(config.resources, 524288, reference);
      const artifact = work.parse(input.artifact, "Artifact", 65536), maps = [artifact];
      try {
        const resolve = (map: typeof artifact) => { const matches = config.namespaces.filter(namespace => namespace.matches(map)); requireCredential(matches.length === 1, "credential_untrusted"); return matches[0]!; };
        const profile = artifact.text("crypto_profile_id"); requireCredential(artifact.text("tenant_id") === config.tenant && artifact.text("audience") === config.audience && config.cryptoProfiles.includes(profile), "credential_binding");
        checkCredentialTime(config.clock, artifact.uint("issued_at_ms"), artifact.uint("initiation_not_after_ms")); const parent = resolve(artifact).verifyCredential(artifact, 1, work); this.#evidence.push(parent);
        for (const [role, raw] of [input.clientCertificate, input.serverCertificate].entries()) {
          const certificate = work.parse(raw, "IdentityCertificate", 8192); maps.push(certificate);
          requireCredential(certificate.uint("role") === BigInt(role) && certificate.text("tenant_id") === config.tenant && certificate.text("audience") === config.audience && certificate.text("subject_id") === (role === 0 ? config.clientSubject : config.serverSubject) && certificate.text("crypto_profile_id") === profile, "credential_binding");
          checkCredentialTime(config.clock, certificate.uint("issued_at_ms"), certificate.uint("expires_at_ms")); const fact = resolve(certificate).verifyCredential(certificate, 0, work); this.#evidence.push(fact);
          const parentPolicy = parent.namespace.policyRequirements(parent), childPolicy = fact.namespace.policyRequirements(fact); requireCredential(parentPolicy.staleness <= childPolicy.staleness && parentPolicy.signerLifetime <= childPolicy.signerLifetime, "credential_untrusted");
          const expected = artifact.bytes(role === 0 ? "client_identity_digest" : "server_identity_digest"); try { requireCredential(equalCredential(fact.digest, expected), "credential_binding"); } finally { expected.fill(0); }
        }
        const candidate = [...artifact.items("candidates")][input.candidateIndex]; requireCredential(candidate !== undefined && artifact.uint("path_kind", candidate, "Candidate") === 1n, "credential_binding");
        route = candidateRouteBytes(artifact, candidate); let candidateIndices = [input.candidateIndex], preparationBytes = 0, preparationWork = 0, totalCandidateAttempts = 1, totalPreparationBytes = 0, preparationAddressAttempts = 1, totalPreparationWork = 0, initiation = artifact.uint("initiation_not_after_ms");
        if (input.source === "preauthorized_pool") {
          requireCredential(input.activation !== undefined); const activation = work.parse(input.activation, "ActivationAuthorization", 4096, 16384, { selectors: { activation_source_profile: input.source } }), onceBytes = parent.namespace.onceAuthority(parent.issuer); maps.push(activation);
          const once = work.parse(onceBytes, "OnceAuthorityRef", 412); maps.push(once); const candidateID = artifact.bytes("candidate_id", candidate, "Candidate"), routeDigest = credentialDigest("route_digest", route);
          try {
            const validity = validateActivation(config, work, artifact, activation, parent, once, input.source, input.candidateIndex, parent.digest, candidateID, routeDigest); this.#evidence.push(validity.evidence); initiation = validity.initiation;
            candidateIndices = checkSelection({ source: input.source, candidateIndex: input.candidateIndex }, artifact, activation, parent.digest, candidateID, routeDigest, once);
            const budget = activation.field("attempt_budget", activation.field("candidate_selection"), "PoolSelectionRef"), per = activation.field("per_candidate", budget, "PoolAttemptBudget");
            const min = (a: bigint, b: bigint): bigint => a < b ? a : b;
            preparationBytes = Number(min(activation.uint("preauth_bytes", per, "CandidateAttemptBudget"), activation.uint("total_preauth_bytes", budget, "PoolAttemptBudget"))); preparationWork = Number(min(activation.uint("work_units", per, "CandidateAttemptBudget"), activation.uint("total_work_units", budget, "PoolAttemptBudget")));
            totalCandidateAttempts = Number(min(activation.uint("total_address_attempts", budget, "PoolAttemptBudget"), activation.uint("total_work_units", budget, "PoolAttemptBudget"))); totalPreparationBytes = Number(activation.uint("total_preauth_bytes", budget, "PoolAttemptBudget")); preparationAddressAttempts = Number(activation.uint("address_attempts", per, "CandidateAttemptBudget")); totalPreparationWork = Number(activation.uint("total_work_units", budget, "PoolAttemptBudget"));
          } finally { onceBytes.fill(0); candidateID.fill(0); routeDigest.fill(0); }
        }
        const allCandidates = [...artifact.items("candidates")];
        for (const index of candidateIndices) {
          const node = allCandidates[index]; requireCredential(node !== undefined && artifact.uint("path_kind", node, "Candidate") === 1n, "credential_binding");
          const projectedRoute = index === input.candidateIndex ? route : candidateRouteBytes(artifact, node);
          let candidateID: Uint8Array | undefined, routeDigest: Uint8Array | undefined;
          try {
            const leg = artifact.field(config.tunnel.role === 0 ? "client_leg" : "server_leg", node, "Candidate");
            candidateID = artifact.bytes("candidate_id", node, "Candidate"); routeDigest = credentialDigest("route_digest", projectedRoute);
            this.#candidates.push(Object.freeze({ candidateIndex: index, candidateID, routeDigest, route: projectedRoute,
              pathKind: 1, accessClass: artifact.uint("access_class", leg, "Leg"), reliableProgress: ["client_leg", "server_leg"].some(name => artifact.uint("carrier", artifact.field(name, node, "Candidate"), "Leg") === 1n) ? "shared_ordered" : "native_bound" }));
          } catch (error) { projectedRoute.fill(0); candidateID?.fill(0); routeDigest?.fill(0); throw error; }
        }
        const preferred = this.#candidates.find(value => value.candidateIndex === input.candidateIndex); requireCredential(preferred !== undefined, "credential_binding");
        const contract = artifact.field("session_contract");
        this.#fields = Object.freeze({ ...preferred, candidates: Object.freeze(this.#candidates), totalCandidateAttempts, totalPreparationBytes, preparationAddressAttempts, totalPreparationWork, preparationBytes, preparationWork, source: input.source,
          maxFrame: Number(artifact.uint("max_frame", contract, "SessionContract")), required: artifact.uint("required_features"), preparationDeadline: TrustedDeadline.ageAt(config.clock, config.clock.sample(), workMS, initiation) }); route = undefined;
      } finally { for (const map of maps) map.close(); }
      this.check(); Object.freeze(this);
    } catch (error) { route?.fill(0); this.close(); throw error; } finally { work?.close(); }
  }
  check(): void { requireCredential(!this.#closed, "credential_closed"); this.#reference.check(); this.#fields.preparationDeadline.check(); for (const fact of this.#evidence) fact.namespace.checkEvidence(fact); }
  fields(): CarrierPreparationFields { this.check(); return this.#fields; }
  checkEnvironment(reference: ResourceReference): void { this.check(); requireCredential(reference.sameEnvironment(this.#reference), "credential_binding"); }
  /** Pins the signed member actually used by the original physical owner. */
  selectCandidate(candidateIndex: number): void {
    this.check(); requireCredential(!this.#selected, "credential_binding"); const candidate = this.#candidates.find(value => value.candidateIndex === candidateIndex);
    requireCredential(candidate !== undefined, "credential_binding"); this.#fields = Object.freeze({ ...this.#fields, ...candidate, candidates: Object.freeze([candidate]) }); this.#selected = true;
  }
  checkOriginalGrant(credentials: VerifiedRelayCredentials, reference: ResourceReference): void {
    this.check(); credentials.check(reference); requireCredential(reference.sameEnvironment(this.#reference) && credentials.role === this.#role, "credential_binding");
    const ref = this.#resources.root.reserve({ owner: credentialOwner(this.#resources, "registered_carrier_original_grant"), accounts: this.#resources.accounts, charge: credentialWorkCharge(163840, this.#resources.runtimeBytes) });
    let encoded: Uint8Array | undefined, certificate: Uint8Array | undefined, work: CredentialWork | undefined;
    try { work = new CredentialWork(this.#resources, 65536, ref); encoded = credentials.grant(reference); certificate = credentials.certificate("endpoint", reference); const grant = work.parse(encoded, "Grant", 65536);
      try { const parent = grant.field("parent_ref"), digest = grant.bytes("artifact_digest", parent, "GrantParentRef"), route = grant.encoded(grant.field("route_descriptor")), identity = credentialDigest("certificate_digest", certificate);
        try { requireCredential(equalCredential(digest, this.#evidence[0]!.digest) && equalCredential(route, this.#fields.route) && equalCredential(identity, this.#evidence[this.#role + 1]!.digest), "credential_binding"); }
        finally { digest.fill(0); route.fill(0); identity.fill(0); }
      } finally { grant.close(); }
    } finally { encoded?.fill(0); certificate?.fill(0); work?.close(); ref.release(); }
  }
  close(): void { if (this.#closed) return; this.#closed = true; this.#fields?.route.fill(0); for (const candidate of this.#candidates) { candidate.route.fill(0); candidate.candidateID.fill(0); candidate.routeDigest.fill(0); } for (const fact of this.#evidence) { fact.issuer.fill(0); fact.digest.fill(0); fact.permissionDigest.fill(0); fact.lease?.fill(0); fact.grant?.fill(0); } this.#reference.release(); }
}
export function prepareRegisteredCarrier(config: CredentialVerifierConfig, input: CredentialInput, workMS: bigint): RegisteredCarrierPreparation {
  const reference = config.resources.root.reserve({ owner: credentialOwner(config.resources, "registered_carrier_preparation"), accounts: config.resources.accounts, charge: credentialWorkCharge(557056, config.resources.runtimeBytes) });
  try { return new RegisteredCarrierPreparation(capability, config, input, workMS, reference); } catch (error) { reference.release(); throw error; }
}
