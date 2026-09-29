import { describe, expect, it } from "vitest";
import { ClockRate } from "./runtime/timeArithmetic.js";
import { TrustedClock, trustedClockCharge } from "./runtime/clock.js";
import { ResourceRoot, ResourceVector } from "./runtime/resources.js";
import { CredentialNamespace } from "./runtime/credentialNamespace.js";
import { credentialVerifierCharge, verifyDirectCredentials, type VerifiedCredentialClosure } from "./runtime/credentialVerifier.js";
import { clearClientPreparation } from "./runtime/clientAdmission.js";
import { credentialFixture, encode, fill, bytes, text, array, u, map, replace, sign, get, digest, type CredentialFixture } from "./testSupport/credentials.js";
function fixture(source: "live_authority" | "preauthorized_pool" = "live_authority", profile?: string) {
  let next = 1n, now = 0n;
  const limit = new ResourceVector([512n << 20n, 0n, 0n, 5000000n, 5000000n, 1000n, 1000n, 1000n, 1000n, 1000n, 1000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 8, reservations: 200, references: 400,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const tenant = "1".repeat(32), environment = "2".repeat(32), accounts = [root.account("tenant", tenant, limit), root.account("environment", environment, limit)];
  const reserve = (kind: string, charge: ResourceVector) => root.reserve({ owner: { tenant, environment, kind, backing: (next++).toString(16).padStart(32, "0") }, charge, accounts });
  const clock = new TrustedClock({ rate: new ClockRate(0n, 1n, 0n), maxWidthMS: 100n, maxAgeMS: 1000000n, maxRoundTripMS: 100n },
    () => ({ milliseconds: now, incarnation: "3".repeat(32) }), 128n, reserve("clock", trustedClockCharge(128n)));
  clock.installTrusted(clock.monotonic(), { lowerMS: 1000n, upperMS: 1010n });
  const resources = { root, accounts, owner: { tenant, environment, kind: "credentials", backing: "4".repeat(32) }, runtimeBytes: 1024n };
  const material = credentialFixture(resources, clock, reserve, source, profile);
  const verify = (config = material.config, input = material.input()) => {
    const ref = reserve("verified", credentialVerifierCharge(resources.runtimeBytes));
    try { return verifyDirectCredentials(config, input, ref); } finally { ref.release(); }
  };
  const reject = (fn = () => verify()) => { const before = root.snapshot().reservations; expect(fn).toThrow(); expect(root.snapshot().reservations).toBe(before); };
  return { material, root, clock, reserve, resources, verify, reject, advance: (ms: bigint) => { now = ms; },
    close: () => { material.namespace.close(); clock.close(); expect(root.snapshot().reservations).toBe(0); } };
}
function updateArtifact(f: CredentialFixture, changes: Parameters<typeof replace>[1]) { f.artifact = sign("Artifact", replace(f.artifact, changes), 12); f.refreshActivation(); }
describe("original credential verification closure", () => {
  for (const source of ["live_authority", "preauthorized_pool"] as const) for (const profile of ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"]) {
    it(`authenticates ${source} client admission before server success for ${profile}`, () => {
      const f = fixture(source, profile); f.material.bootstrap(); const closure = f.verify();
      const admission = f.reserve("server_admission", new ResourceVector([1024n, 0n, 0n, 1n, 1n, 0n, 0n, 0n, 0n, 0n, 0n]));
      const fields = closure.clientPreparation(admission);
      const context = map({ 0: text("4"), 1: text(profile), 2: u(0), 3: u(0), 4: bytes(fields.artifactDigest), 5: bytes(fields.routeDigest),
        6: bytes(fields.attempt), 7: bytes(fields.nonce), 8: bytes(fill(60)), 9: u(0), 10: u(1), 11: u(0), 12: bytes(new Uint8Array()) });
      const request = sign("FSB4", map({ 0: bytes(fields.artifactDigest), 1: text(fields.tenant), 2: bytes(fields.issuer), 3: bytes(fields.lease),
        4: bytes(fields.nonce), 5: bytes(fields.candidateID), 6: bytes(fields.routeDigest), 7: bytes(fields.attempt), 8: bytes(fill(61)),
        9: bytes(fill(60)), 10: u(0), 11: u(1), 12: bytes(digest("transport_context_digest", context)),
        13: bytes(fields.activation), 14: bytes(fields.clientCertificate) }), 14);
      try {
        const baseline = f.root.snapshot().reservations;
        expect(closure.authenticateClientAdmission(encode(request), encode(context), admission)).toEqual(digest("admission_binding", request));
        expect(f.root.snapshot().reservations).toBe(baseline);
        // Even the legitimate client signer cannot change the selected parent,
        // identity, proof, route, attempt, or locally negotiated transcript.
        for (const changes of [
          { 0: bytes(fill(90)) }, { 1: text("other-tenant") }, { 2: bytes(fill(90, 16)) }, { 3: bytes(fill(90, 16)) },
          { 4: bytes(fill(90)) }, { 5: bytes(fill(90, 16)) }, { 6: bytes(fill(90)) }, { 7: bytes(fill(90, 16)) },
          { 9: bytes(fill(90)) }, { 10: u(1) }, { 11: u(0) }, { 12: bytes(fill(90)) },
          { 13: bytes(encode(sign("ActivationAuthorization", f.material.activation, 19))) },
          { 14: bytes(encode(f.material.server)) },
        ]) {
          const forged = sign("FSB4", replace(request, changes), 14);
          expect(() => closure.authenticateClientAdmission(encode(forged), encode(context), admission)).toThrow();
          expect(f.root.snapshot().reservations).toBe(baseline);
        }
        const invalidSignature = sign("FSB4", request, 15);
        expect(() => closure.authenticateClientAdmission(encode(invalidSignature), encode(context), admission)).toThrow();
        const changedContext = replace(context, { 8: bytes(fill(91)) });
        expect(() => closure.authenticateClientAdmission(encode(request), encode(changedContext), admission)).toThrow();
        expect(f.root.snapshot().reservations).toBe(baseline);
        closure.close();
        expect(() => closure.authenticateClientAdmission(encode(request), encode(context), admission)).toThrow("credential_closed");
      } finally { clearClientPreparation(fields); closure.close(); admission.release(); f.close(); }
    });
  }
  for (const source of ["live_authority", "preauthorized_pool"] as const) for (const profile of ["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"]) {
    it(`verifies independently delegated ${source} credentials for ${profile}`, () => {
      const f = fixture(source, profile); let result: VerifiedCredentialClosure | undefined;
      try { f.material.bootstrap(); const baseline = f.root.snapshot().reservations; result = f.verify(); expect(JSON.stringify(result)).toBe("{}"); result.close(); expect(f.root.snapshot().reservations).toBe(baseline); }
      finally { result?.close(); f.close(); }
    });
  }
  it("requires the original nonce and independently pinned root", () => {
    const f = fixture(), m = f.material;
    try {
      const before = f.root.snapshot().reservations;
      expect(() => m.namespace.bootstrap(m.response(fill(91)), encode(m.state))).toThrow(); expect(f.root.snapshot().reservations).toBe(before);
      expect(() => m.namespace.bootstrap(m.response(undefined, sign("TrustConfig", m.trust, 8)), encode(m.state))).toThrow(); expect(f.root.snapshot().reservations).toBe(before);
      m.bootstrap(); f.verify().close(); expect(() => m.namespace.bootstrap(m.response(fill(91)), encode(m.state))).toThrow();
    } finally { f.close(); }
  });
  for (const [name, mutate] of [
    ["certificate role", (m: CredentialFixture) => { m.client = sign("IdentityCertificate", replace(m.client, { 5: u(1) }), 11); }],
    ["untrusted issuer key", (m: CredentialFixture) => { m.artifact = sign("Artifact", m.artifact, 13); }],
    ["trusted subject", (m: CredentialFixture) => { m.client = sign("IdentityCertificate", replace(m.client, { 1: text("other") }), 11); }],
    ["certificate digest", (m: CredentialFixture) => updateArtifact(m, { 9: bytes(fill(88)) })],
    ["audience", (m: CredentialFixture) => updateArtifact(m, { 11: text("other") })],
    ["cohort grid", (m: CredentialFixture) => updateArtifact(m, { 23: u(9) })],
    ["namespace generation", (m: CredentialFixture) => updateArtifact(m, { 22: u(2) })],
    ["unknown namespace", (m: CredentialFixture) => updateArtifact(m, { 21: text("other") })],
    ["activation candidate", (m: CredentialFixture) => { m.activation = sign("ActivationAuthorization", replace(m.activation, { 7: bytes(fill(1, 16)) }), 13); }],
    ["activation route", (m: CredentialFixture) => { m.activation = sign("ActivationAuthorization", replace(m.activation, { 8: bytes(fill(88)) }), 13); }],
    ["activation once authority", (m: CredentialFixture) => { m.activation = sign("ActivationAuthorization", replace(m.activation, { 1: text("other") }), 13); }],
    ["activation delegated signer", (m: CredentialFixture) => { m.activation = sign("ActivationAuthorization", m.activation, 12); }],
    ["activation hard cap", (m: CredentialFixture) => { m.activation = sign("ActivationAuthorization", replace(m.activation, { 15: u(45000) }), 13); }],
    ["low-order endpoint DH", (m: CredentialFixture) => { m.client = sign("IdentityCertificate", replace(m.client, { 3: map({ 0: u(0), 1: bytes(fill(0)) }) }), 11); updateArtifact(m, { 9: bytes(digest("certificate_digest", m.client)) }); }],
    ["namespace role closure", (m: CredentialFixture) => { const candidates = get(m.artifact, 12); if (candidates.kind !== "array") throw new Error("fixture"); const refs = get(candidates.value[0]!, 6); if (refs.kind !== "array") throw new Error("fixture"); updateArtifact(m, { 12: array(replace(candidates.value[0]!, { 6: array(replace(refs.value[0]!, { 4: u(1) })) })) }); }],
  ] as const) it(`rejects ${name} and refunds all work`, () => {
    const f = fixture(); try { f.material.bootstrap(); mutate(f.material); f.reject(); } finally { f.close(); }
  });
  it("fixes source interpretation and rejects forged namespace owners", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); f.reject(() => f.verify(undefined, { ...m.input(), source: "preauthorized_pool" }));
      f.reject(() => f.verify({ ...m.config, namespaces: [Object.create(CredentialNamespace.prototype) as CredentialNamespace] }));
      f.reject(() => f.verify(undefined, { ...m.input(), candidateIndex: 1 }));
    } finally { f.close(); }
  });
  it("checks pool set digest and once mapping exactly", () => {
    const f = fixture("preauthorized_pool"), m = f.material;
    try {
      m.bootstrap(); const selection = get(m.activation, 7);
      m.activation = sign("ActivationAuthorization", replace(m.activation, { 7: replace(selection, { 2: bytes(fill(66)) }) }), 13); f.reject(); m.refreshActivation();
      m.activation = sign("ActivationAuthorization", replace(m.activation, { 7: replace(selection, { 4: replace(get(selection, 4), { 3: text("other") }) }) }), 13); f.reject();
    } finally { f.close(); }
  });
  it("enforces fixed publication lifetime compatibility", () => {
    const f = fixture(), m = f.material;
    try {
      const policies = get(m.trust, 9); if (policies.kind !== "array") throw new Error("fixture");
      m.trust = sign("TrustConfig", replace(m.trust, { 9: array(replace(policies.value[0]!, { 3: u(1000) })) }), 7); m.bootstrap(); f.reject();
    } finally { f.close(); }
  });
  it("rechecks revocation and forbids dropping observed denial", () => {
    const f = fixture(), m = f.material; let result: VerifiedCredentialClosure | undefined;
    try {
      m.bootstrap(); result = f.verify();
      const revoked = replace(m.state, { 9: array(map({ 0: bytes(digest("certificate_digest", m.client)), 1: u(8), 2: u(50000) })) });
      m.namespace.refresh(encode(m.headFor(revoked, 2)), encode(revoked)); f.reject();
      const ref = f.reserve("check", credentialVerifierCharge(1024n)); try { expect(() => result!.checkPreparation(ref)).toThrow(); } finally { ref.release(); }
      expect(() => m.namespace.refresh(encode(m.headFor(m.state, 3)), encode(m.state))).toThrow();
    } finally { result?.close(); f.close(); }
  });
  it("checks floor, full State digest and Head sequence monotonicity", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); expect(() => m.namespace.refresh(encode(m.headFor(m.state, 0)), encode(m.state))).toThrow();
      const bumped = replace(m.state, { 5: array(u(9), u(0)) });
      expect(() => m.namespace.refresh(encode(m.headFor(bumped, 2)), encode(m.state))).toThrow();
      expect(() => m.namespace.refresh(encode(m.headFor(bumped, 2)), encode(bumped))).toThrow(); f.verify().close();
    } finally { f.close(); }
  });
  it("refreshes stale Head without relaxing original credential expiry", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); f.advance(60000n); expect(() => m.namespace.check()).toThrow();
      m.namespace.refresh(encode(m.headFor(m.state, 2, 60900, 80000)), encode(m.state)); m.namespace.check(); f.reject();
    } finally { f.close(); }
  });
  it("rejects a different resource Environment", () => {
    const a = fixture(), b = fixture(); let result: VerifiedCredentialClosure | undefined;
    try {
      a.material.bootstrap(); b.material.bootstrap(); result = a.verify(); const ref = b.reserve("other", credentialVerifierCharge(1024n));
      try { expect(() => result!.checkPreparation(ref)).toThrow(); } finally { ref.release(); }
    } finally { result?.close(); a.close(); b.close(); }
  });
});

function bootstrapResponse(m: CredentialFixture, nonce: Uint8Array, head: Parameters<typeof encode>[0], trust = m.trust): Uint8Array {
  return encode(sign("TrustBootstrapResponse", map({ 0: text("draft.70"), 1: text("tenant"), 2: text("authority"), 3: bytes(nonce), 4: u(900), 5: u(10000),
    6: bytes(encode(trust)), 7: bytes(encode(head)), 8: bytes(fill(1, 16)) }), 7));
}
function revokedState(m: CredentialFixture, certificate = m.client) {
  return replace(m.state, { 9: array(map({ 0: bytes(digest("certificate_digest", certificate)), 1: u(8), 2: u(50000) })) });
}
describe("online namespace original continuity", () => {
  it("finishes the pinned State while newer Heads advance observed", async () => {
    const f = fixture(), m = f.material; let result: VerifiedCredentialClosure | undefined;
    try {
      m.bootstrap(); result = f.verify();
      const first = replace(m.state, { 9: array(map({ 0: bytes(fill(70)), 1: u(8), 2: u(50000) })) });
      const second = replace(first, { 9: array(...[map({ 0: bytes(fill(70)), 1: u(8), 2: u(50000) }), map({ 0: bytes(digest("certificate_digest", m.client)), 1: u(8), 2: u(50000) })].sort((a, b) => Buffer.compare(encode(a), encode(b)))) });
      const h2 = m.headFor(first, 2), h3 = m.headFor(second, 3); m.namespace.observe(encode(h2));
      let release!: () => void, started!: () => void; const pause = new Promise<void>(r => { release = r; }), start = new Promise<void>(r => { started = r; });
      const fetching = m.namespace.fetchPending(async (request, destination) => { expect(request.head).toEqual(encode(h2)); started(); await pause; const raw = encode(first); destination.set(raw); return raw.length; });
      await start; m.namespace.observe(encode(h3)); f.verify().close(); release(); expect(await fetching).toBe(true); f.verify().close();
      expect(await m.namespace.fetchPending(async (request, destination) => { expect(request.head).toEqual(encode(h3)); const raw = encode(second); destination.set(raw); return raw.length; })).toBe(true);
      f.reject(); const ref = f.reserve("check", credentialVerifierCharge(1024n)); try { expect(() => result!.checkPreparation(ref)).toThrow(); } finally { ref.release(); }
    } finally { result?.close(); f.close(); }
  });
  it("reuses full content and pins the original trust expiry", async () => {
    const f = fixture(), m = f.material;
    try {
      m.trust = sign("TrustConfig", replace(m.trust, { 6: u(5000) }), 7); m.bootstrap(); expect(m.namespace.availableUntil(50000n)).toBe(5000n);
      const next = sign("TrustConfig", replace(m.trust, { 4: u(2), 6: u(90000) }), 7); m.namespace.updateTrust(encode(next));
      expect(m.namespace.availableUntil(50000n)).toBe(5000n);
      m.namespace.observe(encode(m.headFor(m.state, 2))); expect(m.namespace.availableUntil(50000n)).toBe(50900n);
      let calls = 0; expect(await m.namespace.fetchPending(async () => { calls++; return 0; })).toBe(true); expect(calls).toBe(0);
    } finally { f.close(); }
  });
  for (const [name, change] of [
    ["publication", (m: CredentialFixture) => ({ 8: replace(get(m.trust, 8), { 2: u(59000) }) })],
    ["capacity", (m: CredentialFixture) => ({ 7: replace(get(m.trust, 7), { 3: u(8191) }) })],
    ["same policy", (m: CredentialFixture) => { const policies = get(m.trust, 9); if (policies.kind !== "array") throw new Error("fixture"); return { 9: array(replace(policies.value[0]!, { 2: u(49999) })) }; }],
    ["same once mapping", (m: CredentialFixture) => { const once = get(m.trust, 13); if (once.kind !== "array") throw new Error("fixture"); return { 13: array(replace(once.value[0]!, { 3: text("other") })) }; }],
    ["same permission", (m: CredentialFixture) => { const permissions = get(m.trust, 10); if (permissions.kind !== "array") throw new Error("fixture"); return { 10: array(replace(permissions.value[0]!, { 14: text("other") }), ...permissions.value.slice(1)) }; }],
  ] as const) it(`rejects changes to immutable ${name}`, () => {
    const f = fixture(), m = f.material;
    try { m.bootstrap(); const next = sign("TrustConfig", replace(m.trust, { 4: u(2), ...change(m) }), 7); expect(() => m.namespace.updateTrust(encode(next))).toThrow(); f.verify().close(); }
    finally { f.close(); }
  });
  it("retains original issuer permission evidence after removal from current trust", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); const permissions = get(m.trust, 10); if (permissions.kind !== "array") throw new Error("fixture");
      const next = sign("TrustConfig", replace(m.trust, { 4: u(2), 10: array(...permissions.value.slice(1)) }), 7); m.namespace.updateTrust(encode(next));
      const retained = permissions.value[1]!, impact = map({ 0: bytes(digest("credential_issuer_authorization_digest", retained)), 1: get(retained, 24), 2: get(retained, 9), 3: get(retained, 10) });
      const missing = replace(m.state, { 8: array(map({ 0: bytes(fill(4, 16)), 1: array(impact) })) });
      expect(() => m.namespace.refresh(encode(m.headFor(missing, 2)), encode(missing))).toThrow();
      // Rejecting a bad downloaded State does not manufacture a new Head or
      // change the original pinned content key to accept a different body.
      expect(() => m.namespace.refresh(encode(m.headFor(missing, 2)), encode(m.state))).toThrow();
    } finally { f.close(); }
  });
  it("retains canceled provider backing until actual exit and never installs late bytes", async () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); const state = revokedState(m), raw = encode(state); m.namespace.observe(encode(m.headFor(state, 2)));
      let release!: () => void, started!: () => void; const pause = new Promise<void>(r => { release = r; }), start = new Promise<void>(r => { started = r; });
      const operation = m.namespace.fetchPending(async (request, destination) => { started(); await pause; expect(request.signal.aborted).toBe(true); destination.set(raw); return raw.length; });
      await start; const count = f.root.snapshot().reservations; m.namespace.close(); expect(m.namespace.cleanupComplete()).toBe(false); expect(f.root.snapshot().reservations).toBe(count);
      release(); await expect(operation).rejects.toThrow(); await m.namespace.waitCleanup(); expect(m.namespace.cleanupComplete()).toBe(true);
    } finally { f.close(); }
  });
  it("fences failed incarnations and replaces only with complete independent coverage", () => {
    const f = fixture(), m = f.material; let old: VerifiedCredentialClosure | undefined, fresh: VerifiedCredentialClosure | undefined;
    try {
      m.bootstrap(); old = f.verify(); m.namespace.observe(encode(m.headFor(m.state, 2))); m.namespace.failContinuity();
      const nonce = m.namespace.beginReplacement();
      expect(() => m.namespace.bootstrap(bootstrapResponse(m, nonce, m.headFor(m.state, 1)), encode(m.state))).toThrow();
      m.namespace.bootstrap(bootstrapResponse(m, nonce, m.headFor(m.state, 3)), encode(m.state)); fresh = f.verify();
      const ref = f.reserve("check", credentialVerifierCharge(1024n)); try { expect(() => old!.checkPreparation(ref)).toThrow(); fresh.checkPreparation(ref); } finally { ref.release(); }
    } finally { old?.close(); fresh?.close(); f.close(); }
  });
  it("does not erase a known revocation during fresh-nonce replacement", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); const denied = revokedState(m); m.namespace.refresh(encode(m.headFor(denied, 2)), encode(denied)); m.namespace.failContinuity(); const nonce = m.namespace.beginReplacement();
      expect(() => m.namespace.bootstrap(bootstrapResponse(m, nonce, m.headFor(m.state, 3)), encode(m.state))).toThrow();
      expect(() => m.namespace.check()).toThrow();
      m.namespace.bootstrap(bootstrapResponse(m, nonce, m.headFor(denied, 3)), encode(denied)); f.reject();
    } finally { f.close(); }
  });
  it("does not repin a canceled content fetch with a fresh deadline", async () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); const state = revokedState(m); m.namespace.observe(encode(m.headFor(state, 2))); m.namespace.cancelFetch();
      let calls = 0; expect(await m.namespace.fetchPending(async () => { calls++; return 0; })).toBe(false); expect(calls).toBe(0); f.verify().close();
    } finally { f.close(); }
  });
  it("keeps one original time-pending Head until its lower bound is proved", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); const original = m.namespace.availableUntil(50000n);
      m.namespace.observe(encode(m.headFor(m.state, 2, 1005, 60000))); expect(m.namespace.availableUntil(50000n)).toBe(original);
      // Additional pending input cannot overwrite the original slot or grant
      // its freshness to the still-active State.
      m.namespace.observe(encode(m.headFor(m.state, 3, 1006, 60000))); expect(m.namespace.availableUntil(50000n)).toBe(original);
      f.advance(5n); m.namespace.advance(); expect(m.namespace.availableUntil(50000n)).toBe(51005n);
    } finally { f.close(); }
  });
  it("requires the immutable per-class maturity bound before accepting a floor", () => {
    const f = fixture(), m = f.material;
    try {
      m.bootstrap(); const oldHeads = get(m.trust, 11); if (oldHeads.kind !== "array") throw new Error("fixture");
      const delegation = replace(oldHeads.value[0]!, { 5: bytes(fill(30, 16)), 11: u(100000), 12: u(100000), 13: u(190000) });
      const trust = sign("TrustConfig", replace(m.trust, { 4: u(2), 5: u(100000), 6: u(200000), 11: array(delegation) }), 7);
      f.advance(99095n); m.namespace.updateTrust(encode(trust));
      const state = replace(m.state, { 5: array(u(1), u(0)) });
      const head = sign("FreshnessHead", replace(m.headFor(state, 2, 100050, 150000), { 14: bytes(digest("head_signer_delegation_digest", delegation)) }), 9);
      m.namespace.observe(encode(head)); expect(() => m.namespace.check()).toThrow();
      f.advance(99100n); m.namespace.advance(); expect(m.namespace.refresh(encode(head), encode(state))).toBe(true); m.namespace.check();
      const rollback = replace(state, { 5: array(u(0), u(1)) });
      const changed = sign("FreshnessHead", replace(m.headFor(rollback, 3, 100050, 150000), { 14: bytes(digest("head_signer_delegation_digest", delegation)) }), 9);
      expect(() => m.namespace.refresh(encode(changed), encode(rollback))).toThrow(); m.namespace.check();
    } finally { f.close(); }
  });
  it("does not revive an original freshness deadline when a later Head arrives", () => {
    const f = fixture(), m = f.material; let old: VerifiedCredentialClosure | undefined, fresh: VerifiedCredentialClosure | undefined;
    try {
      const policies = get(m.trust, 9); if (policies.kind !== "array") throw new Error("fixture");
      m.trust = sign("TrustConfig", replace(m.trust, { 9: array(replace(policies.value[0]!, { 2: u(1000) })) }), 7); m.bootstrap(); old = f.verify();
      expect(old.availableUntil()).toBe(1900n); f.advance(1000n); m.namespace.observe(encode(m.headFor(m.state, 2, 1950, 60000)));
      expect(() => old!.availableUntil()).toThrow(); fresh = f.verify(); expect(fresh.availableUntil()).toBe(2950n);
    } finally { old?.close(); fresh?.close(); f.close(); }
  });
  it("owns a real bootstrap callback through verification and cancellation tails", async () => {
    const f = fixture(), m = f.material;
    try {
      expect(await m.namespace.fetchBootstrap(async (request, response, state) => {
        const reply = m.response(request.nonce), content = encode(m.state); response.set(reply); state.set(content); return { responseBytes: reply.length, stateBytes: content.length };
      })).toBe(true); f.verify().close();
      m.namespace.failContinuity(); m.namespace.beginReplacement();
      let release!: () => void, started!: () => void; const pause = new Promise<void>(r => { release = r; }), start = new Promise<void>(r => { started = r; });
      const operation = m.namespace.fetchBootstrap(async (request, response, state) => {
        const reply = bootstrapResponse(m, request.nonce, m.headFor(m.state, 2)), content = encode(m.state); started(); await pause;
        expect(request.signal.aborted).toBe(true); response.set(reply); state.set(content); return { responseBytes: reply.length, stateBytes: content.length };
      });
      await start; const count = f.root.snapshot().reservations; m.namespace.failContinuity(); m.namespace.close(); expect(m.namespace.cleanupComplete()).toBe(false); expect(f.root.snapshot().reservations).toBe(count);
      release(); await expect(operation).rejects.toThrow(); await m.namespace.waitCleanup(); expect(m.namespace.cleanupComplete()).toBe(true);
    } finally { f.close(); }
  });
});
