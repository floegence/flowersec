import { applicationResumeFeature } from "../runtime/checkpointToken.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { encode, uint, type Value, join, head } from "./cbor.js";
import { wireDomains, wireMaps } from "../runtime/schemaRegistry.js";
import { CredentialNamespace } from "../runtime/credentialNamespace.js";
import { credentialDigest, credentialWorkCharge, type CredentialResources } from "../runtime/credentialSupport.js";
import { type ActivationSource, type CredentialInput, type CredentialVerifierConfig } from "../runtime/credentialVerifier.js";
import type { TrustedClock } from "../runtime/clock.js";
import type { ResourceReference, ResourceVector } from "../runtime/resources.js";

export const bytes = (value: Uint8Array): Value => ({ kind: "bytes", value });
export const fill = (value: number, n = 32): Uint8Array => new Uint8Array(n).fill(value);
export const text = (value: string): Value => ({ kind: "text", value });
export const array = (...value: Value[]): Value => ({ kind: "array", value });
export const map = (fields: Record<number, Value>): Value => ({ kind: "map", value: Object.entries(fields).map(([id, v]) => [uint(BigInt(id)), v]) });
export const u = (n: number | bigint): Value => uint(BigInt(n));
export const nil: Value = { kind: "null" };
export function get(value: Value, id: number): Value {
  if (value.kind !== "map") throw new Error("test map"); const found = value.value.find(([k]) => k.kind === "uint" && k.value === BigInt(id));
  if (found === undefined) throw new Error("test field"); return found[1];
}
export function replace(value: Value, fields: Record<number, Value>): Value {
  if (value.kind !== "map") throw new Error("test map");
  return map(Object.fromEntries(value.value.map(([k, v]) => { if (k.kind !== "uint") throw new Error("test key"); return [Number(k.value), fields[Number(k.value)] ?? v]; })));
}
export const digest = (name: string, value: Value): Uint8Array => credentialDigest(name, encode(value));
export function sign(schema: string, value: Value, seed: number): Value {
  if (value.kind !== "map") throw new Error("test map");
  const signature = wireMaps[schema]!.signature_field!;
  const unsigned: Value = { kind: "map", value: value.value.filter(([k]) => k.kind !== "uint" || k.value !== BigInt(signature)) };
  const domain = wireDomains.find(d => d.operation === "ed25519" && d.input_schema.parts[0]?.schema_ref === schema)!;
  const label = Uint8Array.from(domain.label_bytes.match(/../gu)!.map(v => Number.parseInt(v, 16))), raw = encode(unsigned), length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, raw.length);
  return { kind: "map", value: [...unsigned.value, [u(signature), bytes(ed25519.sign(join([label, length, raw]), fill(seed)))]] };
}
export type CredentialFixture = ReturnType<typeof credentialFixture>;
export function credentialFixture(resources: CredentialResources, clock: TrustedClock, reserve: (name: string, charge: ResourceVector) => ResourceReference,
  source: ActivationSource = "live_authority", profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", suppliedNamespace?: CredentialNamespace, options: { bootstrapMS?: bigint; sessionNotAfterMS?: number; resume?: boolean; datagram?: boolean; timeOrigin?: bigint; leg?: Value; applicationProfile?: "services" | "execution"; rpcMaxGeneralOutstanding?: number; clientSubject?: string; authorizedClientSubjects?: readonly string[]; connectionSeed?: number; candidateLegs?: readonly Value[] } = {}) {
  const clientSubject = options.clientSubject ?? "client", clientSubjects = options.authorizedClientSubjects ?? ["client"];
  if (!clientSubjects.includes(clientSubject)) throw new Error("test client authorization missing");
  const leaseID = fill(options.connectionSeed ?? 22, 16), sessionNonce = fill((options.connectionSeed ?? 22) + 1), attemptID = fill((options.connectionSeed ?? 22) + 3, 16);
  const t = (value: number | bigint): Value => u((options.timeOrigin ?? 0n) + BigInt(value));
  const revision = text("draft.70");
  const namespace = suppliedNamespace ?? new CredentialNamespace({ tenant: "tenant", authority: "authority", rootKeyID: fill(1, 16), rootPublicKey: ed25519.getPublicKey(fill(7)),
    clock, maxTrustLifetimeMS: 120000n, bootstrapMS: options.bootstrapMS ?? 10000n, stateBytes: 8192, stateNodes: 16384, resources }, reserve("namespace", credentialWorkCharge(270336, resources.runtimeBytes)));
  const capacity = map({ 0: text("tenant"), 1: text("authority"), 2: text("capacity-1"), 3: u(8192), 4: u(16), 5: u(16), 6: u(16), 7: u(16), 8: u(795),
    9: u(1 << 20), 10: u(1024), 11: t(0), 12: u(100), 13: u(100000), 14: u(100000) });
  const cap = digest("namespace_capacity_digest", capacity), publication = map({ 0: text("publication"), 1: u(1), 2: u(60000), 3: u(90000) });
  const headDelegation = map({ 0: revision, 1: text("tenant"), 2: text("authority"), 3: bytes(cap), 4: u(1), 5: bytes(fill(2, 16)), 6: bytes(fill(3, 16)),
    7: bytes(ed25519.getPublicKey(fill(9))), 8: u(0), 9: text("publication"), 10: u(1), 11: t(1), 12: t(1), 13: t(90000) });
  const activationDelegation = map({ 0: revision, 1: text("tenant"), 2: text("authority"), 3: bytes(cap), 4: u(1), 5: text("activate-1"), 6: bytes(ed25519.getPublicKey(fill(13))),
    7: u(1), 8: bytes(fill(5, 16)), 9: text("spend"), 10: t(1), 11: t(10000), 12: u(0), 13: u(500), 14: t(20000), 15: t(50000), 16: array(nil, u(500)), 17: bytes(fill(6, 16)) });
  const authorization = (id: number, issuer: number, seed: number, role?: number, subject?: string): Value => map({
    0: bytes(fill(id, 16)), 1: text("tenant"), 2: text("authority"), 3: bytes(cap), 4: u(1), 5: u(role === undefined ? 1 : 0), 6: bytes(fill(issuer, 16)),
    7: bytes(ed25519.getPublicKey(fill(seed))), 8: text("service"), 9: t(1), 10: t(10000), 11: u(0), 12: u(500), 13: t(100000),
    ...(role === undefined ? {} : { 14: text(subject ?? (role === 0 ? "client" : "server")) }), 15: text(profile), ...(role === undefined ? {} : { 16: u(role) }), 24: role === undefined ? array(nil, u(500)) : array(u(500), nil),
  });
  const policy = map({ 0: text("credentials"), 1: u(1), 2: u(50000), 3: u(90000) });
  const once = map({ 0: text("tenant"), 1: bytes(fill(5, 16)), 2: text("spend"), 3: text("winner") });
  let trust = sign("TrustConfig", map({ 0: revision, 1: text("tenant"), 2: text("authority"), 3: u(1), 4: u(1), 5: t(1), 6: t(100000), 7: capacity, 8: publication,
    9: array(policy), 10: array(authorization(10, 4, 11, 0), authorization(11, 4, 11, 1), authorization(12, 5, 12), ...clientSubjects.filter(subject => subject !== "client").map((subject, index) => authorization(40 + index, 4, 11, 0, subject))), 11: array(headDelegation), 12: array(activationDelegation), 13: array(once), 14: array(), 15: array(), 16: bytes(fill(1, 16)) }), 7);
  let state = map({ 0: revision, 1: text("tenant"), 2: text("authority"), 3: bytes(cap), 4: u(1), 5: array(u(0), u(0)), 6: text("publication"), 7: u(1),
    8: array(), 9: array(), 10: array(), 11: array(map({ 0: u(0), 1: u(500), 2: u(100000), 3: u(100000) })) });
  const headFor = (content: Value, sequence = 1, from = 900, until = 60000): Value => sign("FreshnessHead", map({ 0: revision, 1: text("tenant"), 2: text("authority"), 3: bytes(cap), 4: u(1),
    5: get(content, 5), 6: text("publication"), 7: u(1), 8: u(sequence), 9: t(from), 10: t(until), 11: bytes(digest("revocation_state_digest", content)), 12: u(encode(content).length),
    13: bytes(fill(3, 16)), 14: bytes(digest("head_signer_delegation_digest", headDelegation)) }), 9);
  const response = (nonce = namespace.bootstrapNonce(), selectedTrust = trust, selectedState = state): Uint8Array => encode(sign("TrustBootstrapResponse", map({
    0: revision, 1: text("tenant"), 2: text("authority"), 3: bytes(nonce), 4: t(900), 5: t(10000), 6: bytes(encode(selectedTrust)), 7: bytes(encode(headFor(selectedState))), 8: bytes(fill(1, 16)),
  }), 7));
  const publicNoise = (role: number): Uint8Array => profile.includes("x25519") ? x25519.getPublicKey(fill(16 + role)) : p256.getPublicKey(fill(16 + role), false);
  const certificate = (role: number): Value => sign("IdentityCertificate", map({ 0: text("tenant"), 1: text(role === 0 ? clientSubject : "server"), 2: text(profile),
    3: map({ 0: u(profile.includes("x25519") ? 0 : 1), 1: bytes(publicNoise(role)) }), 4: bytes(ed25519.getPublicKey(fill(14 + role))), 5: u(role), 6: text("service"),
    7: bytes(fill(4, 16)), 8: t(800), 9: t(50000), 10: text("authority"), 11: u(1), 12: u(8), 13: text("credentials"), 14: u(1), 15: bytes(cap) }), 11);
  let client = certificate(0), server = certificate(1);
  const leg = options.leg ?? map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1), 6: text("example.com"), 7: u(443), 8: text("/flowersec/v4/direct"),
    9: text("http/1.1"), 10: text("flowersec.direct.v4"), 11: map({ 0: u(0), 1: { kind: "bool", value: true } }) });
  const candidateLegs = options.candidateLegs ?? [leg];
  const candidateValues = candidateLegs.map((candidateLeg, index) => map({ 0: bytes(fill(20 + index, 16)), 1: u(0), 2: u(0), 3: candidateLeg,
    6: array(map({ 0: text("tenant"), 1: text("authority"), 2: u(1), 3: bytes(cap), 4: u(3) })) }));
  const candidateRoutes = candidateValues.map((candidate, index) => digest("route_digest", map({ 0: u(0), 1: bytes(fill(20 + index, 16)), 2: candidateLegs[index]! })));
  const route = candidateRoutes[0]!;
  const contract = map({ 0: u(65536), 1: u(options.applicationProfile === undefined ? 8 : options.applicationProfile === "execution" ? 19 : 18), 2: u(options.applicationProfile === undefined ? 65536 : 1048576), 3: u(0), 4: map({ 0: u(10), 1: u(1000), 2: u(1000) }), 5: u(options.applicationProfile === undefined ? 0 : options.applicationProfile === "services" ? 1 : 2),
    ...(options.applicationProfile === undefined ? {} : { 6: u(options.rpcMaxGeneralOutstanding ?? 4) }) });
  let artifact = sign("Artifact", map({ 0: text("4"), 1: text("flowersec/4"), 2: text("4"), 3: text(profile), 4: text("tenant"), 5: bytes(fill(5, 16)), 6: bytes(leaseID),
    7: bytes(sessionNonce), 8: bytes(fill(24)), 9: bytes(digest("certificate_digest", client)), 10: bytes(digest("certificate_digest", server)), 11: text("service"), 12: array(...candidateValues), 13: contract,
    14: u((options.resume ? applicationResumeFeature() : 0n) | (options.datagram ? 1n : 0n)), 15: u(0), 16: options.resume ? map({ 0: { kind: "bool", value: true }, 1: u(0), 2: u(0), 3: u(8000), 4: u(4948) }) : map({ 0: { kind: "bool", value: false } }), 17: map({ 0: u(0) }), 18: t(800), 19: t(20000), 20: t(40000), 21: text("authority"), 22: u(1), 23: u(8),
    24: text("credentials"), 25: u(1), 26: bytes(cap) }), 12);
  const activationFor = (): Value => {
    const ad = digest("artifact_digest", artifact), indices = candidateValues.map((_candidate, index) => index);
    const set = map({ 0: bytes(ad), 1: array(...indices.map(index => map({ 0: u(index), 1: bytes(fill(20 + index, 16)), 2: bytes(candidateRoutes[index]!) }))) });
    const budget = map({ 0: map({ 0: u(8), 1: u(262144), 2: u(256) }), 1: u(32), 2: u(8 << 20), 3: u(8192), 4: u(2) });
    const selection = source === "live_authority" ? bytes(fill(20, 16)) : map({ 0: bytes(ad), 1: array(...indices.map(index => u(index))), 2: bytes(digest("candidate_set_digest", set)), 3: budget, 4: once });
    return sign("ActivationAuthorization", map({ 0: u(1), 1: text("spend"), 2: text("activate-1"), 3: text("tenant"), 4: bytes(fill(5, 16)), 5: bytes(leaseID), 6: bytes(ad),
      7: selection, 8: bytes(source === "live_authority" ? route : digest("route_set_digest", set)), 9: bytes(attemptID), 10: get(artifact, 9), 11: get(artifact, 10), 12: text("service"),
      13: t(950), 14: t(10000), 15: t(options.sessionNotAfterMS ?? 30000) }), 13);
  };
  let activation = activationFor();
  const config: CredentialVerifierConfig = { resources, clock, namespaces: [namespace], tenant: "tenant", audience: "service", clientSubject, serverSubject: "server", cryptoProfiles: [profile] };
  const input = (): CredentialInput & { readonly activation: Uint8Array } => ({ artifact: encode(artifact), clientCertificate: encode(client), serverCertificate: encode(server), activation: encode(activation), source, candidateIndex: 0 });
  return { namespace, config, input, response, headFor, route, cap, publicNoise, leaseID, sessionNonce, attemptID,
    bootstrap: () => namespace.bootstrap(response(), encode(state)),
    get artifact() { return artifact; }, set artifact(v: Value) { artifact = v; }, get activation() { return activation; }, set activation(v: Value) { activation = v; },
    get client() { return client; }, set client(v: Value) { client = v; }, get server() { return server; }, set server(v: Value) { server = v; },
    get trust() { return trust; }, set trust(v: Value) { trust = v; }, get state() { return state; }, set state(v: Value) { state = v; },
    refreshActivation: () => { activation = activationFor(); },
  };
}
// Export the reference's independent canonical syntax for mutation fixtures.
export { encode, head };
