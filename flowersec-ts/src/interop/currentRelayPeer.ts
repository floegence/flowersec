import { createHash, createPrivateKey, randomBytes, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createRegisteredLiveTunnelControlAuthority, type RegisteredLiveTunnelControlAuthority, type RegisteredLiveTunnelControlAuthorityOptions,
  ClockRate, ResourceRoot, ResourceVector, createTransportEnvironment, createGrantIssuer, createTunnelRuntime,
  createSQLitePoolBacking, openSQLiteAdmissionStore, type GrantIssuer, type SQLiteAdmissionStore,
  type SQLitePoolBacking, type TunnelRuntime, type TunnelCarrierOptions, type TransportEnvironment,
  createRegisteredPoolTunnelAuthority, createRegisteredTunnelControlAuthority, type RegisteredTunnelControlAuthority, type RegisteredTunnelControlAuthorityOptions, type RegisteredPoolTunnelAuthority, type RegisteredPoolTunnelAuthorityOptions, type GrantIssuanceInput,
} from "../node/index.js";
import type { V4CredentialPolicy } from "../v4/runtime/environment.js";
import { originalEnvironment } from "../v4/runtime/environment.js";
import { credentialDigest } from "../v4/runtime/credentialSupport.js";
import { Reference, type Value } from "../v4/testSupport/cbor.js";
import { bootstrapBody, readCurrentPeerMaterial, peerBytes, peerField, type CurrentPoolPeerMaterial, type CurrentLivePeerMaterial } from "./currentPeer.js";
import type { RelayLimits } from "../v4/runtime/relayCredentials.js";
import type { RelayNativePairLimits } from "../node/relayNativePair.js";

/** Trusted engineering installation input. It contains the signed parent
 * registration and signer installation, never imported authorization decisions
 * or relay lookup records. Grant issuance and runtime share one original store. */
export interface CurrentRelayPeerDeployment {
  readonly wire_revision: 4;
  /** Optional exclusive copy of the original engineering publication. */
  readonly material_publication_path?: string;
  readonly registration_json: string;
  readonly server_identity_seed: string; readonly server_dh_seed: string;
  readonly relay_identity_seed: string; readonly relay_certificate: string;
  readonly authority: string; readonly relay_audience: string; readonly relay_subject: string; readonly service: string;
  readonly control_trust_pem: string;
  readonly origin?: string;
  readonly native_tls?: Readonly<{ trustPEM: string; relay: Readonly<{ certificatePEM: string; privateKeyPEM: string }>; client: Readonly<{ certificatePEM: string; privateKeyPEM: string }>; server: Readonly<{ certificatePEM: string; privateKeyPEM: string }> }>;
  readonly server_control?: Omit<RegisteredTunnelControlAuthorityOptions, "issuer" | "material" | "serverControlCertificateDER" | "workMS"> & Readonly<{ serverControlCertificateDER: string; workMS: string }>;
  readonly live_control?: Readonly<{
    host: string; port: number; tls: RegisteredLiveTunnelControlAuthorityOptions["tls"];
    clientControlCertificateDER: string; serverControlCertificateDER: string;
    signingKeyID: string; activationSeed: string; maxActivationMS: string; maxSessionMS: string; workMS: string;
    applicationPolicy: "allow";
  }>;
  readonly signing: readonly [CurrentRelayPeerSigner, CurrentRelayPeerSigner];
  readonly limits: Readonly<{ envelope_bytes: number; total_bytes: string; datagram_bytes: number; rate_bytes_per_second: string;
    queue_bytes: number; pending_mappings: number; resident_mappings: number; total_mappings: number; queue_items: number }>;
}
interface CurrentRelayPeerSigner { readonly namespace: number; readonly issuer_key_id: string; readonly seed: string; readonly revocation_policy_id: string; readonly revocation_policy_revision: string; }
const textField = (value: Value): string => { if (value.kind !== "text") throw new Error("invalid engineering text"); return value.value; };
const uintField = (value: Value): bigint => { if (value.kind !== "uint") throw new Error("invalid engineering integer"); return value.value; };
const bytesField = (value: Value): Uint8Array => { if (value.kind !== "bytes") throw new Error("invalid engineering bytes"); return value.value; };
function quantity(value: string): bigint {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]{0,19})$/u.test(value) || BigInt(value) > 0xffffffffffffffffn) throw new Error("invalid engineering quantity"); return BigInt(value);
}
/** Publishes only after actual original Grant issuance has durably registered
 * both counterpart legs. Configuring a later consumer cannot create that row. */
export interface CurrentRelayPeerOptions {
  readonly carrier: "websocket" | "raw-quic"; readonly serverCarrier?: "websocket" | "raw-quic";
  readonly origin: string; readonly certificatePEM: string; readonly privateKeyPEM: string; readonly trustPEM: string;
  /** Independent TLS installation when the server logical leg listens here. */
  readonly serverListenerTLS?: Readonly<{ certificatePEM: string; privateKeyPEM: string }>;
  /** A trusted local deployment can prepare B in this same Environment before
   * original issuance. It must register the actual supplied ParentWinner. */
  readonly serverControl?: Omit<RegisteredTunnelControlAuthorityOptions, "issuer" | "material">;
  /** Reports the actual original control/listener Prepare to the engineering
   * driver so it can start B before awaiting original publication. */
  readonly liveControl?: Omit<RegisteredLiveTunnelControlAuthorityOptions, "live" | "relayRuntime"> & Readonly<{ live: Omit<RegisteredLiveTunnelControlAuthorityOptions["live"], "issuer" | "material"> }>;
  readonly onControlPrepared?: (address: Readonly<{ host: string; port: number }>) => void;
  readonly prepareServer?: (installation: Readonly<{ environment: TransportEnvironment; parentWinnerStore: SQLiteAdmissionStore; material: GrantIssuanceInput; policy: V4CredentialPolicy }>) => Promise<RegisteredPoolTunnelAuthorityOptions["server"]>;
  readonly serverAllow?: RegisteredPoolTunnelAuthorityOptions["serverAllow"];
  /** Joins the original local B store owners after its Acceptor has closed. */
  readonly cleanupPreparedServer?: () => Promise<void>;
}
export async function createCurrentRelayPeer(deployment: CurrentRelayPeerDeployment, options: CurrentRelayPeerOptions) {
  const owned: Uint8Array[] = [];
  try { return await installCurrentRelayPeer(deployment, options, owned); }
  catch (error) { for (const bytes of owned) bytes.fill(0); throw error; }
}
async function installCurrentRelayPeer(deployment: CurrentRelayPeerDeployment, options: CurrentRelayPeerOptions, owned: Uint8Array[]) {
  if (deployment.wire_revision !== 4 || !Array.isArray(deployment.signing) || deployment.signing.length !== 2) throw new Error("invalid current relay installation");
  const registration = readCurrentPeerMaterial(deployment.registration_json);
  if (registration.role !== 0 || registration.tunnels.length !== 0) throw new Error("current relay requires its trusted original parent registration");
  const acquire = (value: string, maximum: number, exact?: number): Uint8Array => { const bytes = peerBytes(value, maximum, exact); owned.push(bytes); return bytes; };
  const artifact = acquire(registration.artifact, 65536), activation = registration.source === "preauthorized_pool" ? acquire(registration.activation, 4096) : new Uint8Array(), clientCertificate = acquire(registration.client_certificate, 8192), serverCertificate = acquire(registration.server_certificate, 8192), route = acquire(registration.route, 16384), routeDigest = acquire(registration.route_digest, 32, 32), relayCertificate = acquire(deployment.relay_certificate, 8192);
  const decode = (bytes: Uint8Array): Value => { const result = new Reference().decode(bytes, "", {}, 270336n); if (!result.ok) throw new Error("invalid current relay registration"); return result.value; };
  const parent = decode(artifact), descriptor = decode(route), client = decode(clientCertificate), server = decode(serverCertificate);
  if (uintField(peerField(descriptor, "Route", "path_kind")) !== 1n) throw new Error("original relay registration must select a tunnel");
  const clientLeg = peerField(descriptor, "Route", "client_leg"), carrier = uintField(peerField(clientLeg, "Leg", "carrier"));
  if (carrier !== (options.carrier === "raw-quic" ? 0n : 1n) || !["localhost", "127.0.0.1"].includes(textField(peerField(clientLeg, "Leg", "host"))) || !Buffer.from(credentialDigest("route_digest", route)).equals(Buffer.from(routeDigest))) throw new Error("signed relay registration disagrees with its installation");
  const serverLeg = peerField(descriptor, "Route", "server_leg"), serverCarrier = options.serverCarrier ?? options.carrier;
  if (uintField(peerField(serverLeg, "Leg", "carrier")) !== (serverCarrier === "raw-quic" ? 0n : 1n)) throw new Error("signed server leg carrier disagrees with its independently configured server carrier");
  const directions = ([clientLeg, serverLeg] as const).map((leg, role) => {
    const dialer = uintField(peerField(leg, "Leg", "dialer_role")), listener = uintField(peerField(leg, "Leg", "listener_role"));
    if (!(dialer === BigInt(role) && listener === 2n || dialer === 2n && listener === BigInt(role))) throw new Error("signed relay leg does not connect its logical endpoint and relay");
    if (uintField(peerField(leg, "Leg", "endpoint_role")) !== BigInt(role)) throw new Error("signed relay leg has the wrong logical endpoint");
    const host = textField(peerField(leg, "Leg", "host")), port = Number(uintField(peerField(leg, "Leg", "port")));
    if (!["localhost", "127.0.0.1"].includes(host) || !Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("original relay physical listener address is missing");
    return { dialer, listener, host, port };
  });
  const ingressRole = directions[0]!.listener === 2n ? 0 : directions[1]!.listener === 2n ? 1 : undefined;
  if (directions[1]!.listener === 2n && options.serverListenerTLS === undefined) throw new Error("original server-leg relay listener requires its independent TLS installation");
  const primary = directions[ingressRole ?? 0]!, listenerHost = primary.host, port = primary.port;
  const candidates = peerField(parent, "Artifact", "candidates"), selectedID = bytesField(peerField(descriptor, "Route", "candidate_id"));
  if (candidates.kind !== "array") throw new Error("original candidate set is missing");
  const selected = candidates.value.map((candidate, index) => ({ candidate, index })).filter(({ candidate }) => Buffer.from(bytesField(peerField(candidate, "Candidate", "candidate_id"))).equals(Buffer.from(selectedID)));
  if (selected.length !== 1) throw new Error("original relay candidate selection is ambiguous"); const candidateIndex = selected[0]!.index;
  const tenant = textField(peerField(parent, "Artifact", "tenant_id")), audience = textField(peerField(parent, "Artifact", "audience"));
  const clientSubject = textField(peerField(client, "IdentityCertificate", "subject_id")), serverSubject = textField(peerField(server, "IdentityCertificate", "subject_id"));
  // This deployment hosts both relay legs, the authority stores, and the
  // registered B Session in one root, including their prepaid task positions.
  const limit = new ResourceVector([768n << 20n, 256n << 20n, 64n << 20n, 5000000n, 5000000n, 8192n, 5000n, 5000n, 5000n, 5000n, 5000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit, accounts: 2048, reservations: 4096, references: 8192, rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const beginning = performance.now(), now = BigInt(Date.now());
  let environment: TransportEnvironment;
  try { environment = createTransportEnvironment({ root, limit, tenantLimit: limit, tenantID: "1".repeat(32), environmentID: randomBytes(16).toString("hex"), runtimeBytes: 1024n,
    namespaces: registration.namespaces.length, sources: 1, acquisitions: 1, materials: 4, sessions: 4, dependencies: 24, acquireMS: 10000n, cleanupMS: 10000,
    random: destination => { crypto.getRandomValues(destination); }, clock: { profile: { rate: new ClockRate(100n, 1000000n, 1n), maxWidthMS: 200n, maxAgeMS: 60000n, maxRoundTripMS: 10000n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - beginning)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: now - 50n, upperMS: now + 50n }) } }); }
  catch (error) { root.close(); throw error; }
  let directory: string | undefined, backing: SQLitePoolBacking | undefined, store: SQLiteAdmissionStore | undefined, issuer: GrantIssuer | undefined, poolAuthority: RegisteredPoolTunnelAuthority | undefined, controlAuthority: RegisteredTunnelControlAuthority | undefined, liveControlAuthority: RegisteredLiveTunnelControlAuthority | undefined, runtime: TunnelRuntime | undefined, closing: Promise<void> | undefined;
  const close = (): Promise<void> => closing ??= (async () => {
    await liveControlAuthority?.close(); await runtime?.close(); await poolAuthority?.close(); await controlAuthority?.close(); await options.cleanupPreparedServer?.(); issuer?.close(); store?.close(); await store?.waitCleanup(); await environment.close(); await environment.waitCleanup();
    if (directory !== undefined) rmSync(directory, { recursive: true, force: true }); backing?.releaseRemoved(); for (const bytes of owned) bytes.fill(0); root.close();
  })();
  try {
    const owner = originalEnvironment(environment), namespaces: Awaited<ReturnType<typeof owner.namespace>>[] = [];
    for (const entry of registration.namespaces) {
      const namespace = owner.namespace({ tenant: entry.tenant, authority: entry.authority, rootKeyID: acquire(entry.root_key_id, 16, 16), rootPublicKey: acquire(entry.root_public_key, 32, 32), maxTrustLifetimeMS: 30000000n, bootstrapMS: 10000n, stateBytes: 65536, stateNodes: 131072 });
      await namespace.fetchBootstrap(async (request, response, state) => {
        const body = await bootstrapBody(environment, entry.bootstrap_url, JSON.stringify({ tenant: entry.tenant, authority: entry.authority, nonce: Buffer.from(request.nonce).toString("base64") }), request.signal, deployment.control_trust_pem);
        try { const result = JSON.parse(new TextDecoder().decode(body)) as { response: string; state: string }; const signed = peerBytes(result.response, response.length), content = peerBytes(result.state, state.length);
          try { response.set(signed); state.set(content); return { responseBytes: signed.length, stateBytes: content.length }; } finally { signed.fill(0); content.fill(0); }
        } finally { body.fill(0); }
      });
      if (namespace.activeVersion()[0] !== BigInt(entry.generation)) throw new Error("original namespace generation mismatch"); namespaces.push(namespace);
    }
    directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-ts-current-relay-"));
    backing = createSQLitePoolBacking(environment, join(directory, "authority.sqlite"), { maxPages: 256, maxRecords: 64, maxRecordBytes: 270336, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
    store = await openSQLiteAdmissionStore(backing, { create: true, identity: { authority: deployment.authority, storeID: new Uint8Array(createHash("sha256").update(directory).digest()), generation: 1n }, continuity: { check: () => undefined },
      bindings: [{ tenant, audience, issuer: bytesField(peerField(parent, "Artifact", "issuer_key_id")), serverIdentity: credentialDigest("certificate_digest", serverCertificate) }] });
    const signing = deployment.signing.map(record => {
      if (!Number.isSafeInteger(record.namespace) || record.namespace < 0 || record.namespace >= namespaces.length) throw new Error("original Grant namespace is missing");
      return { namespace: namespaces[record.namespace]!, issuerKeyID: acquire(record.issuer_key_id, 16, 16), seed: acquire(record.seed, 32, 32), revocationPolicyID: record.revocation_policy_id, revocationPolicyRevision: quantity(record.revocation_policy_revision) };
    }) as unknown as Parameters<typeof createGrantIssuer>[0]["signing"];
    const bounds = deployment.limits;
    const limits: RelayLimits = { envelopeBytes: BigInt(bounds.envelope_bytes), totalBytes: quantity(bounds.total_bytes), datagramBytes: BigInt(bounds.datagram_bytes), rateBytesPerSecond: quantity(bounds.rate_bytes_per_second), queueBytes: BigInt(bounds.queue_bytes), pendingMappings: BigInt(bounds.pending_mappings), residentMappings: BigInt(bounds.resident_mappings), totalMappings: BigInt(bounds.total_mappings), queueItems: BigInt(bounds.queue_items) };
    const credentials = { namespaces, tenant, audience, clientSubject, serverSubject, cryptoProfiles: [registration.profile] };
    const issuerOptions: Parameters<typeof createGrantIssuer>[0] = { environment, credentials, activationStore: store, routeDigest, signing, relayAudience: deployment.relay_audience, relaySubject: deployment.relay_subject, service: deployment.service, limits, maxLifetimeMS: 120000n, transactionMS: 10000n };
    const original: GrantIssuanceInput = { source: registration.source, artifact, activation, clientCertificate, serverCertificate, relayCertificate, candidateIndex };
    const forwarding: RelayNativePairLimits = { maxEnvelopeBytes: bounds.envelope_bytes, maxDatagramBytes: bounds.datagram_bytes, maxPendingNativeMappings: bounds.pending_mappings, maxResidentNativeMappings: bounds.resident_mappings, maxTotalNativeMappings: bounds.total_mappings, maxQueueItems: bounds.queue_items, maxQueueBytes: bounds.queue_bytes, runtimeBytes: 1024n };
    const roots = [...options.trustPEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(match => new Uint8Array(new X509Certificate(match[0]).raw));
    if (roots.length < 1 || roots.length > 64) throw new Error("original relay requires its bounded native trust installation");
    owned.push(...roots);
    const carrierOptions = (kind: "websocket" | "raw-quic"): TunnelCarrierOptions => kind === "raw-quic" ? { applicationStreams: Math.max(32, bounds.pending_mappings + bounds.resident_mappings), streamBufferBytes: Math.max(65544, bounds.envelope_bytes), runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n, trustRootsDER: roots } : { nativeCarrier: "wss", remoteAddress: "127.0.0.1", origin: options.origin, ca: [options.trustPEM], queueMessages: 8, nativeBytes: 1048576n, prepareBytes: 262144, runtimeBytes: 1024n };
    const relaySeed = acquire(deployment.relay_identity_seed, 32, 32), identityKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), relaySeed]), format: "der", type: "pkcs8" });
    const listenerTLS = (role: 0 | 1) => {
      const installed = role === 0 ? options : options.serverListenerTLS!;
      const certificate = new Uint8Array(new X509Certificate(installed.certificatePEM).raw), key = new Uint8Array(createPrivateKey(installed.privateKeyPEM).export({ format: "der", type: "pkcs8" })); owned.push(certificate, key);
      return { certificateChainDER: [certificate], privateKeyDER: key };
    };
    runtime = createTunnelRuntime({ environment, host: "127.0.0.1", port, serverName: listenerHost, tls: listenerTLS(ingressRole ?? 0), identityKey, relayCertificate,
      credentials: { ...credentials, audience: deployment.relay_audience, service: deployment.service, relaySubject: deployment.relay_subject }, activationStore: store, carrier: carrierOptions(options.carrier), serverCarrier: carrierOptions(serverCarrier), forwarding, deferForwarding: true, maxPairs: 1, handshakeMS: 10000n,
      ...(ingressRole === undefined ? {} : { ingressRole }), ...(directions[0]!.listener === 2n && directions[1]!.listener === 2n ? { oppositeListener: { host: "127.0.0.1", port: directions[1]!.port, serverName: directions[1]!.host, tls: listenerTLS(1) } } : {}) });
    // Native listeners exist before B prepares its physical dialer or the
    // original authority enters either issuance transaction.
    if (ingressRole !== undefined) await runtime.listen();
    if (registration.source === "live_authority") {
      const control = options.liveControl;
      if (control === undefined || options.serverControl !== undefined || options.prepareServer !== undefined) throw new Error("one_original_live_control_required");
      const endpoint = new URL(registration.live_control_base_url), boundHost = control.host.includes(":") ? `[${control.host}]` : control.host;
      const matchingHost = endpoint.hostname === boundHost || ["127.0.0.1", "::1"].includes(control.host) && endpoint.hostname === "localhost";
      if (endpoint.protocol !== "https:" || !matchingHost || Number(endpoint.port || "443") !== control.port || endpoint.pathname !== "/flowersec/control/live" || endpoint.search !== "" || endpoint.hash !== "" || endpoint.username !== "" || endpoint.password !== "" || control.live.authority !== deployment.authority || control.live.signingKeyID !== registration.activation_signing_key_id) throw new Error("original live registration differs from its independent control installation");
      liveControlAuthority = await createRegisteredLiveTunnelControlAuthority({ ...control, relayRuntime: runtime, live: { ...control.live, issuer: issuerOptions, material: { artifact, clientCertificate, serverCertificate, relayCertificate, candidateIndex } } });
      options.onControlPrepared?.(liveControlAuthority.address());
      const relayNamespace = registration.namespaces.findIndex(entry => entry.authority === textField(peerField(decode(relayCertificate), "IdentityCertificate", "revocation_authority_id")));
      if (relayNamespace < 0) throw new Error("original relay namespace is missing");
      const tunnels = ([0, 1] as const).map(role => {
        const signer = deployment.signing[role], namespace = registration.namespaces[signer.namespace]!;
        return { candidate_index: candidateIndex, role, relay_certificate: deployment.relay_certificate, grant_namespace: signer.namespace, relay_namespace: relayNamespace,
          live_grant: { authority: namespace.authority, issuer_key_id: signer.issuer_key_id, audience: deployment.relay_audience, service: deployment.service, revocation_policy_id: signer.revocation_policy_id, revocation_policy_revision: signer.revocation_policy_revision, max_not_after_ms: uintField(peerField(parent, "Artifact", "initiation_not_after_ms")).toString() } };
      });
      const material = (role: 0 | 1): CurrentLivePeerMaterial => ({ ...registration, role, identity_seed: role === 0 ? registration.identity_seed : deployment.server_identity_seed, dh_seed: role === 0 ? registration.dh_seed : deployment.server_dh_seed, tunnels });
      let configured = false;
      // Configure acknowledges the immutable pending registry. Only the live
      // authority's original TxB continuation enables physical forwarding.
      const start = (): void => { if (configured) throw new Error("original relay route was already configured"); configured = true; };
      const endpointURL = `${options.carrier === "raw-quic" ? "quic" : "wss"}://${directions[0]!.host}:${directions[0]!.port}${textField(peerField(clientLeg, "Leg", "path"))}`;
      return Object.freeze({ environment, runtime, endpointURL, start, endpointAArtifactJSON: JSON.stringify(material(0)), endpointBArtifactJSON: JSON.stringify(material(1)), close });
    }
    if (options.liveControl !== undefined) throw new Error("pool registration cannot use live control");
    let grants: Readonly<{ clientGrant: Uint8Array; serverGrant: Uint8Array }>;
    if (options.serverControl !== undefined) {
      if (options.prepareServer !== undefined) throw new Error("one_original_server_registration_required");
      controlAuthority = await createRegisteredTunnelControlAuthority({ ...options.serverControl, issuer: issuerOptions, material: original });
      options.onControlPrepared?.(controlAuthority.address());
      grants = await controlAuthority.takeOriginalPublication();
    } else if (options.prepareServer === undefined) {
      issuer = createGrantIssuer(issuerOptions); grants = await issuer.issue(original);
    } else {
      const policy: V4CredentialPolicy = { tenant, audience, clientSubject, serverSubject, authorities: namespaces.map(namespace => namespace.authority), cryptoProfiles: [registration.profile],
        tunnel: { role: 1, audience: deployment.relay_audience, service: deployment.service, relaySubject: deployment.relay_subject } };
      const serverOptions = await options.prepareServer(Object.freeze({ environment, parentWinnerStore: store, material: original, policy }));
      if (options.serverAllow === undefined) throw new Error("original server Allow installation required");
      poolAuthority = await createRegisteredPoolTunnelAuthority({ issuer: issuerOptions, material: original, server: serverOptions, publicationMS: 10000n, serverAllow: options.serverAllow });
      const issued = await poolAuthority.issue();
      grants = { clientGrant: issued.clientGrant, serverGrant: issued.serverGrant };
      for (const bytes of [issued.artifact, issued.activation, issued.clientCertificate, issued.serverCertificate, issued.relayCertificate]) bytes.fill(0);
    }
    owned.push(grants.clientGrant, grants.serverGrant);
    const relayNamespace = registration.namespaces.findIndex(entry => entry.authority === textField(peerField(decode(relayCertificate), "IdentityCertificate", "revocation_authority_id")));
    if (relayNamespace < 0) throw new Error("original relay namespace is missing");
    const originalTunnels = ([0, 1] as const).map(role => ({ candidate_index: candidateIndex, role,
      grant: Buffer.from(role === 0 ? grants.clientGrant : grants.serverGrant).toString("base64"), relay_certificate: deployment.relay_certificate,
      grant_namespace: deployment.signing[role].namespace, relay_namespace: relayNamespace }));
    const material = (role: 0 | 1): CurrentPoolPeerMaterial => ({ ...registration, role, identity_seed: role === 0 ? registration.identity_seed : deployment.server_identity_seed, dh_seed: role === 0 ? registration.dh_seed : deployment.server_dh_seed,
      tunnels: originalTunnels });
    let activated = false;
    const start = (): void => { if (activated) throw new Error("original relay route was already started"); activated = true; runtime!.activateRoute();
    if (ingressRole === undefined) {
      const outgoing = runtime!.connectOriginalPair([{ grant: grants.clientGrant, endpointCertificate: clientCertificate, relayCertificate }, { grant: grants.serverGrant, endpointCertificate: serverCertificate, relayCertificate }]);
      void outgoing.catch(() => undefined);
    } };
    const endpointURL = `${options.carrier === "raw-quic" ? "quic" : "wss"}://${directions[0]!.host}:${directions[0]!.port}${textField(peerField(clientLeg, "Leg", "path"))}`;
    return Object.freeze({ environment, runtime, endpointURL, ...(poolAuthority === undefined ? {} : { serverAcceptor: poolAuthority.acceptor(), serverAllow: poolAuthority.poolServerAllowBinding() }), start, endpointAArtifactJSON: JSON.stringify(material(0)), endpointBArtifactJSON: JSON.stringify(material(1)), close });
  } catch (error) { await close(); throw error; }
}
