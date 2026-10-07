import { createInterface } from "node:readline";
import { open as openFile, unlink, lstat } from "node:fs/promises";
import { createHash, createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import { isAbsolute, resolve as resolvePath } from "node:path";
import type { NodeLiveHTTPSOptions, Session, PoolServerAllowBinding } from "../node/index.js";
import { runCurrentParityServer, runCurrentParityClient, CurrentParityState, bindParity, exerciseCurrentParityServer, type CurrentParityReady, type CurrentPoolClientInstallation } from "./currentParity.js";
import { createCurrentRegisteredTunnelPeerServer, type CurrentRegisteredTunnelPeerDeployment } from "./currentRegisteredTunnelPeer.js";
import { createCurrentRelayPeer, type CurrentRelayPeerDeployment } from "./currentRelayPeer.js";
import { inspectCurrentTunnelMaterial, currentTunnelAuthorizations, type CurrentTunnelAuthorization } from "./currentTunnelMaterial.js";
import { readCurrentPeerMaterial, type CurrentPoolPeerMaterial, type CurrentRegisteredLiveClientInstallation, peerBytes } from "./currentPeer.js";

const RUNTIME = "node-typescript";
const ORIGIN = process.env.FLOWERSEC_PARITY_ORIGIN ?? "https://client.example";
export type Role =
  "server" | "client" | "relay" | "tunnel-endpoint-a" | "tunnel-endpoint-b";
export type ParityCarrier = "websocket" | "raw-quic";
export type ParityListener = "endpoint" | "relay";

export interface CurrentParityTopology {
  readonly id: string; readonly endpoint_a: string; readonly endpoint_b: string; readonly tunnel_runtime: string;
  readonly ingress_carrier_a: ParityCarrier; readonly ingress_carrier_b: ParityCarrier;
}
interface TunnelInput { readonly topology: CurrentParityTopology; readonly relay: CurrentRelayReady; readonly endpoint_b: CurrentEndpointBReady; }
function writeJSON(value: unknown): void { process.stdout.write(`${JSON.stringify(value)}\n`); }
function validateTunnelDimensions(topology: CurrentParityTopology, relay: CurrentRelayReady, endpoint: "endpoint_a" | "endpoint_b", carrier: ParityCarrier): void {
  if (topology === null || typeof topology !== "object" || relay === null || typeof relay !== "object" ||
    topology[endpoint] !== RUNTIME || topology.tunnel_runtime !== relay.runtime || topology.ingress_carrier_a !== relay.carrier ||
    topology.ingress_carrier_b !== (relay.server_carrier ?? relay.carrier) || topology[endpoint === "endpoint_a" ? "ingress_carrier_a" : "ingress_carrier_b"] !== carrier ||
    relay.type !== "relay-ready" || relay.path !== "tunnel") throw new Error("invalid tunnel topology dimensions");
}

export interface ParityPeerInput { next<T>(): Promise<T>; }
class PeerInput implements ParityPeerInput {
  readonly #reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  readonly #lines = this.#reader[Symbol.asyncIterator]();
  close(): void { this.#reader.close(); }

  async next<T>(): Promise<T> {
    const item = await this.#lines.next();
    if (item.done || item.value.trim() === "")
      throw new Error("peer stdin ended before the next protocol message");
    if (Buffer.byteLength(item.value) > 4194304) throw new Error("peer protocol message exceeds its input bound");
    return JSON.parse(item.value) as T;
  }
}

export interface CurrentRelayReady {
  readonly type: "relay-ready"; readonly runtime: string; readonly carrier: ParityCarrier; readonly path: "tunnel";
  readonly wire_revision: 4; readonly profile: string; readonly source: "preauthorized_pool" | "live_authority";
  readonly endpoint_url?: string; readonly trust_pem: string; readonly origin: string;
  readonly trust_roots_der?: readonly string[]; readonly server_certificate_der?: string;
  readonly server_carrier?: ParityCarrier; readonly route_digest: string;
  readonly client_tls_certificate_pem?: string; readonly client_tls_private_key_pem?: string;
  readonly server_tls_certificate_pem?: string; readonly server_tls_private_key_pem?: string;
  readonly material_digest?: string; readonly endpoint_a_artifact_json?: string; readonly endpoint_b_artifact_json?: string;
  readonly authorizations?: readonly CurrentTunnelAuthorization[]; readonly verification_records?: CurrentPoolPeerMaterial["namespaces"];
}
export interface CurrentParityMaterialPublication {
  readonly wire_revision: 4; readonly endpoint_a_artifact_json: string; readonly endpoint_b_artifact_json: string;
  readonly client_tls_certificate_pem?: string; readonly client_tls_private_key_pem?: string;
  readonly server_tls_certificate_pem?: string; readonly server_tls_private_key_pem?: string;
}
export interface CurrentEndpointBReady {
  readonly server_allow?: PoolServerAllowBinding;
  readonly client_tls_certificate_pem?: string; readonly client_tls_private_key_pem?: string;
  readonly type: "endpoint-b-ready"; readonly runtime: string; readonly carrier: ParityCarrier; readonly path: "tunnel"; readonly wire_revision: 4;
  readonly profile?: string; readonly source?: "preauthorized_pool" | "live_authority"; readonly relay: CurrentRelayReady;
  readonly endpoint_a_artifact_json: string; readonly endpoint_b_artifact_json: string;
  readonly authorizations?: readonly CurrentTunnelAuthorization[]; readonly verification_records?: CurrentPoolPeerMaterial["namespaces"];
}
async function currentV4Deployment(path: string | undefined): Promise<CurrentRelayPeerDeployment> {
  if (path === undefined || path.length === 0 || path.length > 4096) throw new Error("current relay requires --deployment or FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT");
  const file = await openFile(path, "r"), storage = Buffer.alloc(4194305); let length = 0;
  try {
    for (;;) {
      if (length === storage.length) throw new Error("current relay deployment exceeds its input bound");
      const read = await file.read(storage, length, storage.length - length, null);
      if (read.bytesRead === 0) break; length += read.bytesRead;
    }
    if (length > 4194304) throw new Error("current relay deployment exceeds its input bound");
    const parsed = JSON.parse(storage.subarray(0, length).toString("utf8")) as CurrentRelayPeerDeployment;
    if (parsed === null || typeof parsed !== "object" || parsed.wire_revision !== 4 || typeof parsed.registration_json !== "string") throw new Error("invalid current relay deployment");
    return parsed;
  } finally { storage.fill(0); await file.close(); }
}
export function requireCurrentRelay(ready: unknown, endpointRole?: 0 | 1): asserts ready is CurrentRelayReady {
  if (ready === null || typeof ready !== "object") throw new Error("invalid current relay ready envelope");
  const current = ready as Partial<CurrentRelayReady>;
  const inline = current.endpoint_a_artifact_json !== undefined || current.endpoint_b_artifact_json !== undefined;
  const localLive = current.source === "live_authority" && endpointRole !== undefined;
  const ownMaterial = endpointRole === 0 ? current.endpoint_a_artifact_json : current.endpoint_b_artifact_json;
  const oppositeMaterial = endpointRole === 0 ? current.endpoint_b_artifact_json : current.endpoint_a_artifact_json;
  if (current.type !== "relay-ready" || current.path !== "tunnel" || current.wire_revision !== 4 || (current.source !== "preauthorized_pool" && current.source !== "live_authority") ||
    typeof current.runtime !== "string" || current.runtime.length === 0 || !["websocket", "raw-quic"].includes(current.carrier ?? "") ||
    typeof current.profile !== "string" || !["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"].includes(current.profile) || typeof current.trust_pem !== "string" || current.trust_pem.length === 0 || Buffer.byteLength(current.trust_pem) > 1048576 ||
    typeof current.origin !== "string" || current.origin.length === 0 || current.origin.length > 2048 ||
    (localLive ? !inline || !boundedMaterial(ownMaterial) || oppositeMaterial !== ""
      : inline ? !boundedMaterial(current.endpoint_a_artifact_json) || !boundedMaterial(current.endpoint_b_artifact_json)
      : typeof current.material_digest !== "string" || !/^[a-f0-9]{64}$/u.test(current.material_digest))) throw new Error("current tunnel requires material from the original relay issuance");
  if (current.material_digest !== undefined && !/^[a-f0-9]{64}$/u.test(current.material_digest)) throw new Error("invalid current material digest");
  if (current.server_carrier !== undefined && current.server_carrier !== "websocket" && current.server_carrier !== "raw-quic") throw new Error("unsupported current server carrier");
  if (localLive) {
    const ownCertificate = endpointRole === 0 ? current.client_tls_certificate_pem : current.server_tls_certificate_pem;
    const ownKey = endpointRole === 0 ? current.client_tls_private_key_pem : current.server_tls_private_key_pem;
    const publicCertificate = endpointRole === 0 ? current.server_tls_certificate_pem : current.client_tls_certificate_pem;
    const oppositeKey = endpointRole === 0 ? current.server_tls_private_key_pem : current.client_tls_private_key_pem;
    if (oppositeKey !== "") throw new Error("current live endpoint received the opposite TLS private key");
    if (ownCertificate !== undefined || ownKey !== undefined) requireCurrentListenerTLS(ownCertificate, ownKey);
    if (publicCertificate !== undefined) {
      if (typeof publicCertificate !== "string" || publicCertificate.length === 0 || Buffer.byteLength(publicCertificate) > 262144 || new X509Certificate(publicCertificate).checkIP("127.0.0.1") !== "127.0.0.1") throw new Error("current live endpoint requires its opposite public TLS identity");
    }
  } else {
    if (current.client_tls_certificate_pem !== undefined || current.client_tls_private_key_pem !== undefined) requireCurrentListenerTLS(current.client_tls_certificate_pem, current.client_tls_private_key_pem);
    if (current.server_tls_certificate_pem !== undefined || current.server_tls_private_key_pem !== undefined) requireCurrentListenerTLS(current.server_tls_certificate_pem, current.server_tls_private_key_pem);
  }
  if (typeof current.route_digest !== "string" || Buffer.from(current.route_digest, "base64").length !== 32 || Buffer.from(current.route_digest, "base64").toString("base64") !== current.route_digest) throw new Error("invalid current relay route digest");
}
export function requireCurrentListenerTLS(certificatePEM: unknown, privateKeyPEM: unknown): asserts certificatePEM is string {
  if (typeof certificatePEM !== "string" || certificatePEM.length === 0 || Buffer.byteLength(certificatePEM) > 262144 || typeof privateKeyPEM !== "string" || privateKeyPEM.length === 0 || Buffer.byteLength(privateKeyPEM) > 65536) throw new Error("current server listener requires its complete original TLS deployment");
  const certificate = new X509Certificate(certificatePEM), key = createPublicKey(createPrivateKey(privateKeyPEM)).export({ type: "spki", format: "der" });
  if (!certificate.publicKey.export({ type: "spki", format: "der" }).equals(key) || certificate.checkIP("127.0.0.1") !== "127.0.0.1") throw new Error("current listener TLS identity disagrees with its original local deployment");
}
function boundedMaterial(value: unknown): value is string { return typeof value === "string" && value.length > 0 && Buffer.byteLength(value) <= 1048576; }

/** Detached publication equality precedes any Environment or carrier ingress.
 * It neither authorizes a Grant nor synthesizes an original durable record. */
export function requireCurrentTunnelPublication(publication: CurrentParityMaterialPublication, relay: CurrentRelayReady, endpointRole?: 0 | 1): void {
  if (relay.source === "live_authority" && endpointRole !== undefined) {
    if (publication === null || typeof publication !== "object" || publication.wire_revision !== 4) throw new Error("invalid current live local publication");
    const own = endpointRole === 0 ? publication.endpoint_a_artifact_json : publication.endpoint_b_artifact_json;
    const opposite = endpointRole === 0 ? publication.endpoint_b_artifact_json : publication.endpoint_a_artifact_json;
    if (!boundedMaterial(own) || opposite !== "") throw new Error("current live endpoint requires only its original local material");
    const local = inspectCurrentTunnelMaterial(own, endpointRole);
    if (local.clientLeg.carrier !== relay.carrier || local.serverLeg.carrier !== (relay.server_carrier ?? relay.carrier) || local.material.profile !== relay.profile || local.material.source !== relay.source || local.material.route_digest !== relay.route_digest) throw new Error("current publication differs from the fixed relay deployment");
    if (relay.endpoint_a_artifact_json !== publication.endpoint_a_artifact_json || relay.endpoint_b_artifact_json !== publication.endpoint_b_artifact_json) throw new Error("current endpoint altered original relay material");
    if (relay.authorizations !== undefined && (!Array.isArray(relay.authorizations) || relay.authorizations.length !== 0) || relay.verification_records !== undefined && !isDeepStrictEqual(relay.verification_records, local.material.namespaces)) throw new Error("current live relay projection differs from its original local publication");
    return;
  }
  if (publication === null || typeof publication !== "object" || publication.wire_revision !== 4 || !boundedMaterial(publication.endpoint_a_artifact_json) || !boundedMaterial(publication.endpoint_b_artifact_json)) throw new Error("invalid current paired publication");
  const client = inspectCurrentTunnelMaterial(publication.endpoint_a_artifact_json, 0), server = inspectCurrentTunnelMaterial(publication.endpoint_b_artifact_json, 1);
  if (client.clientLeg.listenerRole !== server.clientLeg.listenerRole || client.serverLeg.listenerRole !== server.serverLeg.listenerRole) throw new Error("current endpoints changed their signed physical direction");
  if (client.clientLeg.carrier !== relay.carrier || client.serverLeg.carrier !== (relay.server_carrier ?? relay.carrier) || client.material.profile !== relay.profile || client.material.source !== relay.source || client.material.route_digest !== relay.route_digest) throw new Error("current publication differs from the fixed relay deployment");
  for (const key of ["artifact", "activation", "client_certificate", "server_certificate", "route", "route_digest", "profile", "source", "generation", "namespaces", "tunnels", "activation_signing_key_id", "relay_deployment"] as const) {
    if (!isDeepStrictEqual(client.material[key], server.material[key])) throw new Error("current endpoints did not receive the same original paired publication");
  }
  if (client.material.source === "live_authority" && (server.material.source !== "live_authority" || client.material.live_control_base_url !== server.material.live_control_base_url)) throw new Error("current live registry changed its original control binding");
  if (relay.endpoint_a_artifact_json !== undefined && publication.endpoint_a_artifact_json !== relay.endpoint_a_artifact_json || relay.endpoint_b_artifact_json !== undefined && publication.endpoint_b_artifact_json !== relay.endpoint_b_artifact_json) throw new Error("current endpoint altered original relay material");
  if (relay.authorizations !== undefined && !isDeepStrictEqual(relay.authorizations, currentTunnelAuthorizations(publication.endpoint_a_artifact_json)) ||
    relay.verification_records !== undefined && !isDeepStrictEqual(relay.verification_records, client.material.namespaces)) throw new Error("current relay projection differs from its original publication");
}
export interface CurrentRelayAcknowledgment {
  readonly type: "configure"; readonly wire_revision: 4; readonly route_digest: string;
  readonly authorizations?: readonly unknown[]; readonly verification_records?: unknown;
}
export function requireCurrentRelayAcknowledgment(command: CurrentRelayAcknowledgment, relay: CurrentRelayReady): void {
  if (command === null || typeof command !== "object" || command.type !== "configure" ||
    command.wire_revision !== 4 || command.route_digest !== relay.route_digest ||
    !isDeepStrictEqual(command.authorizations, relay.authorizations) ||
    !isDeepStrictEqual(command.verification_records, relay.verification_records)) throw new Error("configuration differs from original committed publication");
}
function materialPublicationPath(value: string | undefined): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || !isAbsolute(value)) throw new Error("current tunnel requires an independently configured absolute material publication path"); return value;
}
export async function readCurrentParityMaterialPublication(path: string, digest: string): Promise<CurrentParityMaterialPublication> {
  materialPublicationPath(path);
  if (!/^[a-f0-9]{64}$/u.test(digest)) throw new Error("invalid current material digest");
  const file = await openFile(path, "r"), storage = Buffer.alloc(4194305); let length = 0;
  try {
    for (;;) {
      if (length === storage.length) throw new Error("current material publication exceeds its input bound");
      const read = await file.read(storage, length, storage.length - length, null); if (read.bytesRead === 0) break; length += read.bytesRead;
    }
    if (length > 4194304 || createHash("sha256").update(storage.subarray(0, length)).digest("hex") !== digest) throw new Error("current material publication binding failed");
    const material = JSON.parse(storage.subarray(0, length).toString("utf8")) as CurrentParityMaterialPublication;
    if (material === null || typeof material !== "object" || material.wire_revision !== 4 ||
      typeof material.endpoint_a_artifact_json !== "string" || material.endpoint_a_artifact_json.length === 0 || material.endpoint_a_artifact_json.length > 1048576 ||
      typeof material.endpoint_b_artifact_json !== "string" || material.endpoint_b_artifact_json.length === 0 || material.endpoint_b_artifact_json.length > 1048576) throw new Error("invalid current material publication");
    return Object.freeze(material);
  } finally { storage.fill(0); await file.close(); }
}
export async function publishCurrentParityMaterial(path: string, material: CurrentParityMaterialPublication): Promise<Readonly<{ digest: string; close(): Promise<void> }>> {
  materialPublicationPath(path);
  const encoded = Buffer.from(JSON.stringify(material));
  if (encoded.length > 4194304) { encoded.fill(0); throw new Error("current material publication exceeds its output bound"); }
  let owner: Awaited<ReturnType<typeof openFile>> | undefined, identity: Awaited<ReturnType<typeof lstat>> | undefined;
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => closing ??= (async () => {
    await owner?.close(); owner = undefined;
    if (identity !== undefined) {
      let current: Awaited<ReturnType<typeof lstat>>;
      try { current = await lstat(path); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
      if (current.ino !== identity.ino || current.dev !== identity.dev) throw new Error("current material publication ownership changed");
      await unlink(path);
    }
  })();
  try {
    owner = await openFile(path, "wx", 0o600); identity = await owner.stat(); await owner.writeFile(encoded); await owner.sync();
    return Object.freeze({ digest: createHash("sha256").update(encoded).digest("hex"), close });
  } catch (error) { await close(); throw error; } finally { encoded.fill(0); }
}
function currentV4Ready(material: string, relay: CurrentRelayReady, carrier: ParityCarrier): CurrentParityReady {
  return Object.freeze({ type: "ready", runtime: RUNTIME, carrier, path: "tunnel", wire_revision: 4, artifact_json: material, trust_pem: relay.trust_pem,
    origin: relay.origin, profile: relay.profile, source: relay.source, datagram: relay.carrier !== "websocket" && (relay.server_carrier ?? relay.carrier) !== "websocket" });
}
export async function runCurrentV4Relay(deployment: CurrentRelayPeerDeployment, input: ParityPeerInput, carrier: ParityCarrier, serverCarrier: ParityCarrier = carrier, clientListener?: ParityListener, serverListener?: ParityListener): Promise<void> {
  const registration = readCurrentPeerMaterial(deployment.registration_json), installed = deployment.live_control;
  const tls = deployment.native_tls, origin = deployment.origin;
  if (tls === undefined || typeof origin !== "string" || origin.length === 0 || typeof tls.trustPEM !== "string" || tls.trustPEM.length === 0 ||
      [tls.relay, tls.client, tls.server].some(identity => identity === undefined || typeof identity.certificatePEM !== "string" || identity.certificatePEM.length === 0 || typeof identity.privateKeyPEM !== "string" || identity.privateKeyPEM.length === 0)) throw new Error("current relay requires its independent native TLS and Origin installation");
  const roots = [...tls.trustPEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(match => new X509Certificate(match[0]).raw.toString("base64"));
  if (roots.length === 0 || roots.length > 64) throw new Error("current relay trust installation is invalid");
  const owned: Uint8Array[] = [];
  let relay: Awaited<ReturnType<typeof createCurrentRelayPeer>>;
  try {
    const physical = { carrier, serverCarrier, origin, certificatePEM: tls.relay.certificatePEM, privateKeyPEM: tls.relay.privateKeyPEM, trustPEM: tls.trustPEM, serverListenerTLS: tls.relay };
    if (registration.source === "live_authority") {
      if (installed === undefined || deployment.server_control !== undefined || installed.applicationPolicy !== "allow") throw new Error("current live relay requires its independently installed application policy and control");
      const clientCertificate = peerBytes(installed.clientControlCertificateDER, 65536), serverCertificate = peerBytes(installed.serverControlCertificateDER, 65536), activationSeed = peerBytes(installed.activationSeed, 32, 32); owned.push(clientCertificate, serverCertificate, activationSeed);
      const quantity = (value: string): bigint => { if (typeof value !== "string" || !/^[1-9][0-9]{0,19}$/u.test(value) || BigInt(value) > 0xffffffffffffffffn) throw new Error("invalid live control duration"); return BigInt(value); };
      relay = await createCurrentRelayPeer(deployment, { ...physical,
        onControlPrepared: address => writeJSON({ type: "relay-prepared", runtime: RUNTIME, wire_revision: 4, profile: registration.profile, path: "tunnel", source: "live_authority", carrier, server_carrier: serverCarrier, address, control_endpoint: registration.live_control_base_url }),
        liveControl: { host: installed.host, port: installed.port, tls: installed.tls, clientControlCertificateDER: clientCertificate, serverControlCertificateDER: serverCertificate,
          live: { authority: deployment.authority, signingKeyID: installed.signingKeyID, activationSeed, maxActivationMS: quantity(installed.maxActivationMS), maxSessionMS: quantity(installed.maxSessionMS), workMS: quantity(installed.workMS), authorize: async (_request, operation) => { operation.check(); return true; } } } });
    } else {
      const control = deployment.server_control;
      if (control === undefined || installed !== undefined || typeof control.workMS !== "string" || !/^[1-9][0-9]{0,4}$/u.test(control.workMS) || BigInt(control.workMS) > 60000n) throw new Error("current relay requires its original registered B control installation");
      const controlCertificate = peerBytes(control.serverControlCertificateDER, 65536); owned.push(controlCertificate);
      relay = await createCurrentRelayPeer(deployment, { ...physical, onControlPrepared: address => writeJSON({ type: "relay-prepared", runtime: RUNTIME, wire_revision: 4, profile: registration.profile, path: "tunnel", source: "preauthorized_pool", carrier, server_carrier: serverCarrier, control_endpoint: `https://${address.host}:${address.port}/flowersec/control/tunnel` }), serverControl: { ...control, workMS: BigInt(control.workMS), serverControlCertificateDER: controlCertificate } });
    }
  } finally { for (const value of owned) value.fill(0); }
  let publication: Awaited<ReturnType<typeof publishCurrentParityMaterial>> | undefined;
  try {
    const material = readCurrentPeerMaterial(relay.endpointAArtifactJSON); requireListenerSelection(relay.endpointAArtifactJSON, clientListener, serverListener);
    const originalPublication = { wire_revision: 4 as const, endpoint_a_artifact_json: relay.endpointAArtifactJSON, endpoint_b_artifact_json: relay.endpointBArtifactJSON, client_tls_certificate_pem: tls.client.certificatePEM, client_tls_private_key_pem: tls.client.privateKeyPEM, server_tls_certificate_pem: tls.server.certificatePEM, server_tls_private_key_pem: tls.server.privateKeyPEM };
    if (deployment.material_publication_path !== undefined) publication = await publishCurrentParityMaterial(deployment.material_publication_path, originalPublication);
    const ready: CurrentRelayReady = { type: "relay-ready", runtime: RUNTIME, carrier, path: "tunnel", profile: material.profile, source: material.source,
      endpoint_url: relay.endpointURL, trust_pem: tls.trustPEM, trust_roots_der: roots, server_certificate_der: new X509Certificate(tls.relay.certificatePEM).raw.toString("base64"), origin,
      ...originalPublication, ...(publication === undefined ? {} : { material_digest: publication.digest }), server_carrier: serverCarrier, route_digest: material.route_digest,
      authorizations: currentTunnelAuthorizations(relay.endpointAArtifactJSON), verification_records: material.namespaces };
    requireCurrentTunnelPublication(originalPublication, ready);
    writeJSON(ready);
    let acknowledged = false;
    let command = await input.next<CurrentRelayAcknowledgment | { type: "close" }>();
    while (command.type === "configure") {
      requireCurrentRelayAcknowledgment(command, ready); relay.start(); acknowledged = true;
      command = await input.next<CurrentRelayAcknowledgment | { type: "close" }>();
    }
    if (command.type !== "close" || !acknowledged) throw new Error("current relay did not receive close");
    // Runtime Close cancels its original ingress waiters and pair carriers,
    // then joins their physical termination before reporting these milestones.
    await relay.close(); const observed = relay.runtime.status();
    if (observed.listening || observed.authenticatedPairs !== 1n || observed.forwardedBytes === 0n || observed.activePairs !== 0 || observed.lastFailure !== undefined) throw new Error("current relay did not finish an authenticated forwarding pair");
    if (carrier === "raw-quic" && serverCarrier === "raw-quic" && observed.forwardedDatagrams === 0n) throw new Error("current relay did not forward the parity datagram");
    writeJSON({ type: "relay-result", runtime: RUNTIME, carrier, server_carrier: serverCarrier, path: "tunnel", wire_revision: 4, profile: material.profile, source: material.source,
      cases: ["admission", "pairing", "opaque-forwarding", ...(observed.forwardedDatagrams > 0n ? ["datagram-forwarding"] : []), "close", "cancel", "cleanup"], observed_plaintext: false,
      authenticated_pairs: observed.authenticatedPairs.toString(), forwarded_bytes: observed.forwardedBytes.toString(), forwarded_datagrams: observed.forwardedDatagrams.toString() });
  } finally { await relay.close(); await publication?.close(); }
}
export async function runCurrentV4EndpointB(input: ParityPeerInput, carrier: ParityCarrier, publicationPath?: string, clientListener?: ParityListener, serverListener?: ParityListener, deploymentPath?: string): Promise<void> {
  const deployment = await readRegisteredBDeployment(deploymentPath ?? process.env.FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT), state = new CurrentParityState("tunnel");
  const endpoint = await createCurrentRegisteredTunnelPeerServer(deployment, environment => state.plan(environment), { carrier, origin: deployment.origin, trustPEM: deployment.trustPEM });
  let session: Session | undefined, binding: Awaited<ReturnType<typeof bindParity>> | undefined;
  try {
    const envelope = await input.next<TunnelInput>(), { relay } = envelope;
    validateTunnelDimensions(envelope.topology, relay, "endpoint_b", carrier); requireCurrentRelay(relay, 1);
  const material: CurrentParityMaterialPublication = relay.endpoint_a_artifact_json !== undefined && relay.endpoint_b_artifact_json !== undefined ? { wire_revision: 4, endpoint_a_artifact_json: relay.endpoint_a_artifact_json, endpoint_b_artifact_json: relay.endpoint_b_artifact_json }
    : await readCurrentParityMaterialPublication(materialPublicationPath(publicationPath), relay.material_digest!);
  requireCurrentTunnelPublication(material, relay, 1); requireListenerSelection(material.endpoint_b_artifact_json, clientListener, serverListener);
  const publishedB = readCurrentPeerMaterial(material.endpoint_b_artifact_json);
  for (const field of ["artifact", "activation", "client_certificate", "server_certificate", "route", "route_digest", "profile", "source", "generation", "namespaces", "activation_signing_key_id"] as const) {
    if (!isDeepStrictEqual(publishedB[field], endpoint.material[field])) throw new Error("paired publication differs from B original independent registration");
  }
  if (publishedB.source === "live_authority" && (endpoint.material.source !== "live_authority" || publishedB.identity_seed !== endpoint.material.identity_seed || publishedB.dh_seed !== endpoint.material.dh_seed || publishedB.live_control_base_url !== endpoint.material.live_control_base_url || !isDeepStrictEqual(publishedB.tunnels, endpoint.material.tunnels))) throw new Error("paired publication changed B pending live scope");
  const signal = AbortSignal.timeout(30000);
  const serverCertificate = material.server_tls_certificate_pem ?? relay.server_tls_certificate_pem, serverKey = material.server_tls_private_key_pem ?? relay.server_tls_private_key_pem;
  requireCurrentListenerTLS(serverCertificate, serverKey);
  if (relay.origin !== deployment.origin || relay.trust_pem !== deployment.trustPEM || endpoint.listenerRole === 1n && (serverCertificate !== deployment.certificatePEM || serverKey !== deployment.privateKeyPEM)) throw new Error("detached parity publication differs from B trusted installation");
    const accepting = endpoint.acceptor.accept({ signal }); void accepting.catch(() => undefined);
    const clientCertificate = material.client_tls_certificate_pem ?? relay.client_tls_certificate_pem;
    const clientKey = relay.source === "live_authority" ? "" : material.client_tls_private_key_pem ?? relay.client_tls_private_key_pem;
    const ready: CurrentEndpointBReady = { type: "endpoint-b-ready", runtime: RUNTIME, carrier, path: "tunnel", wire_revision: 4, profile: relay.profile, source: relay.source,
      ...(endpoint.serverAllow === undefined ? {} : { server_allow: endpoint.serverAllow }),
      endpoint_a_artifact_json: material.endpoint_a_artifact_json, endpoint_b_artifact_json: material.endpoint_b_artifact_json, relay,
      ...(clientCertificate === undefined ? {} : { client_tls_certificate_pem: clientCertificate }),
      ...(clientKey === undefined ? {} : { client_tls_private_key_pem: clientKey }),
      ...(relay.authorizations === undefined ? {} : { authorizations: relay.authorizations }), ...(relay.verification_records === undefined ? {} : { verification_records: relay.verification_records }) };
    writeJSON(ready);
    const command = await input.next<{ type: string }>(); if (command.type !== "connect") throw new Error("current endpoint B did not receive connect");
    session = (await accepting).session; state.session = session; state.record("admission");
    binding = await bindParity(endpoint.environment, session, { authority: endpoint.policy.authorities[0]!, tenant: endpoint.policy.tenant, audience: endpoint.policy.audience,
      localSubject: endpoint.policy.serverSubject, peers: [{ subject: endpoint.policy.clientSubject, identityDigest: endpoint.clientIdentity }] }, signal);
    const datagramCarrier = relay.carrier === "websocket" || (relay.server_carrier ?? relay.carrier) === "websocket" ? "websocket" : carrier;
    await exerciseCurrentParityServer(session, state, binding, datagramCarrier, signal);
    await session.close(); state.record("close"); binding.service.close(); binding.contracts.close(); await endpoint.close();
    if (state.active !== 0 || session.cleanupStatus().status !== "complete") throw new Error("current endpoint B did not finish cleanup"); state.record("cleanup");
    writeJSON({ type: "endpoint-b-result", runtime: RUNTIME, carrier, path: "tunnel", cases: [...state.executed], wire_revision: 4, profile: relay.profile, source: relay.source });
  } finally { binding?.service.close(); binding?.contracts.close(); await session?.close(); await endpoint.close(); }
}
export async function runCurrentV4EndpointA(input: ParityPeerInput, carrier: ParityCarrier, clientListener?: ParityListener, serverListener?: ParityListener): Promise<void> {
  const envelope = await input.next<TunnelInput>(), ready = envelope.endpoint_b;
  if (ready === undefined || ready === null || typeof ready !== "object" || ready.relay === undefined || ready.relay === null || ready.type !== "endpoint-b-ready" || ready.carrier !== (ready.relay.server_carrier ?? ready.relay.carrier) || ready.path !== "tunnel") throw new Error("invalid current endpoint B envelope");
  validateTunnelDimensions(envelope.topology, ready.relay, "endpoint_a", carrier); requireCurrentRelay(ready.relay, 0);
  const current = ready as CurrentEndpointBReady;
  if (current.wire_revision !== 4 || current.profile !== undefined && current.profile !== current.relay.profile || current.source !== undefined && current.source !== current.relay.source ||
    typeof current.endpoint_a_artifact_json !== "string" || current.endpoint_a_artifact_json.length === 0 || current.endpoint_a_artifact_json.length > 1048576 ||
    current.relay.endpoint_a_artifact_json !== undefined && current.endpoint_a_artifact_json !== current.relay.endpoint_a_artifact_json ||
    current.relay.endpoint_b_artifact_json !== undefined && current.endpoint_b_artifact_json !== current.relay.endpoint_b_artifact_json) throw new Error("current endpoint B altered original relay material");
  if (current.authorizations !== undefined && !isDeepStrictEqual(current.authorizations, current.relay.authorizations) || current.verification_records !== undefined && !isDeepStrictEqual(current.verification_records, current.relay.verification_records)) throw new Error("current endpoint B changed original acknowledgement projections");
  if (current.relay.source === "live_authority" && (current.endpoint_b_artifact_json !== "" || "server_tls_private_key_pem" in current && current.server_tls_private_key_pem !== "")) throw new Error("current live A received the opposite private installation");
  requireCurrentTunnelPublication(current, current.relay, 0); requireListenerSelection(current.endpoint_a_artifact_json, clientListener, serverListener);
  const live = current.relay.source === "live_authority" ? await readLiveControlDeployment() : undefined;
  const pool = current.relay.source === "preauthorized_pool" ? await readPoolControlDeployment() : undefined;
  const clientCertificate = current.client_tls_certificate_pem ?? current.relay.client_tls_certificate_pem;
  const clientKey = current.client_tls_private_key_pem ?? current.relay.client_tls_private_key_pem;
  try { await runCurrentParityClient({ ...currentV4Ready(current.endpoint_a_artifact_json, current.relay, carrier),
    ...(current.server_allow === undefined ? {} : { server_allow: current.server_allow }),
    ...(clientCertificate === undefined ? {} : { client_tls_certificate_pem: clientCertificate }),
    ...(clientKey === undefined ? {} : { client_tls_private_key_pem: clientKey }) }, carrier, live, "endpoint-a-result", pool); }
  finally { if (live !== undefined && "clientPrivateKey" in live) live.clientPrivateKey.fill(0); }
}
async function readRegisteredBDeployment(path: string | undefined): Promise<CurrentRegisteredTunnelPeerDeployment> {
  if (typeof path !== "string" || path.length === 0 || path.length > 4096) throw new Error("current B requires --deployment or FLOWERSEC_PARITY_SERVER_CONTROL_DEPLOYMENT");
  const file = await openFile(path, "r"), storage = Buffer.alloc(4194305); let length = 0;
  try {
    for (;;) { if (length === storage.length) throw new Error("current B deployment exceeds its input bound"); const read = await file.read(storage, length, storage.length - length, null); if (read.bytesRead === 0) break; length += read.bytesRead; }
    const deployment = JSON.parse(storage.subarray(0, length).toString("utf8")) as CurrentRegisteredTunnelPeerDeployment;
    if (deployment === null || typeof deployment !== "object" || deployment.wire_revision !== 4 || !boundedMaterial(deployment.registration_json) || typeof deployment.trustPEM !== "string" || Buffer.byteLength(deployment.trustPEM) > 1048576 || typeof deployment.origin !== "string" || deployment.origin.length === 0 || deployment.origin.length > 2048 || deployment.control === undefined) throw new Error("invalid original registered B installation");
    return deployment;
  } finally { storage.fill(0); await file.close(); }
}
async function readPoolControlDeployment(): Promise<CurrentPoolClientInstallation> {
  const path = process.env.FLOWERSEC_PARITY_POOL_DEPLOYMENT;
  if (typeof path !== "string" || path.length === 0 || path.length > 4096) throw new Error("pool A requires FLOWERSEC_PARITY_POOL_DEPLOYMENT");
  const file = await openFile(path, "r"), storage = Buffer.alloc(1048577); let length = 0;
  try {
    for (;;) { if (length === storage.length) throw new Error("pool client deployment exceeds its input bound"); const read = await file.read(storage, length, storage.length - length, null); if (read.bytesRead === 0) break; length += read.bytesRead; }
    const parsed = JSON.parse(storage.subarray(0, length).toString("utf8")) as CurrentPoolClientInstallation;
    if (parsed === null || typeof parsed !== "object" || parsed.wire_revision !== 4 || typeof parsed.tenant !== "string" || typeof parsed.audience !== "string" || parsed.server_allow === null || typeof parsed.server_allow !== "object") throw new Error("invalid pool client deployment");
    return parsed;
  } finally { storage.fill(0); await file.close(); }
}
function requireListenerSelection(raw: string, client?: ParityListener, server?: ParityListener): void {
  const route = inspectCurrentTunnelMaterial(raw, readCurrentPeerMaterial(raw).role);
  if (client !== undefined && (route.clientLeg.listenerRole === 0 ? "endpoint" : "relay") !== client || server !== undefined && (route.serverLeg.listenerRole === 1 ? "endpoint" : "relay") !== server) throw new Error("physical listener arguments disagree with the original signed route");
}
export function parseArguments(arguments_: readonly string[]): Readonly<{ role: Role; carrier: ParityCarrier; serverCarrier?: ParityCarrier; clientListener?: ParityListener; serverListener?: ParityListener; wireRevision: 4; deploymentPath?: string; materialPublicationPath?: string }> {
  const role = arguments_[0];
  if (role !== "server" && role !== "client" && role !== "relay" && role !== "tunnel-endpoint-a" && role !== "tunnel-endpoint-b" || arguments_[1] !== "--carrier") throw new Error("usage: server-parity-peer server|client|relay|tunnel-endpoint-a|tunnel-endpoint-b --carrier websocket|raw-quic [--wire-revision 4] [--server-carrier websocket|raw-quic] [--client-listener endpoint|relay] [--server-listener endpoint|relay] [--deployment path] [--material-publication absolute_path]");
  const carrier = arguments_[2]; if (carrier !== "websocket" && carrier !== "raw-quic") throw new Error("unsupported parity carrier");
  const wireRevision = 4; let serverCarrier: ParityCarrier | undefined, clientListener: ParityListener | undefined, serverListener: ParityListener | undefined, deploymentPath: string | undefined, publicationPath: string | undefined; const seen = new Set<string>();
  for (let offset = 3; offset < arguments_.length; offset += 2) {
    const name = arguments_[offset]!, value = arguments_[offset + 1];
    if (seen.has(name) || value === undefined) throw new Error("invalid parity option"); seen.add(name);
    if (name === "--wire-revision" && value === "4") { /* Current engine only. */ }
    else if (name === "--server-carrier" && (value === "websocket" || value === "raw-quic")) serverCarrier = value;
    else if (name === "--client-listener" && (value === "endpoint" || value === "relay")) clientListener = value;
    else if (name === "--server-listener" && (value === "endpoint" || value === "relay")) serverListener = value;
    else if (name === "--deployment" && value.length > 0 && value.length <= 4096) deploymentPath = value;
    else if (name === "--material-publication" && value.length > 0 && value.length <= 4096) publicationPath = materialPublicationPath(value);
    else throw new Error("invalid parity option");
  }
  if ((clientListener !== undefined || serverListener !== undefined) && !["relay", "tunnel-endpoint-a", "tunnel-endpoint-b"].includes(role)) throw new Error("listener selection belongs to a tunnel peer");
  if (serverCarrier !== undefined && (role !== "relay" || wireRevision !== 4)) throw new Error("--server-carrier belongs to the current relay role");
  if (deploymentPath !== undefined && (role !== "relay" && role !== "tunnel-endpoint-b" || wireRevision !== 4)) throw new Error("--deployment belongs to a current relay or registered B role");
  if (publicationPath !== undefined && (role !== "tunnel-endpoint-b" || wireRevision !== 4)) throw new Error("--material-publication belongs to the current accepted endpoint role");
  return Object.freeze({ role, carrier, wireRevision, ...(clientListener === undefined ? {} : { clientListener }), ...(serverListener === undefined ? {} : { serverListener }), ...(serverCarrier === undefined ? {} : { serverCarrier }), ...(publicationPath === undefined ? {} : { materialPublicationPath: publicationPath }), ...(deploymentPath === undefined ? {} : { deploymentPath }) });
}

/** Explicit engineering deployment input. The control origin, CA and client
 * TLS identity come from this independently configured file, never material. */
async function readLiveControlDeployment(): Promise<NodeLiveHTTPSOptions | CurrentRegisteredLiveClientInstallation | undefined> {
  const path = process.env.FLOWERSEC_PARITY_LIVE_DEPLOYMENT;
  if (path === undefined) return undefined;
  if (path.length === 0 || path.length > 4096) throw new Error("invalid live parity deployment path");
  const file = await openFile(path, "r"), storage = Buffer.alloc(1048577);
  let length = 0;
  try {
    for (;;) {
      if (length === storage.length) throw new Error("live parity deployment exceeds its input bound");
      const read = await file.read(storage, length, storage.length - length, null);
      if (read.bytesRead === 0) break; length += read.bytesRead;
    }
    let input: { control?: unknown; relay_control?: unknown; baseURL?: unknown; remoteAddress?: unknown; authority?: unknown; tenant?: unknown; audience?: unknown;
      caPEM?: unknown; clientCertificatePEM?: unknown; clientPrivateKeyPEM?: unknown };
    try { input = JSON.parse(storage.subarray(0, length).toString("utf8")) as typeof input; }
    catch { throw new Error("invalid live parity deployment JSON"); }
    if (input === null || typeof input !== "object") throw new Error("invalid live parity deployment JSON");
    if (input.control !== undefined) {
      const original = input as unknown as Omit<CurrentRegisteredLiveClientInstallation, "control"> & { control: CurrentRegisteredTunnelPeerDeployment["control"] };
      if (typeof original.tenant !== "string" || typeof original.audience !== "string" || typeof original.control !== "object" || original.control === null ||
          typeof original.control.endpoint !== "string" || typeof original.control.authority !== "string" || typeof original.control.workMS !== "string" || !/^[1-9][0-9]{0,4}$/u.test(original.control.workMS) || BigInt(original.control.workMS) > 60000n) throw new Error("invalid registered live client binding");
      const control = original.control, tls = control.tls;
      if (tls === null || typeof tls !== "object" || [tls.certificatePEM, tls.privateKeyPEM, tls.trustPEM].some(value => typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > 262144)) throw new Error("invalid registered live client TLS installation");
      let relayControl: CurrentRegisteredLiveClientInstallation["relayControl"];
      if (input.relay_control !== undefined) {
        const relay = input.relay_control as CurrentRegisteredTunnelPeerDeployment["relay_control"];
        if (relay === undefined || relay === null || typeof relay !== "object" || typeof relay.endpoint !== "string" || typeof relay.authority !== "string" || typeof relay.workMS !== "string" || !/^[1-9][0-9]{0,4}$/u.test(relay.workMS) || BigInt(relay.workMS) > 60000n) throw new Error("invalid registered live client relay control installation");
        const relayURL = new URL(relay.endpoint), relayTLS = relay.tls;
        if (relayURL.protocol !== "https:" || relayURL.pathname !== "/" || relayURL.search !== "" || relayURL.hash !== "" || relayURL.username !== "" || relayURL.password !== "" ||
            relayTLS === null || typeof relayTLS !== "object" || [relayTLS.certificatePEM, relayTLS.privateKeyPEM, relayTLS.trustPEM].some(value => typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > 262144)) throw new Error("invalid registered live client relay TLS installation");
        relayControl = { endpoint: relayURL.href, authority: relay.authority, tls: { ...relayTLS }, workMS: BigInt(relay.workMS) };
      }
      return { tenant: original.tenant, audience: original.audience, ...(relayControl === undefined ? {} : { relayControl }), control: { endpoint: control.endpoint, authority: control.authority, tls: { ...tls }, workMS: BigInt(control.workMS) } };
    }
    for (const value of [input.baseURL, input.remoteAddress, input.authority, input.tenant, input.audience])
      if (typeof value !== "string" || value.length === 0 || value.length > 2048) throw new Error("invalid live parity deployment binding");
    if (!Array.isArray(input.caPEM) || input.caPEM.length < 1 || input.caPEM.length > 64 ||
        input.caPEM.some(value => typeof value !== "string" || value.length === 0 || value.length > 262144) ||
        typeof input.clientCertificatePEM !== "string" || input.clientCertificatePEM.length === 0 || input.clientCertificatePEM.length > 262144 ||
        typeof input.clientPrivateKeyPEM !== "string" || input.clientPrivateKeyPEM.length === 0 || input.clientPrivateKeyPEM.length > 65536)
      throw new Error("invalid live parity mutual TLS identity");
    return { baseURL: input.baseURL as string, remoteAddress: input.remoteAddress as string,
      authority: input.authority as string, tenant: input.tenant as string, audience: input.audience as string,
      ca: input.caPEM as string[], clientCertificate: input.clientCertificatePEM, clientPrivateKey: new TextEncoder().encode(input.clientPrivateKeyPEM),
      maxConcurrentRequests: 1, timeoutMS: 10000n, headerBytes: 4096, handshakeBytes: 262144, runtimeBytes: 1024n, providerBytes: 4n << 20n };
  } finally { storage.fill(0); await file.close(); }
}
export async function runParityPeer(arguments_: readonly string[] = process.argv.slice(2)): Promise<void> {
  const { role, carrier, serverCarrier, clientListener, serverListener, deploymentPath, materialPublicationPath: publicationPath } = parseArguments(arguments_);
  const input = new PeerInput();
  try {
    switch (role) {
      case "server": await runCurrentParityServer(carrier, ORIGIN); break;
      case "client": {
        const ready = await input.next<CurrentParityReady>(), live = ready.source === "live_authority" ? await readLiveControlDeployment() : undefined;
        const pool = ready.source === "preauthorized_pool" && ready.path === "tunnel" ? await readPoolControlDeployment() : undefined;
        try { await runCurrentParityClient(ready, carrier, live, "client-result", pool); } finally { if (live !== undefined && "clientPrivateKey" in live) live.clientPrivateKey.fill(0); }
        break;
      }
      case "relay": await runCurrentV4Relay(await currentV4Deployment(deploymentPath ?? process.env.FLOWERSEC_PARITY_CURRENT_V4_DEPLOYMENT), input, carrier, serverCarrier ?? carrier, clientListener, serverListener); break;
      case "tunnel-endpoint-a": await runCurrentV4EndpointA(input, carrier, clientListener, serverListener); break;
      case "tunnel-endpoint-b": await runCurrentV4EndpointB(input, carrier, publicationPath ?? process.env.FLOWERSEC_PARITY_CURRENT_V4_MATERIAL_PUBLICATION, clientListener, serverListener, deploymentPath); break;
    }
  } finally { input.close(); }
}

if (process.argv[1] !== undefined && resolvePath(process.argv[1]) === fileURLToPath(import.meta.url)) await runParityPeer().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
