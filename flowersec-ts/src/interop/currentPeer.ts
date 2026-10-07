import { createHash, createPrivateKey, randomBytes, X509Certificate } from "node:crypto";
import { copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import {
  ClockRate, MethodDefinition, ServiceDefinition, ResourceRoot, ResourceVector,
  configureNodeWSS, configureNodeRawQUIC, connect, createTransportEnvironment, createSQLitePoolBacking,
  openSQLitePoolStore, bytesMessageCodec, createNodeLiveHTTPS, createRegisteredLiveTunnelClientAuthorization,
  createNodePoolServerAllow, type NodePoolServerAllowOptions, type PoolServerAllowBinding,
  type RegisteredTunnelControlClientOptions, type PoolServerAllowConfiguration,
  type ConnectionMaterialSource, type ConnectionRequirements, type NodeWSSClient,
  type Session, type SQLitePoolStore, type TransportEnvironment, type HandlerPlan, type NodeLiveHTTPSOptions,
} from "../node/index.js";
import { Reference, type Value } from "../v4/testSupport/cbor.js";
import { wireMaps } from "../v4/runtime/schemaRegistry.js";
import { originalEnvironment, type V4CredentialPolicy } from "../v4/runtime/environment.js";
import { credentialDigest } from "../v4/runtime/credentialSupport.js";
import { currentPeerContract } from "./currentContracts.js";
import type { V4LiveAuthorizationConfig } from "../v4/runtime/liveAuthorization.js";

/** Explicit engineering peer application contract; never a production key
 * locator. The independently trusted peer supplies complete signed v4 maps. */
interface CurrentPeerMaterialFields {
  readonly wire_revision: 4;
  readonly profile: string;
  readonly generation: Readonly<{ source: string; generation: number }>;
  readonly role: 0 | 1;
  readonly artifact: string;
  readonly client_certificate: string;
  readonly server_certificate: string;
  readonly route: string;
  readonly route_digest: string;
  readonly relay_deployment?: Readonly<{ RouteDigest: readonly number[]; Profile: string }>;
  readonly activation_signing_key_id: string;
  readonly identity_seed: string;
  readonly dh_seed: string;
  readonly namespaces: readonly Readonly<{
    tenant: string; authority: string; generation: number;
    root_key_id: string; root_public_key: string; bootstrap_url: string; state_url: string;
  }>[];
  readonly tunnels: readonly CurrentPeerTunnelMaterial[];
}
export interface CurrentPeerTunnelMaterial {
  readonly candidate_index: number; readonly role: 0 | 1;
  readonly grant?: string | null; readonly relay_certificate: string;
  /** Trusted registration scope; the original live response supplies the Grant. */
  readonly live_grant?: Readonly<{ authority: string; issuer_key_id: string; audience: string; service: string;
    revocation_policy_id: string; revocation_policy_revision: string; max_not_after_ms: string }>;
  readonly grant_namespace: number; readonly relay_namespace: number;
}
export type CurrentPoolPeerMaterial = CurrentPeerMaterialFields & Readonly<{ source: "preauthorized_pool"; activation: string }>;
export type CurrentLivePeerMaterial = CurrentPeerMaterialFields & Readonly<{ source: "live_authority"; activation: "" | null; live_control_base_url: string }>;
export type CurrentPeerMaterial = CurrentPoolPeerMaterial | CurrentLivePeerMaterial;
const profileX = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const profileP = "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1";
const reference = new Reference();
export function peerBytes(value: string, maximum: number, exact?: number): Uint8Array {
  if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) throw new Error("invalid engineering byte string");
  const bytes = new Uint8Array(Buffer.from(value, "base64"));
  if (bytes.length === 0 || bytes.length > maximum || exact !== undefined && bytes.length !== exact || Buffer.from(bytes).toString("base64") !== value) { bytes.fill(0); throw new Error("invalid engineering byte string"); }
  return bytes;
}
function decode(bytes: Uint8Array): Value {
  const result = reference.decode(bytes, "", {}, 270336n);
  if (!result.ok) throw new Error(`invalid engineering canonical map: ${result.error}`);
  return result.value;
}
export function peerField(value: Value, schema: string, name: string): Value {
  const entry = Object.entries(wireMaps[schema]!.fields).find(([, field]) => field.name === name);
  if (entry === undefined || value.kind !== "map") throw new Error("missing engineering field");
  const found = value.value.find(([key]) => key.kind === "uint" && key.value === BigInt(entry[0]));
  if (found === undefined) throw new Error(`missing engineering ${schema}.${name}`);
  return found[1];
}
function text(value: Value): string { if (value.kind !== "text") throw new Error("expected engineering text"); return value.value; }
function uint(value: Value): bigint { if (value.kind !== "uint") throw new Error("expected engineering integer"); return value.value; }
function data(value: Value): Uint8Array { if (value.kind !== "bytes") throw new Error("expected engineering bytes"); return value.value; }
export function readCurrentPeerMaterial(raw: string): CurrentPeerMaterial {
  if (typeof raw !== "string" || Buffer.byteLength(raw) > 1048576) throw new Error("engineering material is too large");
  const value = JSON.parse(raw) as CurrentPeerMaterial;
  if (value === null || typeof value !== "object" || value.wire_revision !== 4 || (value.role !== 0 && value.role !== 1) || (value.source !== "preauthorized_pool" && value.source !== "live_authority") ||
      ![profileX, profileP].includes(value.profile) || !Number.isSafeInteger(value.generation?.generation) || value.generation.generation < 1 ||
      !Array.isArray(value.namespaces) || value.namespaces.length < 1 || value.namespaces.length > 16 || !Array.isArray(value.tunnels) || value.tunnels.length > 16) throw new Error("unsupported engineering material");
  peerBytes(value.generation.source, 16, 16).fill(0);
  peerBytes(value.identity_seed, 32, 32).fill(0); peerBytes(value.dh_seed, 32, 32).fill(0);
  for (const [name, maximum] of [["artifact", 65536], ["client_certificate", 16384], ["server_certificate", 16384], ["route", 16384]] as const) peerBytes(value[name], maximum).fill(0);
  peerBytes(value.route_digest, 32, 32).fill(0);
  const tunnelSlots = new Set<string>();
  for (const tunnel of value.tunnels) {
    if (tunnel === null || typeof tunnel !== "object" || !Number.isSafeInteger(tunnel.candidate_index) || tunnel.candidate_index < 0 || tunnel.candidate_index >= 16 || (tunnel.role !== 0 && tunnel.role !== 1) ||
      !Number.isSafeInteger(tunnel.grant_namespace) || tunnel.grant_namespace < 0 || tunnel.grant_namespace >= value.namespaces.length || !Number.isSafeInteger(tunnel.relay_namespace) || tunnel.relay_namespace < 0 || tunnel.relay_namespace >= value.namespaces.length)
      throw new Error("invalid engineering tunnel material");
    const slot = `${tunnel.candidate_index}/${tunnel.role}`; if (tunnelSlots.has(slot)) throw new Error("duplicate engineering tunnel material"); tunnelSlots.add(slot);
    peerBytes(tunnel.relay_certificate, 16384).fill(0);
    if (value.source === "preauthorized_pool") {
      if (tunnel.live_grant !== undefined || typeof tunnel.grant !== "string") throw new Error("pool tunnel requires its actual issued Grant");
      peerBytes(tunnel.grant, 65536).fill(0);
    } else {
      const scope = tunnel.live_grant, identifier = /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u, integer = /^(?:0|[1-9][0-9]{0,19})$/u;
      if ((tunnel.grant !== undefined && tunnel.grant !== null && tunnel.grant !== "") || scope === undefined || ![scope.authority, scope.audience, scope.service, scope.revocation_policy_id].every(value => typeof value === "string" && identifier.test(value)) ||
        scope.authority !== value.namespaces[tunnel.grant_namespace]!.authority || typeof scope.revocation_policy_revision !== "string" || !integer.test(scope.revocation_policy_revision) || BigInt(scope.revocation_policy_revision) > 0xffffffffffffffffn ||
        typeof scope.max_not_after_ms !== "string" || !integer.test(scope.max_not_after_ms) || BigInt(scope.max_not_after_ms) <= 0n || BigInt(scope.max_not_after_ms) > 0xffffffffffffffffn) throw new Error("live tunnel requires its trusted pending Grant scope");
      peerBytes(scope.issuer_key_id, 16, 16).fill(0);
    }
  }
  if (value.source === "preauthorized_pool") peerBytes(value.activation, 65536).fill(0);
  else if ((value.activation !== "" && value.activation !== null) || typeof value.live_control_base_url !== "string" || value.live_control_base_url.length === 0 || value.live_control_base_url.length > 2048)
    throw new Error("live engineering material must leave activation to the original control authority");
  return value;
}
export const peerLimits = Object.freeze({
  maxFrame: 65536, maxStreams: 18, receiveQueueBytes: 16384, maxDataBytes: 4096,
  maxCursorBytes: 65536, maxWriteBytes: 65536, maxGeneralOutstanding: 32,
  writeDeadlineMS: 10000n, operationDeadlineMS: 10000n,
  rekeyPrepareMS: 1000n, rekeyProtocolMS: 1000n, rekeyConfirmationMS: 1000n, cryptoKeys: 100,
});
// Native admission prepays the ordinary stream positions, its finite RPC
// selection positions, and the fixed service channel before original Acquire.
export const peerRawQUICCapacity = peerLimits.maxStreams + Math.min(128, Math.max(4, peerLimits.maxStreams)) + 1;
// The Go engineering authority derives revision "1" contracts from the
// shared current corpus. Application payloads are bounded JSON bytes; codec
// declarations never replace the authenticated ServiceContract digest.
const codec = bytesMessageCodec({ schemaDigest: new Uint8Array(32), revision: "1", maxMessageBytes: 4096 });
function peerUnary(typeID: number) {
  return new MethodDefinition({ typeID, shape: "unary", unarySemantics: "transient", request: codec, response: codec,
    requestMaxBytes: 4096, minResponseLimitBytes: 0, maxResponseBytes: 4096, restartFlush: false });
}
export const peerPingMethod = peerUnary(7001);
export const peerNotifyMethod = new MethodDefinition({ typeID: 7002, shape: "notify", notifySemantics: "observation", request: codec,
  requestMaxBytes: 4096, responseRevision: "1", restartFlush: false });
export const peerCompletionMethod = peerUnary(7003);
export const peerDatagramBarrierMethod = peerUnary(7005);
export const peerPingService = new ServiceDefinition({ namespace: "flowersec.parity", methods: { ping: peerPingMethod, notification: peerNotifyMethod } });
export const peerCompletionService = new ServiceDefinition({ namespace: "flowersec.parity", methods: { completion: peerCompletionMethod } });
export const peerDatagramBarrierService = new ServiceDefinition({ namespace: "flowersec.parity", methods: { datagramBarrier: peerDatagramBarrierMethod } });
const queryDigest = new Uint8Array(32); queryDigest[0] = 9;
export const peerServices = Object.freeze({ query: { typeID: 7, contractDigest: queryDigest },
  definitions: [peerPingService, peerCompletionService, peerDatagramBarrierService], maxMethods: 4, maxCaptureBytes: 1048576,
  notificationMethods: [{ namespace: "flowersec.parity", method: peerNotifyMethod, contract: currentPeerContract(7002), permission: "allowed" as const }] });
/** Explicit engineering application encoding, separate from signed transport
 * material and the SDK's bounded bytes codec. */
export function peerJSONBytes(value: unknown): Uint8Array {
  const json = JSON.stringify(value);
  if (typeof json !== "string" || json.length > 4096) throw new Error("engineering payload exceeds its declared bound");
  const bytes = new TextEncoder().encode(json);
  if (bytes.length > 4096) { bytes.fill(0); throw new Error("engineering payload exceeds its declared bound"); }
  return bytes;
}
export function peerJSONValue(bytes: Uint8Array): unknown {
  if (bytes.length > 4096) throw new Error("engineering response exceeds its declared bound");
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}
export const peerRequirements: ConnectionRequirements = Object.freeze({ independent_reliable_read_progress: false, bound_stream_input_isolation: false,
  datagram: false, local_consumer_tls13_verification: true, application_profile: "services" });

/** The trusted fixture transport has one physical bounded request. A provider
 * returns only after both response and socket have relinquished its buffers. */
export async function bootstrapBody(environment: TransportEnvironment, rawURL: string, body: string, signal: AbortSignal, trustPEM?: string): Promise<Uint8Array> {
  const url = new URL(rawURL);
  if (!["http:", "https:"].includes(url.protocol) || !["127.0.0.1", "[::1]", "localhost"].includes(url.hostname) || url.username || url.password || url.hash || Buffer.byteLength(body) > 2048) throw new Error("invalid trusted engineering control endpoint");
  const dependency = originalEnvironment(environment).admitDependency("interop_bootstrap_http", new ResourceVector([524288n + 4096n, 4n << 20n, 0n, 16n, 4n, 8n, 1n, 1n, 1n, 0n, 5n]));
  const output = new Uint8Array(524288), wire = Buffer.from(body), abort = new AbortController();
  let request: ReturnType<typeof httpRequest> | undefined, response: IncomingMessage | undefined;
  let requestDone = Promise.resolve(), responseDone = Promise.resolve(), socketDone = Promise.resolve();
  const cancel = () => { abort.abort(); request?.destroy(new Error("canceled")); response?.destroy(); };
  dependency.onClose(cancel); signal.addEventListener("abort", cancel, { once: true });
  let count = 0;
  try {
    dependency.check(); if (signal.aborted) throw new Error("canceled");
    await new Promise<void>((resolve, reject) => {
      const create = url.protocol === "https:" ? httpsRequest : httpRequest;
      request = create(url, { method: "POST", agent: false, signal: abort.signal, maxHeaderSize: 4096,
        headers: { "content-type": "application/json", "content-length": String(wire.length), connection: "close" },
        ...(url.hostname === "localhost" ? { lookup: (_host, options, callback) => {
          // Node may request all address forms from a custom lookup. Return
          // the shape requested by that mode; passing a scalar to an `all`
          // lookup makes the socket path read an undefined address.
          if (options.all) callback(null, [{ address: "127.0.0.1", family: 4 }]);
          else callback(null, "127.0.0.1", 4);
        } } : {}),
        ...(url.protocol === "https:" ? { minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ...(trustPEM === undefined ? {} : { ca: trustPEM }), rejectUnauthorized: true } : {}),
      }, incoming => {
        response = incoming; responseDone = new Promise(done => incoming.once("close", done));
        if (incoming.statusCode !== 200 || incoming.headers["content-encoding"] !== undefined) { incoming.destroy(); reject(new Error("engineering control request failed")); return; }
        incoming.on("error", reject);
        incoming.on("data", (chunk: Buffer) => {
          try {
            dependency.check(); if (signal.aborted || chunk.length > output.length - count) throw new Error("engineering control response is too large or canceled");
            output.set(chunk, count); count += chunk.length;
          } catch (error) { incoming.destroy(); reject(error); }
        });
        incoming.once("end", () => { if (!incoming.complete) reject(new Error("engineering control response was truncated")); else resolve(); });
        incoming.once("aborted", () => reject(new Error("engineering control response was aborted")));
      });
      requestDone = new Promise(done => request!.once("close", done));
      request.once("socket", socket => { socketDone = new Promise(done => socket.once("close", done)); });
      request.on("error", reject); request.setTimeout(10000, () => request!.destroy(new Error("engineering control deadline")));
      dependency.check(); if (signal.aborted) { cancel(); reject(new Error("canceled")); return; }
      request.end(wire);
    });
    dependency.check(); if (signal.aborted) throw new Error("canceled");
    return output.slice(0, count);
  } finally {
    request?.destroy(); response?.destroy();
    await Promise.all([requestDone, responseDone, socketDone]);
    signal.removeEventListener("abort", cancel); wire.fill(0); output.fill(0); dependency.release();
  }
}
interface CurrentPeerOwner {
  readonly environment: TransportEnvironment;
  readonly root: ResourceRoot;
  readonly identityKey: ReturnType<typeof createPrivateKey>;
  readonly noiseKey: ReturnType<typeof createPrivateKey>;
  readonly policy: V4CredentialPolicy;
  readonly applicationProfile: "transport" | "services";
  readonly carrierKind: "websocket" | "raw-quic" | "webtransport";
  readonly path: "direct" | "tunnel";
  readonly candidateAttempts: number;
  readonly dialerRole: bigint; readonly listenerRole: bigint;
  readonly clientIdentity: string;
  readonly endpoint: string;
  readonly routeDigest: Uint8Array;
  readonly initiation: Readonly<{ from: bigint; until: bigint }>;
  readonly serverIdentity: string;
  registerSource(client: Pick<NodeWSSClient, "registerPoolSource" | "registerLiveSource">): ConnectionMaterialSource;
  close(): Promise<void>;
}
export interface CurrentPeerClient extends CurrentPeerOwner {
  readonly material: CurrentPoolPeerMaterial;
  readonly poolStore: SQLitePoolStore;
  spentCount(): number;
}
export interface CurrentLivePeerClient extends CurrentPeerOwner {
  readonly material: CurrentLivePeerMaterial;
  readonly liveAuthority: V4LiveAuthorizationConfig;
}
/** Independently configured mutual-TLS control input is mandatory for live
 * authority; enclosed material never selects its client identity or CA. */
export interface CurrentRegisteredLiveClientInstallation {
  readonly tenant: string; readonly audience: string;
  readonly control: Omit<RegisteredTunnelControlClientOptions, "identityKey">;
  readonly relayControl?: RegisteredTunnelControlClientOptions["relayControl"];
}
export type CurrentLivePeerClientOptions = Readonly<{ trustPEM?: string }> & (
  Readonly<{ liveHTTPS: NodeLiveHTTPSOptions; registeredLive?: never }> |
  Readonly<{ registeredLive: CurrentRegisteredLiveClientInstallation; liveHTTPS?: never }>);
export async function createCurrentLivePeerClient(raw: string, options: CurrentLivePeerClientOptions): Promise<CurrentLivePeerClient> {
  const material = readCurrentPeerMaterial(raw);
  if (material.source !== "live_authority" || material.role !== 0) throw new Error("live engineering client requires original role 0 live material");
  const owner = await createPeerClient(material, options);
  if (!("liveAuthority" in owner)) { await owner.close(); throw new Error("invalid original live owner"); }
  return owner;
}
/** Bounded source/storage setup is shared by Node WSS and the browser bridge
 * fixture. The latter still runs the actual browser carrier and key adapter. */
export async function createCurrentPeerClient(raw: string, options: Readonly<{ trustPEM?: string }> = {}): Promise<CurrentPeerClient> {
  const material = readCurrentPeerMaterial(raw);
  if (material.source !== "preauthorized_pool" || material.role !== 0) throw new Error("pool engineering client requires original role 0 pool material");
  const owner = await createPeerClient(material, options);
  if (!("poolStore" in owner)) { await owner.close(); throw new Error("invalid original pool owner"); }
  return owner;
}
/** Each acquisition transfers the next independently issued direct pool record.
 * The original Environment still verifies it and the built-in store still owns
 * consume. Exhaustion never reuses a spent record or fabricates fresh material. */
export function registerCurrentPoolMaterialSequence(fixture: CurrentPeerClient, owner: Pick<NodeWSSClient, "registerPoolSource">,
  originalRecords: readonly string[], onAcquire?: () => void): ConnectionMaterialSource {
  if (fixture.path !== "direct" || originalRecords.length < 1 || originalRecords.length > 4) throw new Error("engineering pool sequence requires finite original direct material");
  const records = Object.freeze(originalRecords.map(raw => {
    const record = readCurrentPeerMaterial(raw);
    if (record.source !== "preauthorized_pool" || record.role !== 0 || record.profile !== fixture.material.profile || record.identity_seed !== fixture.material.identity_seed ||
        record.dh_seed !== fixture.material.dh_seed || record.tunnels.length !== 0 || JSON.stringify(record.namespaces) !== JSON.stringify(fixture.material.namespaces)) throw new Error("engineering pool sequence changes its independent installation");
    return record;
  }));
  let position = 0;
  return owner.registerPoolSource(fixture.policy, async (request, destination) => {
    if (request.signal.aborted) throw new Error("canceled");
    onAcquire?.();
    const record = records[position++]; if (record === undefined) throw new Error("original engineering pool sequence exhausted");
    const owned: Uint8Array[] = [], read = (encoded: string, limit: number) => { const bytes = peerBytes(encoded, limit); owned.push(bytes); return bytes; };
    try {
      const input = { artifact: read(record.artifact, 65536), activation: read(record.activation, 65536),
        clientCertificate: read(record.client_certificate, 16384), serverCertificate: read(record.server_certificate, 16384) };
      if (request.signal.aborted) throw new Error("canceled");
      for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) destination[name].set(input[name]);
      return { artifact: input.artifact.length, activation: input.activation.length, clientCertificate: input.clientCertificate.length, serverCertificate: input.serverCertificate.length, candidateIndex: 0 };
    } finally { for (const bytes of owned) bytes.fill(0); }
  });
}
/** Accepted engineering endpoint still owns the actual signed server Grant;
 * pool authorization is supplied by the original authority, never reconstructed
 * from a relay lookup. Its admission gate uses its own durable stores. */
export async function createCurrentPoolPeerEndpoint(raw: string, options: Readonly<{ trustPEM?: string }> = {}): Promise<CurrentPeerClient> {
  const material = readCurrentPeerMaterial(raw);
  if (material.source !== "preauthorized_pool" || material.role !== 1) throw new Error("accepted engineering endpoint requires original role 1 pool material");
  const owner = await createPeerClient(material, options);
  if (!("poolStore" in owner)) { await owner.close(); throw new Error("invalid original endpoint owner"); }
  return owner;
}
export interface CurrentRegisteredLivePeerEndpoint extends CurrentPeerOwner { readonly material: CurrentLivePeerMaterial; }
export interface CurrentRegisteredTunnelServerInstallation {
  readonly identitySeed: string; readonly noiseSeed: string; readonly relayCertificate: string;
  readonly relayAudience: string; readonly relayService: string; readonly relaySubject: string;
}
/** Trusted B installation contains registry facts and keys, never an allow or
 * a ParentWinner row. The registered authority supplies the original Grant. */
export async function createCurrentRegisteredTunnelPeerEndpoint(raw: string, installation: CurrentRegisteredTunnelServerInstallation, options: Readonly<{ trustPEM?: string }> = {}): Promise<CurrentPeerClient | CurrentRegisteredLivePeerEndpoint> {
  const registered = readCurrentPeerMaterial(raw);
  if (registered.source === "preauthorized_pool" && registered.tunnels.length !== 0 || registered.source === "live_authority" && registered.tunnels.some(tunnel => typeof tunnel.grant === "string" && tunnel.grant.length > 0)) throw new Error("server registration must precede original tunnel Grant publication");
  const material: CurrentPeerMaterial = { ...registered, role: 1, identity_seed: installation.identitySeed, dh_seed: installation.noiseSeed };
  peerBytes(material.identity_seed, 32, 32).fill(0); peerBytes(material.dh_seed, 32, 32).fill(0); peerBytes(installation.relayCertificate, 8192).fill(0);
  const owner = await createPeerClient(material, { ...options, registeredServer: installation });
  if (owner.material.source !== registered.source) { await owner.close(); throw new Error("original registered endpoint is unavailable"); } return owner;
}
async function createPeerClient(material: CurrentPeerMaterial, options: Readonly<{ trustPEM?: string; liveHTTPS?: NodeLiveHTTPSOptions; registeredLive?: CurrentRegisteredLiveClientInstallation; registeredServer?: CurrentRegisteredTunnelServerInstallation }>): Promise<CurrentPeerClient | CurrentLivePeerClient | CurrentRegisteredLivePeerEndpoint> {
  if (material.role !== 0 && material.role !== 1) throw new Error("engineering endpoint requires an original role");
  const artifactBytes = peerBytes(material.artifact, 65536), activationBytes = material.source === "preauthorized_pool" ? peerBytes(material.activation, 65536) : new Uint8Array();
  const clientBytes = peerBytes(material.client_certificate, 16384), serverBytes = peerBytes(material.server_certificate, 16384), routeBytes = peerBytes(material.route, 16384);
  const artifact = decode(artifactBytes), activation = material.source === "preauthorized_pool" ? decode(activationBytes) : undefined, client = decode(clientBytes), server = decode(serverBytes), route = decode(routeBytes);
  const tenant = text(peerField(artifact, "Artifact", "tenant_id")), audience = text(peerField(artifact, "Artifact", "audience"));
  const clientSubject = text(peerField(client, "IdentityCertificate", "subject_id")), serverSubject = text(peerField(server, "IdentityCertificate", "subject_id"));
  const issuer = data(peerField(artifact, "Artifact", "issuer_key_id")), authority = activation === undefined ? options.registeredLive?.control.authority ?? options.liveHTTPS?.authority : text(peerField(activation, "ActivationAuthorization", "authority_id"));
  const contract = peerField(artifact, "Artifact", "session_contract"), profile = uint(peerField(contract, "SessionContract", "application_profile"));
  if (profile !== 0n && profile !== 1n) throw new Error("engineering fixture requires transport or services");
  const pathKind = uint(peerField(route, "Route", "path_kind")); if (pathKind !== 0n && pathKind !== 1n) throw new Error("invalid engineering path");
  const candidates = peerField(artifact, "Artifact", "candidates"); if (candidates.kind !== "array") throw new Error("invalid engineering candidate set");
  const candidateID = data(peerField(route, "Route", "candidate_id"));
  const selected = candidates.value.map((candidate, index) => ({ candidate, index })).filter(({ candidate }) => Buffer.from(data(peerField(candidate, "Candidate", "candidate_id"))).equals(Buffer.from(candidateID)));
  if (selected.length !== 1) throw new Error("engineering route does not select one original candidate"); const candidateIndex = selected[0]!.index;
  if (activation !== undefined) {
    const poolSelection = peerField(activation, "ActivationAuthorization", "candidate_selection");
    if (poolSelection.kind !== "map") throw new Error("engineering pool activation lacks its original signed candidate set");
    const indices = peerField(poolSelection, "PoolSelectionRef", "candidate_indices");
    if (indices.kind !== "array" || !indices.value.some(value => value.kind === "uint" && value.value === BigInt(candidateIndex))) throw new Error("engineering route is outside its original signed candidate set");
  }
  const selectedTunnels = material.tunnels.filter(tunnel => tunnel.candidate_index === candidateIndex && tunnel.role === material.role);
  const requiresPendingOrIssuedTunnel = options.registeredServer === undefined || material.source === "live_authority";
  if (selectedTunnels.length !== (pathKind === 1n && requiresPendingOrIssuedTunnel ? 1 : 0)) throw new Error("engineering tunnel material does not match the original candidate");
  const tunnel = selectedTunnels[0], tunnelGrant = tunnel === undefined || material.source === "live_authority" ? new Uint8Array() : peerBytes(tunnel.grant!, 65536), relayCertificate = options.registeredServer !== undefined ? peerBytes(options.registeredServer.relayCertificate, 8192) : tunnel === undefined ? new Uint8Array() : peerBytes(tunnel.relay_certificate, 16384);
  const grant = tunnelGrant.length === 0 ? undefined : decode(tunnelGrant), relay = tunnel === undefined ? undefined : decode(relayCertificate);
  const pending = tunnel?.live_grant;
  if (options.registeredServer !== undefined && material.source === "live_authority" && (pending === undefined || pending.audience !== options.registeredServer.relayAudience || pending.service !== options.registeredServer.relayService || tunnel!.relay_certificate !== options.registeredServer.relayCertificate)) throw new Error("registered live B scope differs from its independent relay installation");
  const liveGrant = pending === undefined ? undefined : Object.freeze({ authority: pending.authority, issuerKeyID: peerBytes(pending.issuer_key_id, 16, 16), revocationPolicyID: pending.revocation_policy_id, revocationPolicyRevision: BigInt(pending.revocation_policy_revision), maxNotAfterMS: BigInt(pending.max_not_after_ms) });
  const tunnelPolicy: V4CredentialPolicy["tunnel"] = options.registeredServer !== undefined ? Object.freeze({ role: 1, audience: options.registeredServer.relayAudience, service: options.registeredServer.relayService, relaySubject: options.registeredServer.relaySubject, ...(liveGrant === undefined ? {} : { liveGrant }) }) : relay === undefined ? undefined : grant !== undefined ? Object.freeze({ role: material.role, audience: text(peerField(grant, "Grant", "audience")), service: text(peerField(grant, "Grant", "service")), relaySubject: text(peerField(relay, "IdentityCertificate", "subject_id")) }) : pending === undefined ? undefined : Object.freeze({ role: material.role, audience: pending.audience, service: pending.service, relaySubject: text(peerField(relay, "IdentityCertificate", "subject_id")),
    liveGrant: liveGrant! });
  const leg = peerField(route, "Route", pathKind === 0n ? "direct_leg" : material.role === 0 ? "client_leg" : "server_leg"), access = uint(peerField(leg, "Leg", "access_class"));
  const carrier = uint(peerField(leg, "Leg", "carrier"));
  if (carrier !== 0n && carrier !== 1n && carrier !== 2n) throw new Error("unknown engineering carrier");
  const carrierKind = carrier === 0n ? "raw-quic" as const : carrier === 1n ? "websocket" as const : "webtransport" as const;
  const host = text(peerField(leg, "Leg", "host")), port = uint(peerField(leg, "Leg", "port")), path = text(peerField(leg, "Leg", "path"));
  const endpoint = `${carrier === 0n ? "quic" : carrier === 2n ? "https" : access === 1n ? "ws" : "wss"}://${host.includes(":") ? `[${host}]` : host}:${port}${path}`;
  const routeDigest = peerBytes(material.route_digest, 32, 32);
  if (!Buffer.from(credentialDigest("route_digest", routeBytes)).equals(Buffer.from(routeDigest))) throw new Error("engineering route digest mismatch");
  if (material.relay_deployment !== undefined) {
    const deployment = material.relay_deployment;
    if (pathKind !== 1n || !Array.isArray(deployment.RouteDigest) || deployment.RouteDigest.length !== 32 || !deployment.RouteDigest.every(byte => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255) || !Buffer.from(deployment.RouteDigest).equals(Buffer.from(routeDigest)) || typeof deployment.Profile !== "string" || deployment.Profile.length === 0 || deployment.Profile.length > 128) throw new Error("engineering relay deployment does not bind its original route");
  }
  if (material.source === "live_authority" && options.registeredServer === undefined) {
    const installed = options.registeredLive ?? options.liveHTTPS;
    const endpoint = options.registeredLive?.control.endpoint ?? options.liveHTTPS?.baseURL;
    if (installed === undefined || endpoint !== material.live_control_base_url || installed.tenant !== tenant || installed.audience !== audience ||
        options.registeredLive !== undefined && (options.liveHTTPS !== undefined || pathKind !== 1n))
      throw new Error("live material requires independently configured matching control origin and application binding");
  }
  const rootLimit = new ResourceVector([512n << 20n, 128n << 20n, 64n << 20n, 5000000n, 5000000n, 5000n, 5000n, 5000n, 5000n, 5000n, 5000n]);
  const root = new ResourceRoot({ profileRevision: "1".repeat(64), limit: rootLimit, accounts: 2048, reservations: 4096, references: 8192,
    rootRuntimeBytes: 128n, accountRuntimeBytes: 128n, reservationRuntimeBytes: 128n, referenceRuntimeBytes: 128n });
  const beginning = performance.now(), now = BigInt(Date.now());
  const environment = createTransportEnvironment({ root, limit: rootLimit, tenantLimit: rootLimit, tenantID: "1".repeat(32), environmentID: randomBytes(16).toString("hex"),
    runtimeBytes: 1024n, namespaces: material.namespaces.length, sources: 1, acquisitions: 1, materials: material.role === 0 ? 1 : 4, sessions: material.role === 0 ? 1 : 4, dependencies: material.role === 0 ? 8 : 24, acquireMS: 10000n, cleanupMS: 10000,
    random: output => { crypto.getRandomValues(output); },
    clock: { profile: { rate: new ClockRate(100n, 1000000n, 1n), maxWidthMS: 200n, maxAgeMS: 60000n, maxRoundTripMS: 10000n },
      tick: () => ({ milliseconds: BigInt(Math.floor(performance.now() - beginning)), incarnation: "3".repeat(32) }), initial: () => ({ lowerMS: now - 50n, upperMS: now + 50n }) } });
  let directory: string | undefined, databasePath: string | undefined;
  let backing: ReturnType<typeof createSQLitePoolBacking> | undefined, poolStore: SQLitePoolStore | undefined;
  const identitySeed = peerBytes(material.identity_seed, 32, 32), dhSeed = peerBytes(material.dh_seed, 32, 32);
  try {
    for (const record of material.namespaces) {
      if (record.tenant !== tenant || !Number.isSafeInteger(record.generation) || record.generation < 1) throw new Error("invalid engineering namespace");
      const namespace = originalEnvironment(environment).namespace({ tenant: record.tenant, authority: record.authority,
        rootKeyID: peerBytes(record.root_key_id, 16, 16), rootPublicKey: peerBytes(record.root_public_key, 32, 32),
        maxTrustLifetimeMS: 30000000n, bootstrapMS: 10000n, stateBytes: 65536, stateNodes: 131072 });
      await namespace.fetchBootstrap(async (request, responseDestination, stateDestination) => {
        const raw = await bootstrapBody(environment, record.bootstrap_url,
          JSON.stringify({ tenant: record.tenant, authority: record.authority, nonce: Buffer.from(request.nonce).toString("base64") }), request.signal, options.trustPEM);
        try {
          const body = JSON.parse(new TextDecoder().decode(raw)) as { response: string; state: string };
          const signed = peerBytes(body.response, responseDestination.length), state = peerBytes(body.state, stateDestination.length);
          try { responseDestination.set(signed); stateDestination.set(state); return { responseBytes: signed.length, stateBytes: state.length }; }
          finally { signed.fill(0); state.fill(0); }
        } finally { raw.fill(0); }
      });
      if (namespace.activeVersion()[0] !== BigInt(record.generation)) throw new Error("engineering namespace generation mismatch");
    }
    const identityKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), identitySeed]), format: "der", type: "pkcs8" });
    let liveAuthority: V4LiveAuthorizationConfig | undefined;
    if (material.source === "live_authority") {
      if (options.registeredServer !== undefined) {
        // B's registered server owns receipt of the original live publication.
      } else if (options.registeredLive !== undefined) {
        liveAuthority = createRegisteredLiveTunnelClientAuthorization(environment, {
          control: { ...options.registeredLive.control, ...(options.registeredLive.relayControl === undefined ? {} : { relayControl: options.registeredLive.relayControl }), identityKey },
          material: { artifact: artifactBytes, clientCertificate: clientBytes, serverCertificate: serverBytes, relayCertificate, candidateIndex },
        });
      } else {
        if (options.liveHTTPS === undefined) throw new Error("original live control deployment is missing");
        liveAuthority = createNodeLiveHTTPS(environment, options.liveHTTPS);
      }
    } else {
      directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-ts-interop-"));
      databasePath = join(directory, "spend.sqlite");
      if (authority === undefined) throw new Error("pool authority is missing");
      backing = createSQLitePoolBacking(environment, databasePath, { maxPages: 64, maxRecords: 4, maxRecordBytes: 65536,
        runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
      poolStore = await openSQLitePoolStore(backing, { create: true, identity: { authority,
      storeID: new Uint8Array(createHash("sha256").update(peerBytes(material.generation.source, 16, 16)).digest()), generation: BigInt(material.generation.generation) },
      continuity: { check: () => undefined }, bindings: [{ tenant, issuer }] });
    }
    const noiseKey = material.profile === profileX
      ? createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), dhSeed]), format: "der", type: "pkcs8" })
      : createPrivateKey({ key: Buffer.concat([Buffer.from("30310201010420", "hex"), dhSeed, Buffer.from("a00a06082a8648ce3d030107", "hex")]), format: "der", type: "sec1" });
    const configuredStore = poolStore, configuredBacking = backing;
    let closing: Promise<void> | undefined;
    const configured = { environment, root, identityKey, noiseKey,
      policy: Object.freeze({ tenant, audience, clientSubject, serverSubject, ...(tunnelPolicy === undefined ? {} : { tunnel: tunnelPolicy }), authorities: Object.freeze(material.namespaces.map(value => value.authority)), cryptoProfiles: [material.profile] }),
      applicationProfile: profile === 0n ? "transport" as const : "services" as const, carrierKind, candidateAttempts: candidates.value.length, path: pathKind === 0n ? "direct" as const : "tunnel" as const, dialerRole: uint(peerField(leg, "Leg", "dialer_role")), listenerRole: uint(peerField(leg, "Leg", "listener_role")), clientIdentity: Buffer.from(credentialDigest("certificate_digest", clientBytes)).toString("hex"), endpoint, routeDigest,
      initiation: Object.freeze({ from: uint(peerField(artifact, "Artifact", "issued_at_ms")), until: uint(peerField(artifact, "Artifact", "initiation_not_after_ms")) }),
      serverIdentity: Buffer.from(credentialDigest("certificate_digest", serverBytes)).toString("hex"),
      registerSource: (owner: Pick<NodeWSSClient, "registerPoolSource" | "registerLiveSource">) => (material.source === "preauthorized_pool" ? owner.registerPoolSource.bind(owner) : owner.registerLiveSource.bind(owner))({ tenant, audience, clientSubject, serverSubject, ...(tunnelPolicy === undefined ? {} : { tunnel: tunnelPolicy }), authorities: material.namespaces.map(value => value.authority), cryptoProfiles: [material.profile] }, async (request, destination) => {
        if (options.registeredServer !== undefined) throw new Error("server registration cannot provide endpoint activation");
        if (request.signal.aborted) throw new Error("canceled");
        const input = { artifact: artifactBytes, activation: activationBytes, clientCertificate: clientBytes, serverCertificate: serverBytes, tunnelGrant, relayCertificate };
        for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate", "tunnelGrant", "relayCertificate"] as const) destination[name].set(input[name]);
        return { artifact: artifactBytes.length, activation: activationBytes.length, clientCertificate: clientBytes.length, serverCertificate: serverBytes.length, tunnelGrant: tunnelGrant.length, relayCertificate: relayCertificate.length, candidateIndex };
      }),
      close: () => closing ??= (async () => {
        await environment.close(); configuredStore?.close(); await configuredStore?.waitCleanup(); await environment.waitCleanup();
        if (directory !== undefined) rmSync(directory, { recursive: true, force: true }); configuredBacking?.releaseRemoved();
        for (const bytes of [artifactBytes, activationBytes, clientBytes, serverBytes, routeBytes, routeDigest, tunnelGrant, relayCertificate]) bytes.fill(0); tunnelPolicy?.liveGrant?.issuerKeyID.fill(0); root.close();
      })(),
    };
    if (material.source === "live_authority") {
      if (options.registeredServer !== undefined) return Object.freeze({ ...configured, material });
      if (liveAuthority === undefined) throw new Error("original live owner is unavailable");
      return Object.freeze({ ...configured, material, liveAuthority });
    }
    if (configuredStore === undefined || databasePath === undefined) throw new Error("original pool owner is unavailable");
    const spendPath = databasePath;
    return Object.freeze({ ...configured, material, poolStore: configuredStore,
      spentCount: () => {
        // Call only after the original spend receipt. The store retains its
        // EXCLUSIVE WAL owner, so inspect a bounded engineering snapshot rather
        // than opening a competing connection to the live authority. Automatic
        // checkpointing is disabled by the original store while it is open.
        const snapshot = mkdtempSync(join(dirname(spendPath), "inspection-"));
        let db: DatabaseSync | undefined;
        try {
          const path = join(snapshot, "spend.sqlite");
          copyFileSync(spendPath, path);
          if (existsSync(`${spendPath}-wal`)) copyFileSync(`${spendPath}-wal`, `${path}-wal`);
          db = new DatabaseSync(path, { readOnly: true });
          return Number(db.prepare("SELECT count(*) AS count FROM spend").get()!.count);
        } finally { db?.close(); rmSync(snapshot, { recursive: true, force: true }); }
      },
    });
  } catch (error) {
    await environment.close(); poolStore?.close(); await poolStore?.waitCleanup();
    await environment.waitCleanup(); if (directory !== undefined) rmSync(directory, { recursive: true, force: true }); backing?.releaseRemoved();
    for (const bytes of [artifactBytes, activationBytes, clientBytes, serverBytes, routeBytes, routeDigest, tunnelGrant, relayCertificate]) bytes.fill(0); tunnelPolicy?.liveGrant?.issuerKeyID.fill(0); root.close(); throw error;
  } finally { identitySeed.fill(0); dhSeed.fill(0); }
}
export function configureCurrentPeerWSS(fixture: CurrentPeerClient | CurrentLivePeerClient, origin: string, trustPEM?: string, handlerPlan?: HandlerPlan, listenerTLS?: Readonly<{ certificatePEM: string; privateKeyPEM: string; onPrepared?: (address: Readonly<{ host: string; port: number }>) => void }>, poolServerAllow?: PoolServerAllowConfiguration): NodeWSSClient {
  if (fixture.carrierKind !== "websocket") throw new Error("signed engineering route requires a different carrier");
  const listener = currentPeerListener(fixture, listenerTLS);
  return configureNodeWSS(fixture.environment, { ...(listener === undefined ? {} : { tunnelListener: { ...listener, tls: { certificate: listenerTLS!.certificatePEM, privateKey: listenerTLS!.privateKeyPEM } } }), identityKey: fixture.identityKey, noiseKey: fixture.noiseKey,
    ...("poolStore" in fixture ? { poolStore: fixture.poolStore, ...(poolServerAllow === undefined ? {} : { poolServerAllow }) } : { liveAuthority: fixture.liveAuthority }),
    limits: peerLimits, carrier: { remoteAddress: "127.0.0.1", origin, ...(trustPEM === undefined ? {} : { ca: [trustPEM] }),
      queueMessages: 8, runtimeBytes: 1024n, nativeBytes: 1048576n, prepareBytes: 131072 }, ...(handlerPlan === undefined ? fixture.applicationProfile === "services" ? { services: peerServices } : {} : { handlerPlan }) });
}
/** The native adapter still verifies its own independently signed route and
 * actual TLS evidence; no WSS descriptor is translated into a QUIC route. */
export function configureCurrentPeerRawQUIC(fixture: CurrentPeerClient | CurrentLivePeerClient, trustPEM: string, handlerPlan?: HandlerPlan, listenerTLS?: Readonly<{ certificatePEM: string; privateKeyPEM: string; onPrepared?: (address: Readonly<{ host: string; port: number }>) => void }>, poolServerAllow?: PoolServerAllowConfiguration): NodeWSSClient {
  if (fixture.carrierKind !== "raw-quic" || trustPEM.length > 1048576) throw new Error("invalid raw engineering carrier");
  const roots = [...trustPEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)]
    .map(match => new Uint8Array(new X509Certificate(match[0]).raw));
  if (roots.length < 1 || roots.length > 64) throw new Error("invalid raw engineering trust roots");
  const listener = currentPeerListener(fixture, listenerTLS);
  const listenerDER = listener === undefined ? undefined : { certificateChainDER: [...listenerTLS!.certificatePEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(match => new Uint8Array(new X509Certificate(match[0]).raw)), privateKeyDER: new Uint8Array(createPrivateKey(listenerTLS!.privateKeyPEM).export({ format: "der", type: "pkcs8" })) };
  try { return configureNodeRawQUIC(fixture.environment, { ...(listener === undefined ? {} : { tunnelListener: { ...listener, tls: listenerDER! } }), identityKey: fixture.identityKey, noiseKey: fixture.noiseKey,
    ...("poolStore" in fixture ? { poolStore: fixture.poolStore, ...(poolServerAllow === undefined ? {} : { poolServerAllow }) } : { liveAuthority: fixture.liveAuthority }),
    // The engineering source contains this finite original candidate set.
    // Reserve only its possible attempts before acquisition.
    limits: peerLimits, candidateAttemptLimit: fixture.candidateAttempts, carrier: { applicationStreams: peerRawQUICCapacity, streamBufferBytes: 65544, runtimeBytes: 1024n,
      providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n, trustRootsDER: roots },
    ...(handlerPlan === undefined ? fixture.applicationProfile === "services" ? { services: peerServices } : {} : { handlerPlan }) }); } finally { for (const bytes of listenerDER?.certificateChainDER ?? []) bytes.fill(0); listenerDER?.privateKeyDER.fill(0); for (const bytes of roots) bytes.fill(0); }
}
function currentPeerListener(fixture: CurrentPeerClient | CurrentLivePeerClient, tls?: Readonly<{ certificatePEM: string; privateKeyPEM: string; onPrepared?: (address: Readonly<{ host: string; port: number }>) => void }>) {
  if (fixture.listenerRole !== 0n) return undefined;
  if (fixture.path !== "tunnel" || fixture.dialerRole !== 2n || tls === undefined || typeof tls.certificatePEM !== "string" || typeof tls.privateKeyPEM !== "string") throw new Error("physical A listener requires its original trusted TLS installation");
  const url = new URL(fixture.endpoint); if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.port === "") throw new Error("physical A listener is outside its engineering installation");
  return Object.freeze({ host: "127.0.0.1", serverName: url.hostname, port: Number(url.port), ...(tls.onPrepared === undefined ? {} : { onPrepared: tls.onPrepared }) });
}
export interface CurrentPoolClientInstallation {
  readonly wire_revision: 4; readonly tenant: string; readonly audience: string;
  readonly server_allow: Omit<NodePoolServerAllowOptions, "workMS"> & { readonly workMS: string };
}
export function installCurrentPoolServerAllow(fixture: CurrentPeerClient | CurrentLivePeerClient,
  installation: CurrentPoolClientInstallation | undefined, binding: PoolServerAllowBinding | undefined): ReturnType<typeof createNodePoolServerAllow> {
  const installed = installation?.server_allow;
  if (fixture.material.source !== "preauthorized_pool" || fixture.path !== "tunnel" || installation?.wire_revision !== 4 ||
    installation.tenant !== fixture.policy.tenant || installation.audience !== fixture.policy.audience || installed === undefined ||
    binding === undefined || binding.endpoint !== installed.endpoint || typeof installed.workMS !== "string" || !/^[1-9][0-9]{0,3}$/u.test(installed.workMS) ||
    BigInt(installed.workMS) > 2000n || "clientCertificateDER" in installed) throw new Error("pool A requires its independently installed server Allow endpoint and original B binding");
  const owned: Uint8Array[] = [], copy = (value: string, maximum: number, exact?: number): Uint8Array => { const bytes = peerBytes(value, maximum, exact); owned.push(bytes); return bytes; };
  try {
    const recipients = fixture.material.tunnels.filter(value => value.role === 1).map(value => ({ candidateIndex: value.candidate_index,
      grant: copy(value.grant!, 65536), recipient: copy(binding.recipient, 16, 16), incarnation: copy(binding.incarnation, 16, 16) }));
    return createNodePoolServerAllow(fixture.environment, { ...installed, workMS: BigInt(installed.workMS) }, recipients);
  } finally { for (const bytes of owned) bytes.fill(0); }
}
export async function connectCurrentPeerWSS(fixture: CurrentPeerClient, origin: string, trustPEM?: string): Promise<Session> {
  const owner = configureCurrentPeerWSS(fixture, origin, trustPEM);
  return connect(fixture.environment, fixture.registerSource(owner), { ...peerRequirements, application_profile: fixture.applicationProfile });
}
export async function callCurrentPeerRPC(fixture: CurrentPeerClient, session: Session, payload: unknown): Promise<unknown> {
  const service = await session.bindService(peerPingService, { target: { authority: fixture.policy.authorities[0]!, tenant: fixture.policy.tenant,
    audience: fixture.policy.audience, localSubject: fixture.policy.clientSubject, peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }] }, maximumOfferWindowMS: 10000n });
  try {
    const response = await service.call(peerPingMethod, peerJSONBytes(payload), { responseLimitBytes: 4096 });
    if (response.kind !== "value" || response.encoding !== "typed") throw new Error("engineering ping did not return a value");
    try { return peerJSONValue(response.value); } finally { response.release(); }
  } finally { service.close(); }
}

export function pingCurrentPeer(fixture: CurrentPeerClient, session: Session, message: string): Promise<unknown> {
  return callCurrentPeerRPC(fixture, session, { message });
}
