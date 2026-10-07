import { p256 } from "@noble/curves/nist.js";
import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createHandlerPlan, createSQLitePoolBacking, openSQLiteAdmissionStore,
  type HandlerPlan, type SQLiteAdmissionStore, type SQLitePoolBacking, type Stream,
} from "../node/index.js";
import { credentialDigest } from "../v4/runtime/credentialSupport.js";
import { Reference, type Value } from "../v4/testSupport/cbor.js";
import { createCurrentRelayPeer, type CurrentRelayPeerDeployment } from "./currentRelayPeer.js";
import { peerBytes, peerField, peerLimits, peerRawQUICCapacity, peerServices, readCurrentPeerMaterial, type CurrentPoolClientInstallation } from "./currentPeer.js";
import type { NodePoolServerAllowReceiverOptions } from "../node/poolServerAllow.js";

interface CurrentNativeTunnelInstallation {
  readonly schema_version: 1;
  readonly deployment: CurrentRelayPeerDeployment;
  readonly origin: string;
  readonly trustPEM: string;
  readonly certificatePEM: string;
  readonly privateKeyPEM: string;
  readonly serverListenerTLS: Readonly<{ certificatePEM: string; privateKeyPEM: string }>;
  readonly clientListenerTLS: Readonly<{ certificatePEM: string; privateKeyPEM: string }>;
  readonly server_allow: Omit<NodePoolServerAllowReceiverOptions, "clientCertificateDER" | "workMS"> & Readonly<{ clientCertificateDER: string; workMS: string }>;
  readonly pool_client_deployment: CurrentPoolClientInstallation;
}
const complete = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
const decode = (raw: Uint8Array): Value => {
  const result = new Reference().decode(raw, "", {}, 270336n);
  if (!result.ok) throw new Error("invalid original native tunnel registration");
  return result.value;
};
const uint = (value: Value): bigint => { if (value.kind !== "uint") throw new Error("invalid native tunnel role"); return value.value; };
const text = (value: Value): string => { if (value.kind !== "text") throw new Error("invalid native tunnel endpoint"); return value.value; };

/** Consumes an independently installed original relay/authority deployment.
 * The original registered pool authority prepares B, issues both Grants and
 * records ParentWinner before any application Session can be published. */
export async function createCurrentNativeTunnel(kind: string, handle: (stream: Stream, signal: AbortSignal) => Promise<void>, installationPath = process.env.FLOWERSEC_NATIVE_TUNNEL_INSTALLATION) {
  if (installationPath === undefined || !isAbsolute(installationPath)) throw new Error("FLOWERSEC_NATIVE_TUNNEL_INSTALLATION must name an absolute independently installed deployment");
  const raw = readFileSync(installationPath);
  if (raw.length > 4194304) throw new Error("native tunnel installation exceeds its bound");
  const installation = JSON.parse(raw.toString("utf8")) as CurrentNativeTunnelInstallation;
  if (installation.schema_version !== 1 || installation.deployment.wire_revision !== 4 || typeof installation.origin !== "string" || typeof installation.trustPEM !== "string" || typeof installation.certificatePEM !== "string" || typeof installation.privateKeyPEM !== "string" || installation.serverListenerTLS === undefined || installation.clientListenerTLS === undefined) throw new Error("incomplete independently installed native tunnel deployment");
  const registration = readCurrentPeerMaterial(installation.deployment.registration_json);
  if (registration.source !== "preauthorized_pool") throw new Error("native pool tunnel test requires its original pool installation");
  const routeBytes = peerBytes(registration.route, 16384), route = decode(routeBytes);
  const clientLeg = peerField(route, "Route", "client_leg"), serverLeg = peerField(route, "Route", "server_leg");
  const carrierValue = uint(peerField(clientLeg, "Leg", "carrier"));
  const carrier = carrierValue === 0n ? "raw-quic" as const : carrierValue === 1n ? "websocket" as const : undefined;
  if (carrier === undefined) throw new Error("native tunnel A installation declares an unsupported carrier");
  if (uint(peerField(serverLeg, "Leg", "carrier")) !== 0n) throw new Error("native tunnel B installation does not declare raw QUIC");
  const host = text(peerField(serverLeg, "Leg", "host")), port = Number(uint(peerField(serverLeg, "Leg", "port")));
  const dialer = uint(peerField(serverLeg, "Leg", "dialer_role")), listener = uint(peerField(serverLeg, "Leg", "listener_role"));
  if (!(dialer === 1n && listener === 2n || dialer === 2n && listener === 1n)) throw new Error("original native tunnel B physical roles are invalid");
  let directory: string | undefined, backing: SQLitePoolBacking | undefined, store: SQLiteAdmissionStore | undefined, plan: HandlerPlan | undefined;
  const owned: Uint8Array[] = [routeBytes];
  let cleaned = false;
  const cleanupPreparedServer = async () => {
    if (cleaned) return;
    cleaned = true;
    plan?.close(); store?.close(); await store?.waitCleanup();
    if (directory !== undefined) rmSync(directory, { recursive: true, force: true });
    backing?.releaseRemoved();
  };
  try {
    const installedAllow = installation.server_allow;
    if (installedAllow === undefined || !/^[1-9][0-9]{0,3}$/u.test(installedAllow.workMS) || BigInt(installedAllow.workMS) > 2000n) throw new Error("original native B requires its independent server Allow installation");
    const allowPin = peerBytes(installedAllow.clientCertificateDER, 65536); owned.push(allowPin);
    const relay = await createCurrentRelayPeer(installation.deployment, { carrier, serverCarrier: "raw-quic",
      origin: installation.origin, trustPEM: installation.trustPEM, certificatePEM: installation.certificatePEM,
      privateKeyPEM: installation.privateKeyPEM, serverListenerTLS: installation.serverListenerTLS, cleanupPreparedServer,
      serverAllow: { ...installedAllow, clientCertificateDER: allowPin, workMS: BigInt(installedAllow.workMS) },
      async prepareServer({ environment, parentWinnerStore, material, policy }) {
        const parent = decode(material.artifact), issuer = peerField(parent, "Artifact", "issuer_key_id");
        if (issuer.kind !== "bytes" || issuer.value.length !== 16) throw new Error("original native tunnel issuer is invalid");
        const issuerID = new Uint8Array(issuer.value), serverIdentity = credentialDigest("certificate_digest", material.serverCertificate);
        owned.push(issuerID, serverIdentity);
        directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-ts-native-tunnel-"));
        backing = createSQLitePoolBacking(environment, join(directory, "service.sqlite"), { maxPages: 128, maxRecords: 32, maxRecordBytes: 65536, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
        store = await openSQLiteAdmissionStore(backing, { create: true, identity: { authority: "service", storeID: new Uint8Array(createHash("sha256").update(directory).digest()), generation: 1n },
          continuity: { check: () => undefined }, bindings: [{ tenant: policy.tenant, issuer: issuerID, audience: policy.audience, serverIdentity }], parentWinnerStore });
        plan = createHandlerPlan(environment, { applicationBytes: 16384n, services: { ...peerServices, profile: "services" }, streams: [{ kind, authorize: () => true,
          handler: (stream, context) => handle(stream, context.signal), options: { workClass: "resident", applicationBytes: 16384n, maxConcurrentStreams: 2, maxAuthorizing: 2, applicationTimeoutMS: 10000n } }] });
        const handlers = plan;
        const seed = peerBytes(installation.deployment.server_identity_seed, 32, 32), dhSeed = peerBytes(installation.deployment.server_dh_seed, 32, 32);
        const key = (bytes: Uint8Array, noise = false) => createPrivateKey({ key: Buffer.concat([Buffer.from(noise ? "302e020100300506032b656e04220420" : "302e020100300506032b657004220420", "hex"), bytes]), format: "der", type: "pkcs8" });
        const identityKey = key(seed);
        let noiseKey: ReturnType<typeof createPrivateKey>;
        try {
          if (registration.profile === "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1") noiseKey = key(dhSeed, true);
          else if (registration.profile === "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1") {
            const publicKey = p256.getPublicKey(dhSeed, false);
            try { noiseKey = createPrivateKey({ key: { kty: "EC", crv: "P-256", x: Buffer.from(publicKey.subarray(1,33)).toString("base64url"), y: Buffer.from(publicKey.subarray(33)).toString("base64url"), d: Buffer.from(dhSeed).toString("base64url") }, format: "jwk" }); }
            finally { publicKey.fill(0); }
          } else throw new Error("unsupported original native tunnel crypto profile");
        } finally { seed.fill(0); dhSeed.fill(0); }
        const roots = [...installation.trustPEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(match => new Uint8Array(new X509Certificate(match[0]).raw));
        if (roots.length < 1 || roots.length > 64) throw new Error("original native tunnel trust roots are missing"); owned.push(...roots);
        const carrier = { applicationStreams: peerRawQUICCapacity, streamBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n, trustRootsDER: roots };
        const common = { serverName: host, port, path: "tunnel" as const, identityKey, noiseKey, admissionStore: store, limits: peerLimits,
          ingress: { positions: 4, callbackBytes: 16384n, handshakeMS: 10000n, drainMS: 10000n, cleanupMS: 10000n }, carrier };
        const tls = { certificateChainDER: [...installation.serverListenerTLS.certificatePEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(match => new Uint8Array(new X509Certificate(match[0]).raw)),
          privateKeyDER: new Uint8Array(createPrivateKey(installation.serverListenerTLS.privateKeyPEM).export({ format: "der", type: "pkcs8" })) };
        owned.push(...tls.certificateChainDER, tls.privateKeyDER);
        return { policy, listener: dialer === 1n ? { ...common, physicalDirection: "dialer" as const, carrierKind: "raw_quic" as const } : { ...common, host: "127.0.0.1", carrierKind: "raw_quic" as const, tls },
          maxPendingSessions: 1, maxPendingAccepts: 1, cleanupMS: 10000n, authorizeRequest: () => ({ allowed: true }), resolveHandlers: () => handlers,
          authorizeApplication: (_context, supplied) => ({ decision: "authorized", handlers: supplied, lease: { close: () => undefined, waitCleanup: async () => complete } }), release: () => complete };
      } });
    const acceptor = "serverAcceptor" in relay ? relay.serverAcceptor : undefined;
    if (acceptor === undefined) { await relay.close(); throw new Error("original registered native B Acceptor is unavailable"); }
    const binding = "serverAllow" in relay ? relay.serverAllow : undefined;
    if (binding === null || typeof binding !== "object" || !("endpoint" in binding) || typeof binding.endpoint !== "string" ||
      !("recipient" in binding) || typeof binding.recipient !== "string" || !("incarnation" in binding) || typeof binding.incarnation !== "string") {
      await relay.close(); throw new Error("original registered native B Allow binding is unavailable");
    }
    const serverAllow = Object.freeze({ endpoint: binding.endpoint, recipient: binding.recipient, incarnation: binding.incarnation });
    let closed: Promise<void> | undefined;
    return { relay, acceptor, trustPEM: installation.trustPEM, origin: installation.origin,
      listenerTLS: installation.clientListenerTLS,
      poolClientInstallation: installation.pool_client_deployment,
      serverAllow,
      close: () => closed ??= (async () => { await relay.close(); for (const value of owned) value.fill(0); })() };
  } catch (error) { await cleanupPreparedServer(); for (const value of owned) value.fill(0); throw error; }
}
