import { createHash, createPrivateKey, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRegisteredPoolTunnelServer, createRegisteredLiveTunnelServer, createSQLitePoolBacking, type RegisteredTunnelServer, type RegisteredPoolTunnelServerOptions, type RegisteredTunnelControlClientOptions, type HandlerPlan, type SQLitePoolBacking } from "../node/index.js";
import { createCurrentRegisteredTunnelPeerEndpoint, peerBytes, peerField, peerLimits, peerRawQUICCapacity, type CurrentRegisteredTunnelServerInstallation } from "./currentPeer.js";
import { Reference } from "../v4/testSupport/cbor.js";
import type { NodePoolServerAllowReceiverOptions } from "../node/poolServerAllow.js";

export interface CurrentRegisteredTunnelPeerDeployment extends CurrentRegisteredTunnelServerInstallation {
  readonly wire_revision: 4; readonly registration_json: string;
  readonly control: Omit<RegisteredTunnelControlClientOptions, "identityKey" | "workMS" | "relayControl"> & Readonly<{ workMS: string }>;
  readonly relay_control?: Omit<NonNullable<RegisteredTunnelControlClientOptions["relayControl"]>, "workMS"> & Readonly<{ workMS: string }>;
  readonly trustPEM: string; readonly origin: string;
  readonly certificatePEM: string; readonly privateKeyPEM: string;
  readonly server_allow?: Omit<NodePoolServerAllowReceiverOptions, "clientCertificateDER" | "workMS"> & { readonly clientCertificateDER: string; readonly workMS: string };
}
const cleaned = Object.freeze({ status: "complete" as const, core_cleanup: "complete" as const, pending_callbacks: 0n });
/** Only registry/bootstrap input is used during setup. B's actual native
 * Prepare, original allow transfer and remote winner match use ordinary APIs. */
export async function createCurrentRegisteredTunnelPeerServer(deployment: CurrentRegisteredTunnelPeerDeployment, buildPlan: (environment: Awaited<ReturnType<typeof createCurrentRegisteredTunnelPeerEndpoint>>["environment"]) => HandlerPlan,
  options: Readonly<{ carrier: "websocket" | "raw-quic"; origin: string; trustPEM: string }>) {
  if (deployment.wire_revision !== 4 || typeof deployment.control.workMS !== "string" || !/^[1-9][0-9]{0,4}$/u.test(deployment.control.workMS) || BigInt(deployment.control.workMS) > 60000n) throw new Error("invalid current B deployment");
  const relay = deployment.relay_control;
  if (relay !== undefined && (relay === null || typeof relay !== "object" || typeof relay.workMS !== "string" || !/^[1-9][0-9]{0,4}$/u.test(relay.workMS) || BigInt(relay.workMS) > 60000n)) throw new Error("invalid independent B relay control installation");
  const relayControl = relay === undefined ? undefined : { ...relay, workMS: BigInt(relay.workMS) };
  const endpoint = await createCurrentRegisteredTunnelPeerEndpoint(deployment.registration_json, deployment, { trustPEM: options.trustPEM });
  let directory: string | undefined, backing: SQLitePoolBacking | undefined, server: RegisteredTunnelServer | undefined, plan: HandlerPlan | undefined, closing: Promise<void> | undefined;
  const owned: Uint8Array[] = [];
  const close = (): Promise<void> => closing ??= (async () => { await server?.close(); plan?.close(); if (directory !== undefined) rmSync(directory, { recursive: true, force: true }); backing?.releaseRemoved(); for (const value of owned) value.fill(0); await endpoint.close(); })();
  try {
    if (endpoint.path !== "tunnel" || endpoint.carrierKind !== options.carrier || endpoint.applicationProfile !== "services" || endpoint.policy.tunnel?.role !== 1) throw new Error("current B installation differs from its signed registry");
    const url = new URL(endpoint.endpoint); if (!["localhost", "127.0.0.1"].includes(url.hostname) || url.port === "") throw new Error("current B endpoint is outside its engineering deployment");
    const material = endpoint.material, input = { source: material.source, candidateIndex: -1, artifact: peerBytes(material.artifact, 65536), activation: material.source === "preauthorized_pool" ? peerBytes(material.activation, 4096) : new Uint8Array(), clientCertificate: peerBytes(material.client_certificate, 8192), serverCertificate: peerBytes(material.server_certificate, 8192), relayCertificate: peerBytes(deployment.relayCertificate, 8192) }; owned.push(...Object.values(input).filter((value): value is Uint8Array => value instanceof Uint8Array));
    const routeBytes = peerBytes(material.route, 16384); owned.push(routeBytes);
    const reference = new Reference(), parent = reference.decode(input.artifact, "", {}, 270336n), route = reference.decode(routeBytes, "", {}, 270336n);
    if (!parent.ok || !route.ok) throw new Error("invalid registered current route");
    const candidateID = peerField(route.value, "Route", "candidate_id"), candidates = peerField(parent.value, "Artifact", "candidates");
    if (candidateID.kind !== "bytes" || candidates.kind !== "array") throw new Error("invalid registered current candidate");
    input.candidateIndex = candidates.value.findIndex(value => { const id = peerField(value, "Candidate", "candidate_id"); return id.kind === "bytes" && Buffer.from(id.value).equals(Buffer.from(candidateID.value)); });
    if (input.candidateIndex < 0) throw new Error("registered current candidate is missing");
    const issuer = peerField(parent.value, "Artifact", "issuer_key_id"); if (issuer.kind !== "bytes" || issuer.value.length !== 16) throw new Error("registered current issuer is invalid");
    const issuerBytes = new Uint8Array(issuer.value), serverIdentity = new Uint8Array(Buffer.from(endpoint.serverIdentity, "hex")); owned.push(issuerBytes, serverIdentity);
    directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-ts-registered-tunnel-"));
    backing = createSQLitePoolBacking(endpoint.environment, join(directory, "service.sqlite"), { maxPages: 128, maxRecords: 32, maxRecordBytes: 65536, runtimeBytes: 1024n, providerRuntimeBytes: 1024n, diskOverheadBytes: 4096n });
    plan = buildPlan(endpoint.environment); const handlers = plan;
    const common = { serverName: url.hostname, port: Number(url.port), path: "tunnel" as const, identityKey: endpoint.identityKey, noiseKey: endpoint.noiseKey, limits: peerLimits, ingress: { positions: 4, callbackBytes: 16384n, handshakeMS: 10000n, drainMS: 10000n, cleanupMS: 10000n } };
    const dialer = endpoint.dialerRole === 1n && endpoint.listenerRole === 2n;
    if (!dialer && !(endpoint.dialerRole === 2n && endpoint.listenerRole === 1n)) throw new Error("registered current B leg has invalid physical direction");
    const native = { applicationStreams: peerRawQUICCapacity, streamBufferBytes: 65544, runtimeBytes: 1024n, providerRuntimeBytes: 1048576n, providerStreamBytes: 65536n, trustRootsDER: [...options.trustPEM.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/gu)].map(match => new Uint8Array(new X509Certificate(match[0]).raw)) };
    if (native.trustRootsDER.length < 1 || native.trustRootsDER.length > 64) throw new Error("registered B requires its bounded original native trust installation");
    owned.push(...native.trustRootsDER);
    const wss = { remoteAddress: "127.0.0.1", origin: options.origin, ca: [options.trustPEM], queueMessages: 8, nativeBytes: 1048576n, prepareBytes: 262144, runtimeBytes: 1024n };
    let listener: RegisteredPoolTunnelServerOptions["server"]["listener"];
    if (dialer) listener = options.carrier === "raw-quic" ? { ...common, physicalDirection: "dialer" as const, carrierKind: "raw_quic", carrier: native } : { ...common, physicalDirection: "dialer" as const, carrierKind: "wss", carrier: wss };
    else if (options.carrier === "raw-quic") {
      const certificate = new Uint8Array(new X509Certificate(deployment.certificatePEM).raw), privateKey = new Uint8Array(createPrivateKey(deployment.privateKeyPEM).export({ format: "der", type: "pkcs8" })); owned.push(certificate, privateKey);
      listener = { ...common, host: "127.0.0.1", carrierKind: "raw_quic", carrier: native, tls: { certificateChainDER: [certificate], privateKeyDER: privateKey } };
    } else listener = { ...common, host: "127.0.0.1", carrier: wss, tls: { certificate: deployment.certificatePEM, privateKey: deployment.privateKeyPEM } };
    const state = new Uint8Array(createHash("sha256").update(directory + "/service").digest()); owned.push(state);
    let serverAllow: NodePoolServerAllowReceiverOptions | undefined;
    if (material.source === "preauthorized_pool") {
      const installed = deployment.server_allow;
      if (installed === undefined || typeof installed.workMS !== "string" || !/^[1-9][0-9]{0,3}$/u.test(installed.workMS) || BigInt(installed.workMS) > 2000n) throw new Error("pool B requires its independent server Allow installation");
      const pin = peerBytes(installed.clientCertificateDER, 65536); owned.push(pin); serverAllow = { ...installed, clientCertificateDER: pin, workMS: BigInt(installed.workMS) };
    }
    const serverOptions: RegisteredPoolTunnelServerOptions = { environment: endpoint.environment, material: input, policy: endpoint.policy, ...(serverAllow === undefined ? {} : { serverAllow }), control: { ...deployment.control, ...(relayControl === undefined ? {} : { relayControl }), workMS: BigInt(deployment.control.workMS), identityKey: endpoint.identityKey }, serviceBacking: backing,
      serviceStore: { create: true, identity: { authority: "service", storeID: state, generation: 1n }, continuity: { check: () => undefined }, bindings: [{ tenant: endpoint.policy.tenant, audience: endpoint.policy.audience, issuer: issuerBytes, serverIdentity }] },
      server: { listener, maxPendingSessions: 1, maxPendingAccepts: 1, cleanupMS: 10000n, authorizeRequest: context => ({ allowed: dialer || options.carrier === "raw-quic" || context.origin === options.origin }), resolveHandlers: () => handlers,
        authorizeApplication: (_context, supplied) => ({ decision: "authorized", handlers: supplied, lease: { close: () => undefined, waitCleanup: async () => cleaned } }), release: () => cleaned } };
    server = material.source === "live_authority" ? await createRegisteredLiveTunnelServer({ ...serverOptions, material: { artifact: input.artifact, clientCertificate: input.clientCertificate, serverCertificate: input.serverCertificate, relayCertificate: input.relayCertificate, candidateIndex: input.candidateIndex } }) : await createRegisteredPoolTunnelServer(serverOptions);
    return Object.freeze({ environment: endpoint.environment, acceptor: server.acceptor(), ...(material.source === "preauthorized_pool" ? { serverAllow: server.poolServerAllowBinding() } : {}), clientIdentity: endpoint.clientIdentity, listenerRole: endpoint.listenerRole, policy: endpoint.policy, material: endpoint.material, close });
  } catch (error) { await close(); throw error; }
}
