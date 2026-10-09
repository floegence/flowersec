import { spawn } from "node:child_process";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { Reference, type Value } from "../src/v4/testSupport/cbor.js";
import { credentialDigest } from "../src/v4/runtime/credentialSupport.js";
import { readCurrentPeerMaterial, peerBytes, peerField } from "../src/interop/currentPeer.js";
import { signalParityProcess, stopAndJoinParityProcesses } from "../../scripts/server-parity-browser-installation.mjs";

export interface CurrentBrowserFixture {
  readonly carrier: "webtransport" | "wss";
  readonly endpoint: string; readonly timeOrigin: string; readonly profile: string;
  readonly route: readonly number[]; readonly issuer: readonly number[]; readonly serverIdentity: readonly number[];
  readonly tlsMode: "ca" | "pin"; readonly pins: readonly string[];
  readonly services: boolean; readonly spendAuthority: string;
  readonly identitySeed: readonly number[]; readonly noiseSeed: readonly number[];
  readonly namespaces: readonly Readonly<{ tenant: string; authority: string; generation: number; rootKeyID: readonly number[]; rootPublicKey: readonly number[] }>[];
  readonly policy: Readonly<{ tenant: string; audience: string; clientSubject: string; serverSubject: string; authorities: readonly string[]; cryptoProfiles: readonly string[] }>;
  readonly input: Readonly<{ artifact: readonly number[]; clientCertificate: readonly number[]; serverCertificate: readonly number[]; activation: readonly number[]; candidateIndex: number }>;
  bootstrap(index: number, nonce: readonly number[]): Promise<Readonly<{ response: readonly number[]; state: readonly number[] }>> | Readonly<{ response: readonly number[]; state: readonly number[] }>;
}
interface Ready { wire_revision: number; profile: string; source: string; trust_pem: string; origin: string; url: string; certificate_hash: string; artifact_json: string }
const syntax = new Reference();
const decode = (wire: string, maximum: number): Value => { const bytes = peerBytes(wire, maximum); try { const result = syntax.decode(bytes, "", {}, 270336n); if (!result.ok) throw new Error("invalid current browser fixture map"); return result.value; } finally { bytes.fill(0); } };
const text = (value: Value): string => { if (value.kind !== "text") throw new Error("invalid current browser fixture text"); return value.value; };
const uint = (value: Value): bigint => { if (value.kind !== "uint") throw new Error("invalid current browser fixture integer"); return value.value; };
const data = (value: Value): number[] => { if (value.kind !== "bytes") throw new Error("invalid current browser fixture bytes"); return Array.from(value.value); };
const unpack = (wire: string, maximum: number): number[] => { const bytes = peerBytes(wire, maximum); try { return Array.from(bytes); } finally { bytes.fill(0); } };
async function bootstrap(endpoint: string, trustPEM: string, tenant: string, authority: string, nonce: readonly number[], publicCAHost?: string): Promise<Readonly<{ response: number[]; state: number[] }>> {
  const url = new URL(endpoint);
  const publicCA = publicCAHost !== undefined && url.hostname === publicCAHost;
  if (!["http:", "https:"].includes(url.protocol) || (!publicCA && !["127.0.0.1", "localhost"].includes(url.hostname)) || publicCA && url.protocol !== "https:" || url.username !== "" || url.password !== "" || nonce.length !== 32) throw new Error("invalid current bootstrap endpoint");
  const body = Buffer.from(JSON.stringify({ tenant, authority, nonce: Buffer.from(nonce).toString("base64") }));
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, { method: "POST", ...(url.protocol === "https:" ? {
      minVersion: "TLSv1.3",
      ...(publicCA ? {
        // Mirror Chromium's test-host mapping while preserving SNI and public CA verification.
        family: 4, autoSelectFamily: false,
        lookup: (_hostname: string, _options: unknown, callback: (error: NodeJS.ErrnoException | null, address: string, family: number) => void) => callback(null, "127.0.0.1", 4),
      } : { ca: trustPEM }),
    } : {}), headers: { "content-type": "application/json", "content-length": body.length }, timeout: 10000 }, response => {
      if (response.statusCode !== 200) { response.resume(); reject(new Error("current bootstrap refused")); return; }
      const chunks: Buffer[] = []; let length = 0;
      response.on("data", (chunk: Buffer) => { length += chunk.length; if (length > 262144) { request.destroy(new Error("current bootstrap exceeded its bound")); return; } chunks.push(chunk); });
      response.once("error", reject); response.once("end", () => resolve(Buffer.concat(chunks, length)));
    });
    request.once("timeout", () => request.destroy(new Error("current bootstrap timed out"))); request.once("error", reject); request.end(body);
  });
  try { const value = JSON.parse(raw.toString("utf8")) as { response: string; state: string }; return { response: unpack(value.response, 65536), state: unpack(value.state, 65536) }; }
  finally { body.fill(0); raw.fill(0); }
}
/** Launches the ordinary Go current endpoint driver. Its stdout contains an
 * engineering authority installation, not an imported authorization owner. */
export async function startGoWebTransportPeer(origin: string, options: Readonly<{ publicCA?: boolean; wrongPin?: boolean; datagram?: boolean }> = {}) {
  const args = ["run", "./internal/cmd/browser-webtransport-peer", "--product-direct", "--origin", origin];
  if (options.publicCA) args.push("--public-ca"); if (options.wrongPin) args.push("--wrong-pin"); if (options.datagram) args.push("--datagram");
  const child = spawn("go", args, { cwd: fileURLToPath(new URL("../../flowersec-go/", import.meta.url)), detached: process.platform !== "win32", stdio: ["ignore", "pipe", "pipe"] });
  let diagnostics = "", settled = false;
  child.stderr.setEncoding("utf8"); child.stderr.on("data", (chunk: string) => { diagnostics = (diagnostics + chunk).slice(-32768); });
  const lines = createInterface({ input: child.stdout });
  const ended = new Promise<number | null>(resolve => child.once("close", resolve));
  const ready = new Promise<Ready>((resolve, reject) => {
    const timer = setTimeout(() => { settled = true; reject(new Error(`current Go WT driver did not publish its installation:\n${diagnostics}`)); }, 25000);
    child.once("error", error => { clearTimeout(timer); settled = true; reject(error); });
    child.once("close", code => { clearTimeout(timer); if (!settled) { settled = true; reject(new Error(`current Go WT driver exited (${code}) before its installation:\n${diagnostics}`)); } });
    lines.once("line", line => { clearTimeout(timer); if (settled) return; settled = true; try { if (line.length > 1048576) throw new Error("current Go WT installation exceeds its bound"); resolve(JSON.parse(line) as Ready); } catch (error) { reject(error); } });
  });
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> => closing ??= (async () => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      signalParityProcess(child, "SIGTERM");
      await Promise.race([ended, new Promise<void>(resolve => { timer = setTimeout(resolve, 1000); })]);
      await stopAndJoinParityProcesses([{ child, completion: ended }]);
    } finally { clearTimeout(timer); lines.close(); }
  })();
  try {
    const value = await ready, material = readCurrentPeerMaterial(value.artifact_json);
    if (value.wire_revision !== 4 || value.profile !== material.profile || value.source !== "preauthorized_pool" || material.profile !== "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" || material.source !== "preauthorized_pool" || material.role !== 0 || material.tunnels.length !== 0 || value.origin !== origin || typeof value.trust_pem !== "string" || value.trust_pem.length === 0 || value.trust_pem.length > 1048576) throw new Error("unsupported current Go WT installation");
    const endpoint = new URL(value.url); if (endpoint.protocol !== "https:" || endpoint.href !== value.url || endpoint.username !== "" || endpoint.password !== "" || endpoint.hash !== "" || endpoint.search !== "") throw new Error("invalid current Go WT endpoint");
    const publicCAHost = options.publicCA ? process.env.FLOWERSEC_BROWSER_PUBLIC_CA_HOST : undefined;
    if (options.publicCA && (publicCAHost === undefined || endpoint.hostname !== publicCAHost)) throw new Error("current Go WT endpoint differs from the configured public-CA host");
    const artifact = decode(material.artifact, 65536), activation = decode(material.activation, 4096), client = decode(material.client_certificate, 16384), server = decode(material.server_certificate, 16384), route = decode(material.route, 16384);
    const leg = peerField(route, "Route", "direct_leg"), tls = peerField(leg, "Leg", "tls_policy"), mode = uint(peerField(tls, "TLSPolicy", "mode"));
    if (uint(peerField(leg, "Leg", "carrier")) !== 2n || mode > 1n) throw new Error("current browser driver did not install WebTransport");
    const pins = mode === 0n ? [] : (() => { const values = peerField(tls, "TLSPolicy", "pins"); if (values.kind !== "array") throw new Error("invalid current WT pin set"); return values.value.map(pin => Buffer.from(data(peerField(pin, "TLSPin", "leaf_der_sha256"))).toString("base64url")); })();
    const policy = { tenant: text(peerField(artifact, "Artifact", "tenant_id")), audience: text(peerField(artifact, "Artifact", "audience")), clientSubject: text(peerField(client, "IdentityCertificate", "subject_id")), serverSubject: text(peerField(server, "IdentityCertificate", "subject_id")), authorities: material.namespaces.map(record => record.authority), cryptoProfiles: [material.profile] };
    const fixture: CurrentBrowserFixture = { carrier: "webtransport", endpoint: value.url, profile: material.profile, timeOrigin: uint(peerField(activation, "ActivationAuthorization", "issued_at_ms")).toString(),
      route: unpack(material.route_digest, 32), issuer: data(peerField(artifact, "Artifact", "issuer_key_id")), serverIdentity: Array.from(credentialDigest("certificate_digest", new Uint8Array(unpack(material.server_certificate, 16384)))),
      tlsMode: mode === 0n ? "ca" : "pin", pins, services: true, spendAuthority: text(peerField(activation, "ActivationAuthorization", "authority_id")), identitySeed: unpack(material.identity_seed, 32), noiseSeed: unpack(material.dh_seed, 32), policy,
      namespaces: material.namespaces.map(record => ({ tenant: record.tenant, authority: record.authority, generation: record.generation, rootKeyID: unpack(record.root_key_id, 16), rootPublicKey: unpack(record.root_public_key, 32) })),
      input: { artifact: unpack(material.artifact, 65536), clientCertificate: unpack(material.client_certificate, 16384), serverCertificate: unpack(material.server_certificate, 16384), activation: unpack(material.activation, 4096), candidateIndex: 0 },
      bootstrap: (index, nonce) => { const record = material.namespaces[index]; if (record === undefined) throw new Error("unknown original namespace"); return bootstrap(record.bootstrap_url, value.trust_pem, record.tenant, record.authority, nonce, publicCAHost); } };
    return { ...fixture, certificateHash: value.certificate_hash, finished: async () => { const code = await ended; if (code !== 0) throw new Error(`current Go WT driver failed (${code}):\n${diagnostics}`); }, diagnostics: () => diagnostics, close };
  } catch (error) { await close(); throw error; }
}
