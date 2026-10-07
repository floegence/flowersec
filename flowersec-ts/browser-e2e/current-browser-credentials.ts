import { ed25519 } from "@noble/curves/ed25519.js";
import { createV4WSSPeerFixture, type startV4WSSPeer } from "./v4-wss-peer.js";
import { credentialFixture, fill, map, bytes, text, u, array, encode } from "../src/v4/testSupport/credentials.js";
import { credentialDigest } from "../src/v4/runtime/credentialSupport.js";
import type { CurrentBrowserFixture } from "./go-webtransport-peer.js";

const profile = "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1";
const namespaces = [{ tenant: "tenant", authority: "authority", generation: 1, rootKeyID: Array.from(fill(1, 16)), rootPublicKey: Array.from(ed25519.getPublicKey(fill(7))) }];
const policy = { tenant: "tenant", audience: "service", clientSubject: "client", serverSubject: "server", authorities: ["authority"], cryptoProfiles: [profile] };
export function currentWSSBrowserFixture(peer: Awaited<ReturnType<typeof startV4WSSPeer>>): CurrentBrowserFixture {
  return { ...peer, carrier: "wss", issuer: Array.from(fill(5, 16)), serverIdentity: Array.from(credentialDigest("certificate_digest", new Uint8Array(peer.input.serverCertificate))),
    tlsMode: "ca", pins: [], services: false, spendAuthority: "spend", identitySeed: Array.from(fill(14)), noiseSeed: Array.from(fill(16)), namespaces, policy,
    bootstrap: (_index, nonce) => peer.bootstrap(Array.from(nonce)) };
}
/** Signed local credentials for constructor/deployment refusal scenarios only.
 * These scenarios never qualify TLS or native carrier interoperability. */
export function createCurrentWTPolicyFixture(origin: string, mode: "ca" | "pin", endpoint = "https://localhost/flowersec/webtransport/v4/direct") {
  const url = new URL(endpoint), owner = createV4WSSPeerFixture(origin, Number(url.port || 443), profile);
  const tls = mode === "ca" ? map({ 0: u(0), 1: { kind: "bool", value: false } }) : map({ 0: u(1), 1: { kind: "bool", value: false }, 2: u(0), 3: array(map({
    0: bytes(fill(99)), 1: u(owner.timeOrigin), 2: u(owner.timeOrigin + 50000n), 3: text("x509v3-p256-14d"),
  })) });
  const leg = map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(2), 6: text(url.hostname), 7: u(Number(url.port || 443)), 8: text(url.pathname),
    9: text("h3"), 10: text(""), 11: tls, 12: map({ 0: array(text(origin)), 1: { kind: "bool", value: false } }) });
  const material = credentialFixture(owner.env.owner.resources, owner.env.owner.clock, () => { throw new Error("original Environment only"); }, "preauthorized_pool", profile, owner.fixture.namespace, { timeOrigin: owner.timeOrigin, leg });
  const input = material.input();
  const fixture: CurrentBrowserFixture = { carrier: "webtransport", endpoint: url.href, timeOrigin: owner.timeOrigin.toString(), profile, route: Array.from(material.route), issuer: Array.from(fill(5, 16)),
    serverIdentity: Array.from(credentialDigest("certificate_digest", input.serverCertificate)), tlsMode: mode, pins: mode === "ca" ? [] : [Buffer.from(fill(99)).toString("base64url")], services: false, spendAuthority: "spend",
    identitySeed: Array.from(fill(14)), noiseSeed: Array.from(fill(16)), namespaces, policy,
    input: { artifact: Array.from(input.artifact), activation: Array.from(input.activation), clientCertificate: Array.from(input.clientCertificate), serverCertificate: Array.from(input.serverCertificate), candidateIndex: 0 },
    bootstrap: (_index, nonce) => ({ response: Array.from(material.response(new Uint8Array(nonce))), state: Array.from(encode(material.state)) }) };
  for (const name of ["artifact", "activation", "clientCertificate", "serverCertificate"] as const) input[name].fill(0);
  return { ...fixture, close: async () => { await owner.env.publicOwner.close(); await owner.env.publicOwner.waitCleanup(); } };
}
