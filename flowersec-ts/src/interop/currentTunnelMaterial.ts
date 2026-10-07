import { Reference, encode, type Value } from "../v4/testSupport/cbor.js";
import { credentialDigest } from "../v4/runtime/credentialSupport.js";
import { readCurrentPeerMaterial, peerBytes, peerField, type CurrentPeerMaterial } from "./currentPeer.js";

export type CurrentTunnelCarrier = "websocket" | "raw-quic";
export interface CurrentTunnelLeg {
  readonly carrier: CurrentTunnelCarrier;
  readonly endpointRole: 0 | 1;
  readonly dialerRole: 0 | 1 | 2;
  readonly listenerRole: 0 | 1 | 2;
  readonly host: string;
  readonly port: number;
  readonly path: string;
}
export interface CurrentTunnelAuthorization {
  readonly candidate_index: number; readonly role: 0 | 1; readonly grant: string;
  readonly endpoint_certificate: string; readonly relay_certificate: string;
  readonly grant_namespace: number; readonly endpoint_namespace: number; readonly relay_namespace: number;
}
function decode(bytes: Uint8Array): Value {
  const result = new Reference().decode(bytes, "", {}, 270336n);
  if (!result.ok) throw new Error("invalid current tunnel canonical map");
  return result.value;
}
function integer(value: Value): bigint { if (value.kind !== "uint") throw new Error("invalid current tunnel integer"); return value.value; }
function text(value: Value): string { if (value.kind !== "text") throw new Error("invalid current tunnel text"); return value.value; }
function data(value: Value): Uint8Array { if (value.kind !== "bytes") throw new Error("invalid current tunnel bytes"); return value.value; }
function equal(left: Uint8Array, right: Uint8Array): boolean { return Buffer.from(left).equals(Buffer.from(right)); }

/** Checks only the detached engineering publication. Signature, revocation,
 * durable admission and actual TLS evidence remain with the original owners. */
export function inspectCurrentTunnelMaterial(raw: string, role: 0 | 1): Readonly<{
  material: CurrentPeerMaterial; candidateIndex: number; clientLeg: CurrentTunnelLeg; serverLeg: CurrentTunnelLeg;
}> {
  const material = readCurrentPeerMaterial(raw);
  if (material.role !== role) throw new Error("current tunnel publication has the wrong original role or source");
  const owned: Uint8Array[] = [];
  const bytes = (value: string, maximum: number, exact?: number) => { const result = peerBytes(value, maximum, exact); owned.push(result); return result; };
  try {
    const descriptor = bytes(material.route, 16384), route = decode(descriptor), digest = bytes(material.route_digest, 32, 32), parent = decode(bytes(material.artifact, 65536));
    if (integer(peerField(route, "Route", "path_kind")) !== 1n || !equal(credentialDigest("route_digest", descriptor), digest)) throw new Error("current tunnel publication differs from its complete route digest");
    const candidateID = data(peerField(route, "Route", "candidate_id")), candidates = peerField(parent, "Artifact", "candidates");
    if (candidates.kind !== "array") throw new Error("current tunnel candidate set is missing");
    const selected = candidates.value.map((candidate, index) => ({ candidate, index })).filter(({ candidate }) => equal(data(peerField(candidate, "Candidate", "candidate_id")), candidateID));
    if (selected.length !== 1) throw new Error("current tunnel route does not select one original candidate");
    const candidateIndex = selected[0]!.index, candidate = selected[0]!.candidate;
    const originalRoute = encode({ kind: "map", value: [
      [{ kind: "uint", value: 0n }, { kind: "uint", value: integer(peerField(candidate, "Candidate", "path_kind")) }],
      [{ kind: "uint", value: 1n }, { kind: "bytes", value: candidateID }],
      [{ kind: "uint", value: 3n }, peerField(candidate, "Candidate", "client_leg")],
      [{ kind: "uint", value: 4n }, peerField(candidate, "Candidate", "server_leg")],
    ] }); owned.push(originalRoute);
    if (!equal(originalRoute, descriptor)) throw new Error("current publication changed its original Artifact route descriptor");
    const leg = (side: 0 | 1): CurrentTunnelLeg => {
      const source = peerField(route, "Route", side === 0 ? "client_leg" : "server_leg");
      const carrier = integer(peerField(source, "Leg", "carrier")), endpoint = integer(peerField(source, "Leg", "endpoint_role"));
      const dialer = integer(peerField(source, "Leg", "dialer_role")), listener = integer(peerField(source, "Leg", "listener_role")), port = integer(peerField(source, "Leg", "port"));
      if ((carrier !== 0n && carrier !== 1n) || endpoint !== BigInt(side) || !((dialer === BigInt(side) && listener === 2n) || (dialer === 2n && listener === BigInt(side))) || port < 1n || port > 65535n) throw new Error("current tunnel leg has invalid logical side or physical roles");
      const host = text(peerField(source, "Leg", "host")), path = text(peerField(source, "Leg", "path"));
      if (!["localhost", "127.0.0.1"].includes(host) || path !== (carrier === 1n ? "/flowersec/v4/tunnel" : "")) throw new Error("current tunnel requires its signed local listener endpoint");
      return Object.freeze({ carrier: carrier === 0n ? "raw-quic" : "websocket", endpointRole: side, dialerRole: Number(dialer) as 0 | 1 | 2, listenerRole: Number(listener) as 0 | 1 | 2, host, port: Number(port), path });
    };
    const clientLeg = leg(0), serverLeg = leg(1);
    for (const side of [0, 1] as const) {
      const selectedGrants = material.tunnels.filter(item => item.candidate_index === candidateIndex && item.role === side);
      if (selectedGrants.length !== 1) throw new Error("current tunnel publication requires both original logical sides");
      if (material.source === "live_authority") {
        if (selectedGrants[0]!.live_grant === undefined || typeof selectedGrants[0]!.grant === "string" && selectedGrants[0]!.grant!.length > 0) throw new Error("current live registry must await its original publication");
        continue;
      }
      if (typeof selectedGrants[0]!.grant !== "string") throw new Error("current pool publication requires both original Grants");
      const grant = decode(bytes(selectedGrants[0]!.grant!, 65536)), grantRoute = encode(peerField(grant, "Grant", "route_descriptor")); owned.push(grantRoute);
      const grantRoleMask = integer(peerField(peerField(grant, "Grant", "namespace"), "GrantNamespace", "role_mask"));
      if (grantRoleMask !== (4n | 1n << BigInt(side)) || !equal(data(peerField(grant, "Grant", "route_digest")), digest) || !equal(grantRoute, descriptor)) throw new Error("current tunnel Grant differs from its logical side or complete route digest");
    }
    return Object.freeze({ material, candidateIndex, clientLeg, serverLeg });
  } finally { for (const value of owned) value.fill(0); }
}

/** A view of newly issued pool bytes for the CLI acknowledgement only.
 * Live registry acknowledgement contains no authorization bytes. A runtime
 * may never restore authorization or issue ledger rows from this projection. */
export function currentTunnelAuthorizations(raw: string): readonly CurrentTunnelAuthorization[] {
  const { material, candidateIndex } = inspectCurrentTunnelMaterial(raw, 0);
  if (material.source === "live_authority") return Object.freeze([]);
  return Object.freeze(([0, 1] as const).map(role => {
    const original = material.tunnels.find(item => item.role === role && item.candidate_index === candidateIndex)!;
    return Object.freeze({ candidate_index: candidateIndex, role, grant: original.grant!,
      endpoint_certificate: role === 0 ? material.client_certificate : material.server_certificate,
      relay_certificate: original.relay_certificate, grant_namespace: original.grant_namespace,
      endpoint_namespace: 0, relay_namespace: original.relay_namespace });
  }));
}

export function requireDefaultCurrentTunnelRoute(input: ReturnType<typeof inspectCurrentTunnelMaterial>): void {
  if (input.clientLeg.dialerRole !== 0 || input.clientLeg.listenerRole !== 2 || input.serverLeg.dialerRole !== 2 || input.serverLeg.listenerRole !== 1) {
    throw new Error("current parity requires client 0-to-2 and server 2-to-1; other physical directions need their original pairing deployment");
  }
}
