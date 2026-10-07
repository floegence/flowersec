import { ResourceVector } from "./resources.js";
import { requireCredential } from "./credentialSupport.js";
import { FixedCBORWriter } from "./cborWriter.js";

export interface PoolServerAllowRecipient {
  readonly candidateIndex: number;
  readonly recipient: Uint8Array;
  readonly incarnation: Uint8Array;
  readonly grant: Uint8Array;
}
export interface TunnelServerAllowRequest {
  readonly tenant: string; readonly audience: string;
  readonly artifact: Uint8Array; readonly grant: Uint8Array; readonly relayIdentity: Uint8Array;
  readonly attempt: Uint8Array; readonly pairing: Uint8Array; readonly leg: Uint8Array;
  readonly recipient: Uint8Array; readonly incarnation: Uint8Array;
  readonly candidateIndex: number; readonly candidateID: Uint8Array; readonly routeDigest: Uint8Array;
  readonly notAfterMS: bigint;
}
/** The authenticated adapter is fixed before TxA-P. It checks the original
 * guard immediately before sending and joins physical I/O before returning.
 * No receipt, query or retry can recreate the original publication call. */
export interface PoolServerAllowConfiguration {
  readonly recipients: readonly PoolServerAllowRecipient[];
  readonly prepare: (request: TunnelServerAllowRequest, grant: Uint8Array) => PoolServerAllowPublication;
}
export interface PoolServerAllowPublication {
  publish(operation: Readonly<{ signal: AbortSignal; check(): void; remainingMS(): bigint }>): Promise<void>;
  close(): void;
}
export function poolServerAllowConfigurationCharge(input: PoolServerAllowConfiguration | undefined): ResourceVector {
  if (input === undefined) return new ResourceVector(Array<bigint>(11).fill(0n));
  requireCredential(Array.isArray(input.recipients) && input.recipients.length > 0 && input.recipients.length <= 16 && typeof input.prepare === "function", "configuration_capacity");
  const seen = new Set<number>(); let bytes = 1024n;
  for (const item of input.recipients) {
    requireCredential(Number.isSafeInteger(item.candidateIndex) && item.candidateIndex >= 0 && item.candidateIndex < 16 && !seen.has(item.candidateIndex), "configuration_capacity");
    seen.add(item.candidateIndex);
    for (const value of [item.recipient, item.incarnation]) requireCredential(value instanceof Uint8Array && value.length === 16 && value.some(byte => byte !== 0), "configuration_capacity");
    requireCredential(item.grant instanceof Uint8Array && item.grant.length > 0 && item.grant.length <= 65536, "configuration_capacity");
    bytes += BigInt(item.grant.length) + 128n;
  }
  return new ResourceVector([bytes, 0n, 0n, 1n + 4n * BigInt(input.recipients.length), 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
}
export function capturePoolServerAllowConfiguration(input: PoolServerAllowConfiguration): PoolServerAllowConfiguration {
  poolServerAllowConfigurationCharge(input);
  return Object.freeze({ recipients: Object.freeze(input.recipients.map(item => Object.freeze({ candidateIndex: item.candidateIndex,
    recipient: new Uint8Array(item.recipient), incarnation: new Uint8Array(item.incarnation), grant: new Uint8Array(item.grant) }))), prepare: input.prepare.bind(input) });
}
export function clearPoolServerAllowConfiguration(input: PoolServerAllowConfiguration | undefined): void {
  for (const item of input?.recipients ?? []) { item.grant.fill(0); item.recipient.fill(0); item.incarnation.fill(0); }
}
export interface PreparedPoolServerAllow {
  readonly request: TunnelServerAllowRequest;
  readonly grant: Uint8Array;
  check(): void;
  remainingMS(): bigint;
  close(): void;
}
export function encodeTunnelServerAllow(request: TunnelServerAllowRequest, grant: Uint8Array, output: Uint8Array): Uint8Array {
  const writer = new FixedCBORWriter(output).array(14).data(new TextEncoder().encode("tunnel-server-allow-1"), true)
    .data(new TextEncoder().encode(request.tenant), true).data(new TextEncoder().encode(request.audience), true);
  for (const value of [request.artifact, request.grant, request.relayIdentity, request.attempt, request.pairing, request.leg, request.recipient, request.incarnation]) writer.data(value);
  return writer.array(3).uint(request.candidateIndex).data(request.candidateID).data(request.routeDigest).uint(request.notAfterMS).data(grant).result();
}
