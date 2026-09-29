import { transportV4RecordRegistryJSON } from "../../generated/transportV4Registry.js";
import { own } from "./schemaRegistry.js";

export interface BinaryField { readonly name: string; readonly type: string; readonly const?: number; readonly max?: number }
export interface CryptoProfile {
  readonly dh_public_bytes: number;
  readonly handshake_message_bytes: number;
  readonly dh_algorithm: number;
  readonly record_aead: string;
  readonly key_bytes: number;
  readonly nonce_bytes: number;
  readonly tag_bytes: number;
}
interface WireRegistry {
  readonly streams: { readonly client_ordinals: number; readonly server_ordinals: number };
  readonly envelope: { readonly prefix_bytes: number; readonly layout: readonly BinaryField[] };
  readonly header: readonly BinaryField[];
  readonly nonce: readonly BinaryField[];
  readonly profiles: Readonly<Record<string, CryptoProfile>>;
  readonly frame_types: Readonly<Record<string, number>>;
  readonly frame_classes: Readonly<Record<string, readonly string[]>>;
  readonly resource_caps: {
    readonly max_payload_length: number;
    readonly scope_id: { readonly min: number; readonly max: string };
    readonly datagram_scope: string;
    readonly max_datagram_envelope: number;
    readonly record_replay_window_bits: number;
  };
}
function frozen<T>(value: T): T {
  if (value !== null && typeof value === "object") { for (const child of Object.values(value)) frozen(child); Object.freeze(value); }
  return value;
}
export const wire: WireRegistry = frozen(JSON.parse(transportV4RecordRegistryJSON) as WireRegistry);
export function binaryWidth(type: string): number {
  switch (type) { case "uint8": return 1; case "uint16_be": return 2; case "uint32_be": return 4; case "uint64_be": return 8; default: throw new Error("wire_registry"); }
}
export const envelopePrefixBytes = wire.envelope.prefix_bytes;
export const recordHeaderBytes = wire.header.reduce((n, f) => n + binaryWidth(f.type), 0);
export const datagramScope = BigInt(wire.resource_caps.datagram_scope);
export const maxStreamScope = BigInt(wire.resource_caps.scope_id.max);
export function ownProfile(name: string): CryptoProfile | undefined { return typeof name === "string" ? own(wire.profiles, name) : undefined; }
export function validFrameType(frame: number): boolean { return Object.values(wire.frame_types).includes(frame); }
export function inFrameClass(frame: number, name: string): boolean {
  return (own(wire.frame_classes, name) ?? []).some(type => own(wire.frame_types, type) === frame);
}
