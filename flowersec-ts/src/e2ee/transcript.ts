import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, u16be, u32be } from "../utils/bin.js";

// TranscriptInputs contains the canonical fields hashed into the transcript.
export type TranscriptInputs = Readonly<{
  /** Protocol version byte used in the transcript. */
  version: number;
  /** Numeric suite identifier (see e2ee suite). */
  suite: number;
  /** Role byte (client=1, server=2). */
  role: number;
  /** Client feature bitset. */
  clientFeatures: number;
  /** Server feature bitset. */
  serverFeatures: number;
  /** Channel identifier shared by both endpoints. */
  channelId: string;
  /** Client nonce (32 bytes). */
  nonceC: Uint8Array; // 32
  /** Server nonce (32 bytes). */
  nonceS: Uint8Array; // 32
  /** Client ephemeral public key bytes. */
  clientEphPub: Uint8Array;
  /** Server ephemeral public key bytes. */
  serverEphPub: Uint8Array;
}>;

const te = new TextEncoder();

// transcriptHash computes the SHA-256 hash of the handshake transcript.
export function transcriptHash(inputs: TranscriptInputs): Uint8Array {
  if (inputs.nonceC.length !== 32 || inputs.nonceS.length !== 32) throw new Error("nonce must be 32 bytes");
  const channelIdBytes = te.encode(inputs.channelId);
  if (channelIdBytes.length > 0xffff) throw new Error("channel_id too long");
  if (inputs.clientEphPub.length > 0xffff || inputs.serverEphPub.length > 0xffff) throw new Error("pub too long");

  const prefix = te.encode("flowersec-e2ee-v1");
  const body = concatBytes([
    prefix,
    new Uint8Array([inputs.version & 0xff]),
    u16be(inputs.suite),
    new Uint8Array([inputs.role & 0xff]),
    u32be(inputs.clientFeatures >>> 0),
    u32be(inputs.serverFeatures >>> 0),
    u16be(channelIdBytes.length),
    channelIdBytes,
    inputs.nonceC,
    inputs.nonceS,
    u16be(inputs.clientEphPub.length),
    inputs.clientEphPub,
    u16be(inputs.serverEphPub.length),
    inputs.serverEphPub
  ]);
  return sha256(body);
}
