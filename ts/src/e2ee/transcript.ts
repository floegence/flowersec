import { sha256 } from "@noble/hashes/sha256";
import { concatBytes, u16be, u32be } from "../utils/bin.js";

export type TranscriptInputs = Readonly<{
  version: number;
  suite: number;
  role: number;
  clientFeatures: number;
  serverFeatures: number;
  channelId: string;
  nonceC: Uint8Array; // 32
  nonceS: Uint8Array; // 32
  clientEphPub: Uint8Array;
  serverEphPub: Uint8Array;
}>;

const te = new TextEncoder();

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

