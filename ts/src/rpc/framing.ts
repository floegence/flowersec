import { readU32be, u32be } from "../utils/bin.js";

const te = new TextEncoder();
const td = new TextDecoder();

// RpcFramingError marks malformed or oversized frames.
export class RpcFramingError extends Error {}

// writeJsonFrame encodes a JSON payload with a 4-byte length prefix.
export async function writeJsonFrame(
  write: (b: Uint8Array) => Promise<void>,
  v: unknown
): Promise<void> {
  const json = te.encode(JSON.stringify(v));
  const hdr = u32be(json.length);
  const out = new Uint8Array(4 + json.length);
  out.set(hdr, 0);
  out.set(json, 4);
  await write(out);
}

// readJsonFrame reads and parses a length-prefixed JSON payload.
export async function readJsonFrame(
  readExactly: (n: number) => Promise<Uint8Array>,
  maxBytes: number
): Promise<unknown> {
  const hdr = await readExactly(4);
  const n = readU32be(hdr, 0);
  if (maxBytes > 0 && n > maxBytes) throw new RpcFramingError("frame too large");
  const payload = await readExactly(n);
  return JSON.parse(td.decode(payload));
}
