import { readU32be, u32be } from "../utils/bin.js";

export const DEFAULT_MAX_JSON_FRAME_BYTES = 1 << 20;

const te = new TextEncoder();
const td = new TextDecoder();

// JsonFramingError marks malformed or oversized frames.
export class JsonFramingError extends Error {}

type WriteFn = (b: Uint8Array) => Promise<void>;
type WriteLike = Readonly<{ write: (b: Uint8Array) => Promise<void> }>;

type ReadExactlyFn = (n: number) => Promise<Uint8Array>;
type ReadExactlyLike = Readonly<{ readExactly: (n: number) => Promise<Uint8Array> }>;

function normalizeWrite(write: WriteFn | WriteLike): WriteFn {
  return typeof write === "function" ? write : (b) => write.write(b);
}

function normalizeReadExactly(readExactly: ReadExactlyFn | ReadExactlyLike): ReadExactlyFn {
  return typeof readExactly === "function" ? readExactly : (n) => readExactly.readExactly(n);
}

// writeJsonFrame encodes a JSON payload with a 4-byte length prefix.
export async function writeJsonFrame(write: WriteFn | WriteLike, v: unknown): Promise<void> {
  const json = te.encode(JSON.stringify(v));
  const hdr = u32be(json.length);
  const out = new Uint8Array(4 + json.length);
  out.set(hdr, 0);
  out.set(json, 4);
  await normalizeWrite(write)(out);
}

// readJsonFrame reads and parses a length-prefixed JSON payload.
export async function readJsonFrame(readExactly: ReadExactlyFn | ReadExactlyLike, maxBytes: number): Promise<unknown> {
  const read = normalizeReadExactly(readExactly);
  const hdr = await read(4);
  const n = readU32be(hdr, 0);
  if (maxBytes > 0 && n > maxBytes) throw new JsonFramingError("frame too large");
  const payload = await read(n);
  return JSON.parse(td.decode(payload));
}

