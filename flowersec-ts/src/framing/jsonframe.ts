import { readU32be } from "../utils/bin.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { SessionError } from "../public/contract.js";

export const DEFAULT_MAX_JSON_FRAME_BYTES = SDK_DEFAULTS.rpc.maxJsonFrameBytes;

/** Counts encoded envelope bytes, excluding the four-byte length prefix. */
export function rpcFrameLimit(bytes: number = DEFAULT_MAX_JSON_FRAME_BYTES): number {
  if (!Number.isSafeInteger(bytes) || bytes < 1 || bytes > 64 * 1024 * 1024) throw new RangeError("invalid maxRpcFrameBytes");
  return bytes;
}

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

// JsonFramingError marks malformed or oversized frames.
export class JsonFramingError extends Error {}

// Only opt-in large RPC frames share this transient storage allowance in a JS
// isolate. Count the wire bytes and up to two bytes per decoded text unit.
const largeFrameBudget = 512 * 1024 * 1024;
let largeFrameBytes = 0;
const noCharge = () => {};
function reserveFrame(bytes: number, charge: number): () => void {
  if (bytes <= DEFAULT_MAX_JSON_FRAME_BYTES) return noCharge;
  if (charge > largeFrameBudget - largeFrameBytes) throw new SessionError("resource_exhausted");
  largeFrameBytes += charge;
  let active = true;
  return () => { if (active) { active = false; largeFrameBytes -= charge; } };
}

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
export async function writeJsonFrame(write: WriteFn | WriteLike, v: unknown, maxBytes = 0, rpc = false): Promise<void> {
  const text = JSON.stringify(v);
  if (typeof text !== "string") throw new JsonFramingError("invalid JSON value");
  let length = text.length;
  if (maxBytes > 0 && length > maxBytes) throw new JsonFramingError("frame too large");
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) continue;
    if (code < 0x800) length++;
    else {
      length += 2;
      if (code >= 0xd800 && code <= 0xdbff && text.charCodeAt(i + 1) >= 0xdc00 && text.charCodeAt(i + 1) <= 0xdfff) i++;
    }
  }
  if (length > 0xffffffff || (maxBytes > 0 && length > maxBytes)) throw new JsonFramingError("frame too large");
  const release = rpc ? reserveFrame(length, 4 + length + 2 * text.length) : noCharge;
  try {
    const frame = new Uint8Array(4 + length);
    new DataView(frame.buffer).setUint32(0, length, false);
    te.encodeInto(text, frame.subarray(4));
    await normalizeWrite(write)(frame);
  } finally { release(); }
}

// readJsonFrame reads and parses a length-prefixed JSON payload.
export async function readJsonFrame(readExactly: ReadExactlyFn | ReadExactlyLike, maxBytes: number): Promise<unknown> {
  return (await readFrame(readExactly, maxBytes, false)).value;
}

export async function readRpcFrame(readExactly: ReadExactlyFn | ReadExactlyLike, maxBytes: number) {
  return await readFrame(readExactly, maxBytes, true);
}

async function readFrame(readExactly: ReadExactlyFn | ReadExactlyLike, maxBytes: number, rpc: boolean) {
  const read = normalizeReadExactly(readExactly);
  const hdr = await read(4);
  const n = readU32be(hdr, 0);
  if (maxBytes > 0 && n > maxBytes) throw new JsonFramingError("frame too large");
  const releaseWire = rpc ? reserveFrame(n, 4 + 3 * n) : noCharge;
  try {
    const payload = await read(n);
    let text: string;
    try { text = td.decode(payload); } catch { throw new JsonFramingError("invalid UTF-8"); }
    const release = rpc ? reserveFrame(n, 2 * text.length) : noCharge;
    try { return { value: JSON.parse(text) as unknown, release }; }
    catch (error) { release(); throw error; }
  } finally { releaseWire(); }
}
