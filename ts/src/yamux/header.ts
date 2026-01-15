import { readU32be, u32be } from "../utils/bin.js";
import { YAMUX_VERSION } from "./constants.js";

export const HEADER_LEN = 12;

export type YamuxHeader = Readonly<{
  version: number;
  type: number;
  flags: number;
  streamId: number;
  length: number;
}>;

export function encodeHeader(h: Omit<YamuxHeader, "version"> & { version?: number }): Uint8Array {
  const out = new Uint8Array(HEADER_LEN);
  out[0] = (h.version ?? YAMUX_VERSION) & 0xff;
  out[1] = h.type & 0xff;
  out[2] = (h.flags >>> 8) & 0xff;
  out[3] = h.flags & 0xff;
  out.set(u32be(h.streamId >>> 0), 4);
  out.set(u32be(h.length >>> 0), 8);
  return out;
}

export function decodeHeader(buf: Uint8Array, off: number): YamuxHeader {
  if (buf.length - off < HEADER_LEN) throw new Error("header too short");
  const version = buf[off]!;
  const type = buf[off + 1]!;
  const flags = ((buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
  const streamId = readU32be(buf, off + 4);
  const length = readU32be(buf, off + 8);
  return { version, type, flags, streamId, length };
}

