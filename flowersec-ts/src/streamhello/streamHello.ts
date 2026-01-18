import type { StreamHello } from "../gen/flowersec/rpc/v1.gen.js";
import { readJsonFrame, writeJsonFrame } from "../rpc/framing.js";

// writeStreamHello sends the initial stream greeting.
export async function writeStreamHello(write: (b: Uint8Array) => Promise<void>, kind: string): Promise<void> {
  const h: StreamHello = { kind, v: 1 };
  await writeJsonFrame(write, h);
}

// readStreamHello reads and validates the stream greeting.
export async function readStreamHello(readExactly: (n: number) => Promise<Uint8Array>): Promise<StreamHello> {
  const h = (await readJsonFrame(readExactly, 8 * 1024)) as StreamHello;
  if (h.v !== 1 || typeof h.kind !== "string" || h.kind.length === 0) throw new Error("bad StreamHello");
  return h;
}

