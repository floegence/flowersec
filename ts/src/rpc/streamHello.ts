import type { StreamHello } from "../gen/flowersec/rpc/v1.gen.js";
import { readJsonFrame, writeJsonFrame } from "./framing.js";

export async function writeStreamHello(write: (b: Uint8Array) => Promise<void>, kind: string): Promise<void> {
  const h: StreamHello = { kind, v: 1 };
  await writeJsonFrame(write, h);
}

export async function readStreamHello(readExactly: (n: number) => Promise<Uint8Array>): Promise<StreamHello> {
  const h = (await readJsonFrame(readExactly, 8 * 1024)) as StreamHello;
  if (h.v !== 1 || typeof h.kind !== "string" || h.kind.length === 0) throw new Error("bad StreamHello");
  return h;
}

