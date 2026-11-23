import { fstatSync } from "node:fs";
import { Socket } from "node:net";

// The launcher gives the two separately started processes opposite ends of a
// private Unix socketpair. Neither process discovers, launches or samples peers.
export function roleSocket(): Socket {
  if (process.argv.length !== 2 || !fstatSync(3).isSocket()) throw new Error("an inherited product control socket is required");
  return new Socket({ fd: 3, readable: true, writable: true, allowHalfOpen: true });
}
export function send(socket: Socket, value: unknown, limit: number): Promise<void> {
  const frame = Buffer.from(JSON.stringify(value) + "\n");
  if (frame.byteLength > limit) throw new Error("product control response exceeds its bound");
  return new Promise((resolve, reject) => socket.write(frame, error => error ? reject(error) : resolve()));
}
export async function* frames(socket: Socket, limit: number): AsyncGenerator<Record<string, unknown>> {
  let saved: Buffer[] = [], size = 0;
  for await (const chunk of socket.iterator({ destroyOnReturn: false })) {
    const bytes = chunk as Buffer;
    for (let from = 0; from < bytes.length;) {
      const newline = bytes.indexOf(10, from), end = newline < 0 ? bytes.length : newline;
      size += end - from;
      if (size + 1 > limit) throw new Error("product control frame exceeds its bound");
      saved.push(bytes.subarray(from, end));
      if (newline < 0) break;
      const value: unknown = JSON.parse(Buffer.concat(saved, size).toString("utf8"));
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid product control frame");
      saved = []; size = 0; yield value as Record<string, unknown>; from = end + 1;
    }
  }
  if (size !== 0) throw new Error("incomplete product control frame");
}
export const requestBytes = 8192, replyBytes = 256 * 1024, concurrentCalls = 1016;

export function originalDeadline(stamp: unknown, ms: number): AbortSignal {
  if (typeof stamp !== "string" || !/^\d{1,20}$/.test(stamp)) throw new Error("invalid original operation start");
  const elapsed = process.hrtime.bigint() - BigInt(stamp);
  if (elapsed < 0n) throw new Error("product and coordinator require one monotonic clock");
  const remaining = Number((BigInt(ms) * 1_000_000n - elapsed) / 1_000_000n);
  return remaining <= 0 ? AbortSignal.abort(new DOMException("original operation deadline", "TimeoutError")) : AbortSignal.timeout(remaining);
}
