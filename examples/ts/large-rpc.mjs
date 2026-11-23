import { setImmediate as yieldTurn } from "node:timers/promises";

/** @typedef {import('@floegence/flowersec-core/node').JsonValue} JsonValue */
/** @typedef {import('@floegence/flowersec-core/node').RPCHandlers} RPCHandlers */
/** @typedef {import('@floegence/flowersec-core/node').Session} Session */

export const largeEchoID = 7010;
const size = 32 * 1024 * 1024;
const encodedSize = 4 * Math.ceil(size / 3);
const minFrame = encodedSize + JSON.stringify({ type_id: largeEchoID, request_id: Number.MAX_SAFE_INTEGER, response_to: 0, payload: "" }).length;

/** @param {NodeJS.ProcessEnv} env */
export function rpcSettings(env) {
  const mode = env.FSEC_EXAMPLE_LARGE_RPC ?? "0";
  if (!["0", "1", "call", "serve"].includes(mode)) throw new Error("invalid FSEC_EXAMPLE_LARGE_RPC mode");
  const large = mode !== "0", serve = mode === "serve";
  const raw = env.FSEC_RPC_FRAME_BYTES;
  if (!large && raw === undefined) return { large, serve };
  const maxRpcFrameBytes = Number(raw);
  if (raw === undefined || !/^[1-9][0-9]*$/u.test(raw) || !Number.isSafeInteger(maxRpcFrameBytes) ||
      maxRpcFrameBytes > 64 * 1024 * 1024 || (large && maxRpcFrameBytes < minFrame)) {
    throw new Error(`invalid FSEC_RPC_FRAME_BYTES${large ? ` (large RPC requires at least ${minFrame})` : ""}`);
  }
  return { large, serve, maxRpcFrameBytes };
}

/** @param {number} i */
const byteAt = i => (i ^ (i >>> 8) ^ (i >>> 16)) & 255;

/** @param {JsonValue} value @param {boolean} checkContents @param {AbortSignal} signal */
async function valid(value, checkContents, signal) {
  if (typeof value !== "string" || value.length !== encodedSize) return false;
  let offset = 0;
  for (let i = 0; i < value.length; i += 65536) {
    if (i % (1024 * 1024) === 0) await yieldTurn(undefined, { signal });
    const text = value.slice(i, i + 65536);
    const bytes = Buffer.from(text, "base64");
    // Node's decoder alone also accepts whitespace, URL-safe characters and nonzero padding bits.
    if (bytes.length !== Math.min(text.length / 4 * 3, size - offset) || bytes.toString("base64") !== text) return false;
    if (checkContents) {
      for (let j = 0; j < bytes.length; j++) if (bytes[j] !== byteAt(offset + j)) return false;
    }
    offset += bytes.length;
  }
  return offset === size;
}

/** @param {RPCHandlers} registry @param {() => boolean} permitted @param {AbortSignal} lifetime @param {() => void} accepted */
export function registerLargeEcho(registry, permitted, lifetime, accepted) {
  registry.handleRPC(largeEchoID, async (payload, request) => {
    const denied = () => ({ error: { code: 403, message: "binary echo unavailable" } });
    if (!permitted()) return denied();
    const signal = request.signal ? AbortSignal.any([lifetime, request.signal]) : lifetime;
    if (!await valid(payload, false, signal)) return { error: { code: 400, message: "invalid binary payload" } };
    if (!permitted()) return denied();
    accepted();
    return { payload };
  });
}

/** @param {AbortSignal} signal */
async function requestValue(signal) {
  const bytes = Buffer.allocUnsafe(size);
  for (let start = 0; start < size; start += 1024 * 1024) {
    await yieldTurn(undefined, { signal });
    for (let i = start; i < start + 1024 * 1024; i++) bytes[i] = byteAt(i);
  }
  return bytes.toString("base64");
}

/** @param {Session} session @param {AbortSignal} signal */
export async function callLargeEcho(session, signal) {
  const reply = await session.rpc.call(largeEchoID, await requestValue(signal), value => value, { signal });
  if (!reply.ok) throw new Error(`binary echo rejected: ${reply.error.code}`);
  if (!await valid(reply.payload, true, signal)) throw new Error("binary echo response does not match all 32 MiB");
}
