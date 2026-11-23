import { once } from "node:events";
import { open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  connect,
  ConnectError,
  createArtifactLease,
  createStreamMetadata,
  parseArtifact,
  RPCHandlers,
  SessionError,
} from "@floegence/flowersec-core/node";
import { parityRegistrations, verifyParity } from "./parity.mjs";
import { callLargeEcho, largeEchoID, registerLargeEcho, rpcSettings } from "./large-rpc.mjs";
import { policyAllows } from "./permissions.mjs";

/** @typedef {import("@floegence/flowersec-core/node").ByteStream} ByteStream */
/** @typedef {import("@floegence/flowersec-core/node").JsonValue} JsonValue */
/** @typedef {import("@floegence/flowersec-core/node").Session} Session */
/** @typedef {{ value: string }} ValuePayload */

const ECHO_RPC_TYPE_ID = 7_001;
const NOTIFICATION_TYPE_ID = 7_002;
const ECHO_STREAM_KIND = "parity.echo";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const [artifactPath, origin, receiptPath, trustRootPath] = process.argv.slice(2);
if (artifactPath === undefined || origin === undefined || receiptPath === undefined) {
  throw new Error(
    "usage: node-client.mjs <artifact-json> <origin> <spend-receipt> [trust-root-pem]",
  );
}

const artifact = parseArtifact(await readFile(artifactPath));
const lease = createArtifactLease(artifact, async () => {
  const receipt = await open(receiptPath, "wx", 0o600);
  try {
    await receipt.writeFile("flowersec-v5-artifact-spent\n", "utf8");
    await receipt.sync();
  } finally {
    await receipt.close();
  }
  const directory = await open(dirname(receiptPath), "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
});
const settings = rpcSettings(process.env);
let acceptedLargeEcho = false;
const signal = AbortSignal.timeout(settings.large ? 120_000 : 15_000);
const roots = trustRootPath === undefined ? undefined : await readFile(trustRootPath);
const ingress = process.env.FSEC_TUNNEL_INGRESS;
/** @type {Promise<Session>} */
const connected = connect(lease, {
  origin,
  signal,
  rpcHandlers: createHandlers(() => connected, signal, settings.large),
  ...(settings.maxRpcFrameBytes === undefined ? {} : { maxRpcFrameBytes: settings.maxRpcFrameBytes }),
  ...(ingress === undefined ? {} : { tunnelIngressURL: ingress }),
  ...(roots === undefined ? {} : { roots }),
});
let session;
try {
  session = await connected;
} catch (error) {
  reportRecovery(error);
  throw error;
}
try {
  if (process.env.FSEC_EXAMPLE_QUERY === "1") await verifyParity(session, signal);
  if (settings.serve) {
    await serveEchoStreams(session, signal);
    const end = await session.waitTermination({ signal });
    if (end.error.code !== "closed" || !end.peerCloseReceived || !acceptedLargeEcho) throw new Error("peer did not complete the binary echo exchange");
    console.log("binary_echo=accepted");
  } else if (settings.large) {
    await callLargeEcho(session, signal);
    console.log("binary_echo=verified");
  } else {
    const rpc = await session.rpc.call(
      ECHO_RPC_TYPE_ID,
      { value: "ping" },
      decodeValuePayload,
      { signal },
    );
    if (!rpc.ok || rpc.payload.value !== "ping") {
      throw new Error("unexpected typed RPC response");
    }
    await session.rpc.notify(
      NOTIFICATION_TYPE_ID,
      { value: "notify" },
      { signal },
    );
    const metadata = createStreamMetadata({
      cell: process.env.FSEC_EXAMPLE_STREAM_CELL ?? "direct",
    });
    const stream = await session.openStream(ECHO_STREAM_KIND, { metadata, signal });
    await writeAll(stream, encoder.encode("hello"), signal);
    await stream.closeWrite();
    const streamResponse = await readEcho(stream, signal);
    if (decoder.decode(streamResponse) !== "world") {
      throw new Error("unexpected reliable stream response");
    }

    const roundTripMs = await session.probeLiveness({ signal });
    console.log("session=ready");
    console.log(`rpc=ok notification=ok stream=ok liveness_ms=${Math.round(roundTripMs)}`);
  }
} catch (error) {
  reportRecovery(error);
  throw error;
} finally {
  await session.close();
}

/** @param {() => Promise<Session>} getSession @param {AbortSignal} lifetime @param {boolean} large */
function createHandlers(getSession, lifetime, large) {
  const registry = new RPCHandlers();
  const allowed = new Set([ECHO_RPC_TYPE_ID, NOTIFICATION_TYPE_ID, 7003, 7005]);
  if (large) allowed.add(largeEchoID);
  const policy = process.env.FLOWERSEC_PARITY_POLICY_FILE;
  /** @param {number} id */
  const permitted = id => !lifetime.aborted && allowed.has(id) && policyAllows(policy, "execute", id);
  const routes = parityRegistrations(registry, permitted, id => !lifetime.aborted && allowed.has(id) && policyAllows(policy, "disclose", id));
  if (large) registerLargeEcho(registry, () => permitted(largeEchoID), lifetime, () => { acceptedLargeEcho = true; });
  const observed = new EventTarget();
  let notifications = 0;
  const bad = () => ({ error: { code: 400, message: "invalid value payload" } });
  const denied = () => ({ error: { code: 403, message: "parity method unavailable" } });
  /** @param {JsonValue} payload */
  const valueOf = payload => {
    try { return decodeValuePayload(payload).value; } catch { return undefined; }
  };
  routes.handleRPC(ECHO_RPC_TYPE_ID, async (payload, request) => {
    const value = valueOf(payload);
    if (value !== "ping" && value !== "notifications-observed") return bad();
    if (value === "notifications-observed" && notifications < 2) {
      const signal = request.signal ? AbortSignal.any([lifetime, request.signal]) : lifetime;
      await once(observed, "delivered", { signal });
    }
    return permitted(ECHO_RPC_TYPE_ID) ? { payload } : denied();
  });
  routes.handleNotification(NOTIFICATION_TYPE_ID, payload => {
    if (valueOf(payload) !== "notify") return;
    if (notifications < 2 && ++notifications === 2) observed.dispatchEvent(new Event("delivered"));
  });
  routes.handleRPC(7003, async (payload, request) => {
    if (valueOf(payload) !== "complete") return bad();
    const session = await getSession();
    const signal = request.signal ? AbortSignal.any([lifetime, request.signal]) : lifetime;
    if (!permitted(7003)) return denied();
    await session.rekey({ signal });
    if (!permitted(7003)) return denied();
    await session.probeLiveness({ signal });
    return permitted(7003) ? { payload } : denied();
  });
  routes.handleRPC(7005, async payload => valueOf(payload) === "datagram-ready" ? { payload } : bad());
  return registry;
}

/**
 * @param {JsonValue} payload
 * @returns {ValuePayload}
 */
function decodeValuePayload(payload) {
  if (
    typeof payload !== "object" ||
    payload === null ||
    Array.isArray(payload)
  ) {
    throw new Error("invalid value payload");
  }
  const value = Reflect.get(payload, "value");
  if (typeof value !== "string") throw new Error("invalid value payload");
  return { value };
}

/**
 * @param {ByteStream} stream
 * @param {Uint8Array} data
 * @param {AbortSignal} signal
 */
async function writeAll(stream, data, signal) {
  let offset = 0;
  while (offset < data.byteLength) {
    const written = await stream.write(data.subarray(offset), { signal });
    if (written <= 0) throw new Error("reliable stream made no write progress");
    offset += written;
  }
}

/**
 * @param {ByteStream} stream
 * @param {AbortSignal} signal
 * @returns {Promise<Uint8Array>}
 */
async function readEcho(stream, signal) {
  const output = new Uint8Array(5);
  let length = 0;
  for (;;) {
    const chunk = await stream.read({ signal });
    if (chunk === null) return output.subarray(0, length);
    if (chunk.length > output.length - length) throw new Error("unexpected reliable stream length");
    output.set(chunk, length);
    length += chunk.byteLength;
  }
}

/** @param {Session} session @param {AbortSignal} signal */
async function serveEchoStreams(session, signal) {
  for (;;) {
    let incoming;
    try { incoming = await session.acceptStream({ signal }); }
    catch (error) {
      if (error instanceof SessionError && (error.code === "closed" || error.code === "going_away")) return;
      throw error;
    }
    if (incoming.kind !== ECHO_STREAM_KIND) { await incoming.stream.reset(); continue; }
    if (decoder.decode(await readEcho(incoming.stream, signal)) !== "hello") throw new Error("unexpected reliable stream request");
    await writeAll(incoming.stream, encoder.encode("world"), signal);
    await incoming.stream.closeWrite();
  }
}

/** @param {unknown} error */
function reportRecovery(error) {
  if (error instanceof ConnectError) {
    console.error(`connection_error=${error.code}`);
    console.error(`retry=${error.retryDisposition.kind}`);
  } else if (error instanceof SessionError) {
    console.error(`session_error=${error.code}`);
  }
}
