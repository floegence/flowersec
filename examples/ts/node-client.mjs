import { open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  connect,
  ConnectError,
  createArtifactLease,
  createStreamMetadata,
  parseArtifact,
  SessionError,
} from "@floegence/flowersec-core/node";

/** @typedef {import("@floegence/flowersec-core/node").ByteStream} ByteStream */
/** @typedef {import("@floegence/flowersec-core/node").JsonValue} JsonValue */
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
    await receipt.writeFile("flowersec-v2-artifact-spent\n", "utf8");
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
const signal = AbortSignal.timeout(15_000);
const tls = trustRootPath === undefined ? undefined : { ca: await readFile(trustRootPath) };
let session;
let unsubscribe = () => {};
try {
  session = await connect(lease, {
    origin,
    signal,
    ...(tls === undefined ? {} : { tls }),
  });
} catch (error) {
  reportRecovery(error);
  throw error;
}
try {
  try {
    /** @type {Promise<ValuePayload>} */
    const notificationReceived = new Promise((resolve) => {
      unsubscribe = session.rpc.onNotify(
        NOTIFICATION_TYPE_ID,
        decodeValuePayload,
        resolve,
      );
    });
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
    const notification = await notificationReceived;
    if (notification.value !== "notify") {
      throw new Error("unexpected notification payload");
    }

    const metadata = createStreamMetadata({
      cell: process.env.FSEC_EXAMPLE_STREAM_CELL ?? "direct",
    });
    const stream = await session.openStream(ECHO_STREAM_KIND, { metadata, signal });
    await writeAll(stream, encoder.encode("hello"), signal);
    await stream.closeWrite();
    const streamResponse = await readAll(stream, signal);
    if (decoder.decode(streamResponse) !== "world") {
      throw new Error("unexpected reliable stream response");
    }

    const roundTripMs = await session.probeLiveness({ signal });
    console.log("session=ready");
    console.log(`rpc=ok notification=ok stream=ok liveness_ms=${Math.round(roundTripMs)}`);
  } catch (error) {
    reportRecovery(error);
    throw error;
  }
} finally {
  unsubscribe();
  unsubscribe();
  await session.close();
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
async function readAll(stream, signal) {
  /** @type {Uint8Array[]} */
  const chunks = [];
  let length = 0;
  for (;;) {
    const chunk = await stream.read({ signal });
    if (chunk === null) break;
    chunks.push(chunk);
    length += chunk.byteLength;
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

/** @param {unknown} error */
function reportRecovery(error) {
  if (error instanceof ConnectError) {
    console.error(`connection_error=${error.code}`);
  } else if (error instanceof SessionError) {
    console.error(`session_error=${error.code}`);
  }
}
