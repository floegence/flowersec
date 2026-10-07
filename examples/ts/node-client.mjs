import { open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { connect, createStreamMetadata } from "@floegence/flowersec-core/node";
// The maintained public source entrypoint is the createArtifactLease family; this
// example uses the current peer fixture adapter while preserving the same durable
// spend and structured ConnectError/SessionError recovery contract (typed RPC 7001,
// notification 7002).
// This repository example explicitly trusts its engineering peer's application
// material. Identity seeds are confined to that peer fixture; the SDK receives
// configured keys, independently pinned namespaces and an original source.
import {
  createCurrentPeerClient, configureCurrentPeerWSS, peerRequirements,
  peerPingService, peerPingMethod, peerNotifyMethod, peerJSONBytes, peerJSONValue,
} from "../../flowersec-ts/dist/interop/currentPeer.js";

const [materialArgument, origin, receiptArgument, trustRootPath] = process.argv.slice(2);
const materialPath = materialArgument ?? process.env.FSEC_MATERIAL_PATH;
const receiptPath = receiptArgument ?? process.env.FSEC_SPEND_RECEIPT_PATH;
if (materialPath === undefined || origin === undefined || receiptPath === undefined) {
  throw new Error("usage: node-client.mjs <current-material-json> <origin> <spend-receipt> [trust-root-pem]");
}
const signal = AbortSignal.timeout(15_000);
const roots = trustRootPath === undefined ? undefined : await readFile(trustRootPath, "utf8");
const fixture = await createCurrentPeerClient(await readFile(materialPath, "utf8"), roots === undefined ? {} : { trustPEM: roots });
let session;
try {
  const client = configureCurrentPeerWSS(fixture, origin, roots);
  const source = fixture.registerSource(client);
  session = await connect(fixture.environment, source, { ...peerRequirements, application_profile: "services" }, { signal });
  if (fixture.spentCount() !== 1) throw new Error("the original material was not consumed once");
  // This observation receipt records the SDK's completed durable consumption.
  // It never authorizes a Session or supplies an application consume callback.
  const receipt = await open(receiptPath, "wx", 0o600);
  try { await receipt.writeFile("flowersec-v4-material-spent\n", "utf8"); await receipt.sync(); }
  finally { await receipt.close(); }
  const directory = await open(dirname(receiptPath), "r");
  try { await directory.sync(); } finally { await directory.close(); }

  const authority = fixture.policy.authorities[0];
  if (authority === undefined) throw new Error("engineering material has no service authority");
  const service = await session.bindService(peerPingService, { target: {
    authority, tenant: fixture.policy.tenant,
    audience: fixture.policy.audience, localSubject: fixture.policy.clientSubject,
    peers: [{ subject: fixture.policy.serverSubject, identityDigest: fixture.serverIdentity }],
  }, maximumOfferWindowMS: 10000n, signal });
  try {
    const rpc = await service.call(peerPingMethod, peerJSONBytes({ value: "ping" }), { signal, responseLimitBytes: 4096 });
    if (rpc.kind !== "value" || rpc.encoding !== "typed") throw new Error("unexpected typed RPC outcome");
    try {
      const response = peerJSONValue(rpc.value);
      if (typeof response !== "object" || response === null || !("value" in response) || response.value !== "ping") {
        throw new Error("unexpected typed RPC response");
      }
    }
    finally { rpc.release(); }
    const notification = await service.notify(peerNotifyMethod, peerJSONBytes({ value: "notify" }), { signal });
    if (notification.submission !== "submitted") throw new Error("notification was not submitted");
  } finally { service.close(); }

  const stream = await session.openStream("parity.echo", {
    metadata: createStreamMetadata({ cell: process.env.FSEC_EXAMPLE_STREAM_CELL ?? "direct" }), signal,
  });
  try {
    const request = new TextEncoder().encode("hello");
    const progress = await stream.write(request, { signal });
    if (progress.phase !== "terminal" || progress.terminal_reason !== "complete" || progress.accepted_bytes !== BigInt(request.length)) {
      throw new Error("reliable stream did not admit its complete request");
    }
    await stream.closeWrite({ signal });
    const response = await readAll(stream, signal);
    if (new TextDecoder().decode(response) !== "world") throw new Error("unexpected reliable stream response");
    const finished = await stream.finish({ signal });
    if (!finished.send_drained) throw new Error("reliable stream output was not drained");
  } finally { await stream.close({ signal }).catch(() => undefined); }
  const liveness = await session.probeLiveness({ signal });
  console.log("session=ready");
  console.log(`rpc=ok notification=ok stream=ok liveness_ms=${liveness.elapsedMS}`);
} catch (error) {
  console.error(`operation_error=${error instanceof Error ? error.message : String(error)}`);
  throw error;
} finally {
  await session?.close(); await fixture.close();
}

/** @param {import("@floegence/flowersec-core/node").Stream} stream
 * @param {AbortSignal} signal */
async function readAll(stream, signal) {
  const chunks = []; let length = 0;
  for (;;) {
    const result = await stream.read(16384n, { signal });
    if (result.wait_status !== "ready" || result.stream_status === "aborted" || result.stream_status === "error") throw new Error("reliable stream read failed");
    if (result.data.length > 65536 - length) throw new Error("example response exceeds its declared bound");
    if (result.data.length > 0) { chunks.push(result.data.slice()); length += result.data.length; }
    if (result.stream_status === "eof") break;
  }
  const output = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.length; }
  return output;
}
