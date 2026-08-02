import type {
  ArtifactLease,
  ByteStream,
  RpcPeer,
  RpcResult,
  Session,
  StreamMetadata,
} from "../node/index.js";
import {
  connectNodeSession,
  createArtifactLease,
  createStreamMetadata,
  parseArtifact,
} from "../node/index.js";
import { expect, test } from "vitest";
import * as publicAPI from "../node/index.js";

// @ts-expect-error Application-level v2 suffixes are not public package exports.
import type { SessionV2 } from "../node/index.js";

type PingRequest = Readonly<{ nonce: string }>;
type PingResponse = Readonly<{ acknowledged: boolean }>;

function decodePingResponse(payload: unknown): PingResponse {
  if (
    typeof payload !== "object"
    || payload === null
    || !("acknowledged" in payload)
    || typeof payload.acknowledged !== "boolean"
  ) {
    throw new TypeError("invalid ping response");
  }
  return { acknowledged: payload.acknowledged };
}

function typecheckPublicAPI(
  lease: ArtifactLease,
  session: Session,
  peer: RpcPeer,
  stream: ByteStream,
  metadata: StreamMetadata,
): void {
  const result: Promise<RpcResult<PingResponse>> = peer.call<PingRequest, PingResponse>(
    7,
    { nonce: "n" },
    decodePingResponse,
  );
  void result;
  void session.openStream("typed", { metadata });
  void stream.kind;
  void connectNodeSession(lease, { origin: "https://client.example" });
  void connectNodeSession(lease, { origin: "https://client.example", connectTimeoutMs: 2_500 });
  void createArtifactLease(parseArtifact("{}"), async () => {});
  void createStreamMetadata({ purpose: "typed", attempt: 1 });
  // @ts-expect-error stream metadata must be constructed and validated first.
  void session.openStream("unvalidated", { metadata: { purpose: "typed" } });
  // @ts-expect-error Artifact leases are nominal handles created by the SDK.
  const forgedLease: ArtifactLease = { artifact: parseArtifact("{}") };
  void forgedLease;
  // @ts-expect-error session termination has one public waiting entrypoint.
  void session.termination;
  // @ts-expect-error successful typed responses require an explicit decoder.
  void peer.call<PingRequest, PingResponse>(7, { nonce: "n" });
}

test("exposes the unversioned typed public API", () => {
  expect(typecheckPublicAPI).toBeTypeOf("function");
  expect("connectNodeSessionV2" in publicAPI).toBe(false);
  const legacySession: SessionV2 | undefined = undefined;
  expect(legacySession).toBeUndefined();
});
