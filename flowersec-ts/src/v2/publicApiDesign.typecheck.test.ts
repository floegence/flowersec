import type {
  ArtifactLease,
  ByteStream,
  JsonObject,
  RpcPeer,
  RpcResult,
  Session,
} from "../node/index.js";
import {
  connectNodeSession,
  createArtifactLease,
  parseArtifact,
} from "../node/index.js";
import { expect, test } from "vitest";
import * as publicAPI from "../node/index.js";

// @ts-expect-error Application-level v2 suffixes are not public package exports.
import type { SessionV2 } from "../node/index.js";

type PingRequest = Readonly<{ nonce: string }>;
type PingResponse = Readonly<{ acknowledged: boolean }>;

function typecheckPublicAPI(
  lease: ArtifactLease,
  session: Session,
  peer: RpcPeer,
  stream: ByteStream,
  metadata: JsonObject,
): void {
  const result: Promise<RpcResult<PingResponse>> = peer.call<PingRequest, PingResponse>(
    7,
    { nonce: "n" },
  );
  void result;
  void session.openStream("typed", { metadata });
  void stream.kind;
  void connectNodeSession(lease, { origin: "https://client.example" });
  void createArtifactLease(parseArtifact("{}"), async () => {});
}

test("exposes the unversioned typed public API", () => {
  expect(typecheckPublicAPI).toBeTypeOf("function");
  expect("connectNodeSessionV2" in publicAPI).toBe(false);
  const legacySession: SessionV2 | undefined = undefined;
  expect(legacySession).toBeUndefined();
});
