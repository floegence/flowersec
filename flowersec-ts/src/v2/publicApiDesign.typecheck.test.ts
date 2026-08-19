import type {
  ArtifactLease,
  ByteStream,
  RpcPeer,
  RpcResult,
  Session,
  StreamMetadata,
} from "../node/v2.js";
import {
  ArtifactError,
  connect,
  createArtifactLease,
  createConnectionController,
  createStreamMetadata,
  parseArtifact,
  RPCHandlers,
} from "../node/v2.js";
// @ts-expect-error Browser profiles do not expose native inbound RPC handlers.
import { RPCHandlers as BrowserRPCHandlers } from "../browser/v2.js";
import { expect, test } from "vitest";

type PingRequest = Readonly<{ nonce: string }>;
type PingResponse = Readonly<{ acknowledged: boolean }>;

function decodePingNotification(payload: unknown): PingResponse {
  return decodePingResponse(payload);
}

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
  const rpcHandlers = new RPCHandlers();
  rpcHandlers.handleRPC(9, async () => ({ payload: null }));
  rpcHandlers.handleNotification(10, async () => undefined);
  // @ts-expect-error Client RPC handlers cannot register application streams.
  rpcHandlers.handleStream("invalid", async () => undefined);
  const result: Promise<RpcResult<PingResponse>> = peer.call<PingRequest, PingResponse>(
    7,
    { nonce: "n" },
    decodePingResponse,
  );
  void result;
  const unsubscribe = peer.onNotify(8, decodePingNotification, (payload) => {
    const acknowledged: boolean = payload.acknowledged;
    void acknowledged;
  });
  unsubscribe();
  void session.openStream("typed", { metadata });
  void stream.kind;
  void connect(lease, { origin: "https://client.example", rpcHandlers });
  void connect(lease, { origin: "https://client.example", connectTimeoutMs: 2_500 });
  void createConnectionController({
    acquire: async () => ({ kind: "lease", lease }),
  }, { origin: "https://client.example", rpcHandlers });
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
  // @ts-expect-error notification payloads require an explicit decoder.
  void peer.onNotify<PingResponse>(8, () => undefined);
  // @ts-expect-error RPC calls accept only JSON values.
  void peer.call(7, { nonce: 1n }, decodePingResponse);
  // @ts-expect-error RPC notifications accept only JSON values.
  void peer.notify(8, undefined);
  void BrowserRPCHandlers;
}

test("exposes the unversioned typed public API", () => {
  expect(typecheckPublicAPI).toBeTypeOf("function");
  expect(ArtifactError).toBeTypeOf("function");
});

test("projects artifact parsing failures to the stable public error", () => {
  expect(() => parseArtifact("{}"))
    .toThrowError(expect.objectContaining({ name: "ArtifactError", code: "invalid_artifact" }));
});
