import type {
  AcceptorOptions,
  AuthorizationRecord,
  AuthorizationResponse,
  IssuedArtifact,
  Issuer,
  RuntimeAuthorizationRequest,
  TunnelRuntimeOptions,
} from "./v2.js";
import {
  authorizeRuntime,
  authorizeTunnelRuntime,
  rejectRuntime,
  rejectTunnelRuntime,
} from "./controlplane.js";
import type { OperationOptions, RpcPeer, Session, UnreliableMessageChannel } from "../public/contract.js";
import { expect, test } from "vitest";
import { readFile } from "node:fs/promises";
import path from "node:path";

function typecheckNodeServerSurface(
  issuer: Issuer,
  issued: IssuedArtifact,
  record: AuthorizationRecord,
  request: RuntimeAuthorizationRequest,
  response: AuthorizationResponse,
  peer: RpcPeer,
  session: Session,
  unreliable: UnreliableMessageChannel,
  options: OperationOptions,
): void {
  void issuer;
  void issued;
  void record;
  void request;
  void response;
  const result = peer.call(7, { value: 1 }, (payload) => payload, options);
  void result;
  void peer.notify(8, { ready: true }, options);
  void session.waitTermination(options);
  const maxMessageSize: number = unreliable.maxMessageSize;
  void maxMessageSize;
}

export const nodeServerSurfaceTypecheck = typecheckNodeServerSurface;

function typecheckTypedRuntimeAuthorizers(
  record: AuthorizationRecord,
): Readonly<{
  direct: AcceptorOptions["authorize"];
  tunnel: TunnelRuntimeOptions["authorize"];
}> {
  return {
    direct: async (request) => authorizeRuntime(request, record, "lease-direct"),
    tunnel: async (request) => authorizeTunnelRuntime(request, record, "lease-tunnel"),
  };
}

const rejectedDirectAuthorizer: AcceptorOptions["authorize"] = async () =>
  rejectRuntime("permission_denied", false);
const retryingTunnelAuthorizer: TunnelRuntimeOptions["authorize"] = async () =>
  rejectTunnelRuntime("busy", true);

export const typedRuntimeAuthorizersTypecheck = typecheckTypedRuntimeAuthorizers;
export const typedRuntimeRejectionsTypecheck = {
  direct: rejectedDirectAuthorizer,
  tunnel: retryingTunnelAuthorizer,
};

test("keeps the Node server public type surface callable", () => {
  expect(nodeServerSurfaceTypecheck).toBeTypeOf("function");
});

test("keeps control-plane internals out of the built declaration", async () => {
  const declaration = await readFile(path.resolve(process.cwd(), "dist/node/controlplane.d.ts"), "utf8");
  expect(declaration).not.toMatch(/IssuerOptions|requestBase64URL|toCandidates|fromDecoded/u);
  expect(declaration).not.toMatch(/constructor\(artifact:|constructor\(json:/u);
});
