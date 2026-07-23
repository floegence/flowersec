import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { NODE_RUNTIME_CAPABILITY_V2 } from "../v2/capability.js";
import type { SessionV2 } from "../v2/contract.js";
import {
  createBrowserSessionConnectorV2InternalStage,
  createWebSocketAttemptFactoryV2InternalStage,
} from "../browser/connectV2.js";
import { createNodeWsFactory } from "./wsFactory.js";
import { projectSessionV2 } from "../v2/publicSession.js";

export type NodeSessionTLSOptionsV2 = Readonly<{
  ca?: string | Uint8Array;
}>;

export type NodeSessionConnectorV2Options = Readonly<{
  origin: string;
  signal?: AbortSignal;
  loserCloseTimeoutMs?: number;
  now?: () => number;
  tls?: NodeSessionTLSOptionsV2;
}>;

export async function connectNodeSessionV2(
  lease: ArtifactLeaseV2,
  options: NodeSessionConnectorV2Options,
): Promise<SessionV2> {
  const origin = normalizeOrigin(options.origin);
  const wsFactory = createNodeWsFactory(options.tls);
  const connector = createBrowserSessionConnectorV2InternalStage(lease, {
    admissionReasons: new Set(),
    capability: NODE_RUNTIME_CAPABILITY_V2,
    ...(options.loserCloseTimeoutMs === undefined ? {} : { loserCloseTimeoutMs: options.loserCloseTimeoutMs }),
    ...(options.now === undefined ? {} : { now: options.now }),
    runtime: "node",
    attemptFactory: createWebSocketAttemptFactoryV2InternalStage(
      (url, subprotocol) => wsFactory(url, origin, subprotocol),
    ),
  });
  const result = await connector.connect(options.signal === undefined ? {} : { signal: options.signal });
  return projectSessionV2(result.session);
}

function normalizeOrigin(input: string): string {
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new TypeError("origin must be an absolute HTTP(S) origin"); }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== input || parsed.username !== "" || parsed.password !== "") {
    throw new TypeError("origin must be an absolute HTTP(S) origin without path, query, or credentials");
  }
  return parsed.origin;
}
