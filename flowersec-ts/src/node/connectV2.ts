import type { ArtifactLeaseV2 } from "../v2/artifactLease.js";
import { NODE_RUNTIME_CAPABILITY_V2 } from "../v2/capability.js";
import type { SessionV2 } from "../v2/session.js";
import {
  createBrowserSessionConnectorV2InternalStage,
  createWebSocketAttemptFactoryV2InternalStage,
  type BrowserSessionConnectorV2Options,
} from "../browser/connectV2.js";
import { createNodeWsFactory, type NodeWsFactoryOptions } from "./wsFactory.js";

export type NodeSessionConnectorV2Options = Readonly<{
  origin: string;
  admissionReasons?: ReadonlySet<string>;
  signal?: AbortSignal;
  loserCloseTimeoutMs?: number;
  now?: () => number;
  webSocket?: NodeWsFactoryOptions;
}>;

export async function connectNodeSessionV2(
  lease: ArtifactLeaseV2,
  options: NodeSessionConnectorV2Options,
): Promise<SessionV2> {
  const origin = normalizeOrigin(options.origin);
  const wsFactory = createNodeWsFactory(options.webSocket);
  const connectorOptions: BrowserSessionConnectorV2Options = {
    admissionReasons: options.admissionReasons ?? new Set(),
    capability: NODE_RUNTIME_CAPABILITY_V2,
    ...(options.loserCloseTimeoutMs === undefined ? {} : { loserCloseTimeoutMs: options.loserCloseTimeoutMs }),
    ...(options.now === undefined ? {} : { now: options.now }),
  };
  const connector = createBrowserSessionConnectorV2InternalStage(lease, {
    ...connectorOptions,
    runtime: "node",
    attemptFactory: createWebSocketAttemptFactoryV2InternalStage(
      (url, subprotocol) => wsFactory(url, origin, subprotocol),
    ),
  });
  const result = await connector.connect(options.signal === undefined ? {} : { signal: options.signal });
  return result.session;
}

function normalizeOrigin(input: string): string {
  let parsed: URL;
  try { parsed = new URL(input); } catch { throw new TypeError("origin must be an absolute HTTP(S) origin"); }
  if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.origin !== input || parsed.username !== "" || parsed.password !== "") {
    throw new TypeError("origin must be an absolute HTTP(S) origin without path, query, or credentials");
  }
  return parsed.origin;
}
