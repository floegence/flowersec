import {
  defineRuntimeCapabilityDescriptorV2,
  type RuntimeCapabilityDescriptorV2,
  type UnsupportedRuntimeCarrierV2,
} from "../v2/capability.js";
import type { CarrierKind } from "../v2/contract.js";
import { hasWebTransportConstructorSurfaceV2 } from "../transport/webTransportAdapter.js";

export type BrowserRuntimeFeaturesV2 = Readonly<{
  WebSocket?: unknown;
  WebTransport?: unknown;
}>;

const tuples = Object.freeze([
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, sessionRole: "client" },
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "client" },
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "server" },
  { carrier: "webtransport", datagrams: true, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, sessionRole: "client" },
  { carrier: "webtransport", datagrams: true, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "client" },
  { carrier: "webtransport", datagrams: true, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "server" },
] as const);

export const BROWSER_RUNTIME_CAPABILITY_V2 = defineRuntimeCapabilityDescriptorV2(
  "browser",
  tuples,
  [{ carrier: "raw_quic", reason: "browser_no_raw_udp" }],
);

export function detectBrowserRuntimeCapabilityV2(
  runtime: BrowserRuntimeFeaturesV2 = globalThis as BrowserRuntimeFeaturesV2,
): RuntimeCapabilityDescriptorV2 {
  const available = new Set<CarrierKind>();
  if (typeof runtime.WebSocket === "function") available.add("websocket");
  if (hasWebTransportConstructorSurfaceV2(runtime.WebTransport)) available.add("webtransport");
  const unsupported: UnsupportedRuntimeCarrierV2[] = [{ carrier: "raw_quic", reason: "browser_no_raw_udp" }];
  if (!available.has("websocket")) {
    unsupported.push({ carrier: "websocket", reason: "browser_websocket_api_unavailable" });
  }
  if (!available.has("webtransport")) {
    unsupported.push({ carrier: "webtransport", reason: "browser_webtransport_api_unavailable" });
  }
  unsupported.sort((left, right) => left.carrier.localeCompare(right.carrier));
  return defineRuntimeCapabilityDescriptorV2(
    "browser",
    tuples.filter(({ carrier }) => available.has(carrier)),
    unsupported,
  );
}
