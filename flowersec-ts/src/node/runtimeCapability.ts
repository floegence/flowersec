import { defineRuntimeCapabilityDescriptorV2 } from "../v2/capability.js";

const nodeWebSocketTuples = [
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, sessionRole: "client" },
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "client" },
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "server" },
  { carrier: "websocket", datagrams: false, migration: false, networkMode: "listen", path: "direct", reliableStreams: true, sessionRole: "server" },
] as const;

export const NODE_RUNTIME_PROFILE_V2 = defineRuntimeCapabilityDescriptorV2(
  "node",
  [
    { carrier: "raw_quic", datagrams: true, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, sessionRole: "client" },
    { carrier: "raw_quic", datagrams: true, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "client" },
    { carrier: "raw_quic", datagrams: true, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "server" },
    { carrier: "raw_quic", datagrams: true, migration: false, networkMode: "listen", path: "direct", reliableStreams: true, sessionRole: "server" },
    ...nodeWebSocketTuples,
  ],
  [
    { carrier: "webtransport", reason: "node_webtransport_driver_unavailable" },
  ],
);

export function detectNodeRuntimeCapabilityV2(rawQuicAvailable: boolean) {
  if (rawQuicAvailable) return NODE_RUNTIME_PROFILE_V2;
  return defineRuntimeCapabilityDescriptorV2("node", nodeWebSocketTuples, [
    { carrier: "raw_quic", reason: "node_native_transport_unavailable" },
    { carrier: "webtransport", reason: "node_webtransport_driver_unavailable" },
  ]);
}
