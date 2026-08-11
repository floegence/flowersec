import { defineRuntimeCapabilityDescriptorV2 } from "../v2/capability.js";

export const NODE_RUNTIME_CAPABILITY_V2 = defineRuntimeCapabilityDescriptorV2(
  "node",
  [
    { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "direct", reliableStreams: true, sessionRole: "client" },
    { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "client" },
    { carrier: "websocket", datagrams: false, migration: false, networkMode: "dial", path: "tunnel", reliableStreams: true, sessionRole: "server" },
  ],
  [
    { carrier: "raw_quic", reason: "node_raw_quic_driver_unavailable" },
    { carrier: "webtransport", reason: "node_webtransport_driver_unavailable" },
  ],
);
