/** Version-bound transport identifiers shared by the v3 production paths. */
export const FLOWERSEC_V3_PROFILE = "flowersec/3" as const;

export const FLOWERSEC_V3_WIRE_PROFILES = Object.freeze({
  direct: "flowersec-direct/3",
  tunnel: "flowersec-tunnel/3",
} as const);

export const FLOWERSEC_V3_PATHS = Object.freeze({
  websocket: Object.freeze({
    direct: "/flowersec/v3/direct",
    tunnel: "/flowersec/v3/tunnel",
  }),
  webtransport: Object.freeze({
    direct: "/flowersec/webtransport/v3/direct",
    tunnel: "/flowersec/webtransport/v3/tunnel",
  }),
} as const);

export const FLOWERSEC_V3_WEBSOCKET_SUBPROTOCOLS = Object.freeze({
  direct: "flowersec.direct.v3",
  tunnel: "flowersec.tunnel.v3",
} as const);

export const FLOWERSEC_V3_ALPN = FLOWERSEC_V3_WIRE_PROFILES;

/** The strings below are the exact v3 inputs to the protocol KDF/MAC helpers. */
export const FLOWERSEC_V3_CRYPTO_LABELS = Object.freeze({
  handshake: "flowersec-v3-handshake\0",
  "server-finished": "flowersec v3 server finished",
  "client-finished": "flowersec v3 client finished",
  "epoch-zero": "flowersec v3 epoch zero",
  "control-root": "flowersec v3 control root",
  "stream-root": "flowersec v3 stream root",
  "setup-root": "flowersec v3 setup root",
  "rekey-root": "flowersec v3 rekey root",
  "next-epoch": "flowersec v3 next epoch",
  stream: "flowersec v3 stream",
  control: "flowersec v3 control",
  "record-key": "flowersec v3 record key",
  nonce: "flowersec v3 nonce",
  "unreliable-root": "flowersec v3 unreliable root",
  unreliable: "flowersec v3 unreliable",
  "unreliable-key": "flowersec v3 unreliable key",
  "unreliable-nonce": "flowersec v3 unreliable nonce",
  "unreliable-aad": "flowersec-v3-unreliable",
  "setup-mac": "flowersec-v3-setup\0",
  "record-aad": "flowersec-v3-record\0",
  open: "flowersec-v3-open\0",
} as const);

export function wireProfileForPathV3(path: "direct" | "tunnel"): string {
  return FLOWERSEC_V3_WIRE_PROFILES[path];
}

export function websocketSubprotocolForPathV3(path: "direct" | "tunnel"): string {
  return FLOWERSEC_V3_WEBSOCKET_SUBPROTOCOLS[path];
}

export function alpnForPathV3(path: "direct" | "tunnel"): string {
  return FLOWERSEC_V3_ALPN[path];
}
