/** Version-bound transport identifiers shared by the v3 production paths. */
export const FLOWERSEC_V3_PROFILE = "flowersec/5" as const;

export const FLOWERSEC_V3_WIRE_PROFILES = Object.freeze({
  direct: "flowersec-direct/5",
  tunnel: "flowersec-tunnel/5",
} as const);

export const FLOWERSEC_V3_PATHS = Object.freeze({
  websocket: Object.freeze({
    direct: "/flowersec/v5/direct",
    tunnel: "/flowersec/v5/tunnel",
  }),
  webtransport: Object.freeze({
    direct: "/flowersec/webtransport/v5/direct",
    tunnel: "/flowersec/webtransport/v5/tunnel",
  }),
} as const);

export const FLOWERSEC_V3_WEBSOCKET_SUBPROTOCOLS = Object.freeze({
  direct: "flowersec.direct.v5",
  tunnel: "flowersec.tunnel.v5",
} as const);

export const FLOWERSEC_V3_ALPN = FLOWERSEC_V3_WIRE_PROFILES;

/** The strings below are the exact v3 inputs to the protocol KDF/MAC helpers. */
export const FLOWERSEC_V3_CRYPTO_LABELS = Object.freeze({
  "session-contract": "flowersec-v5-session-contract\0",
  candidates: "flowersec-v5-candidates\0",
  admission: "flowersec-v5-admission\0",
  "runtime-capability": "flowersec-v5-runtime-capability\0",
  handshake: "flowersec-v5-handshake\0",
  "server-finished": "flowersec v5 server finished",
  "client-finished": "flowersec v5 client finished",
  "epoch-zero": "flowersec v5 epoch zero",
  "control-root": "flowersec v5 control root",
  "stream-root": "flowersec v5 stream root",
  "setup-root": "flowersec v5 setup root",
  "rekey-root": "flowersec v5 rekey root",
  "next-epoch": "flowersec v5 next epoch",
  stream: "flowersec v5 stream",
  control: "flowersec v5 control",
  "record-key": "flowersec v5 record key",
  nonce: "flowersec v5 nonce",
  "unreliable-root": "flowersec v5 unreliable root",
  unreliable: "flowersec v5 unreliable",
  "unreliable-key": "flowersec v5 unreliable key",
  "unreliable-nonce": "flowersec v5 unreliable nonce",
  "unreliable-aad": "flowersec-v5-unreliable",
  "setup-mac": "flowersec-v5-setup\0",
  "record-aad": "flowersec-v5-record\0",
  open: "flowersec-v5-open\0",
  "acceptor-admissions": "flowersec-v5-acceptor-admissions\0",
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
