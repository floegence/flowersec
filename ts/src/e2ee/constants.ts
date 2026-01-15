// Handshake header prefix.
export const HANDSHAKE_MAGIC = "FSEH";
// Record header prefix.
export const RECORD_MAGIC = "FSEC";
// Wire-format version for E2EE framing.
export const PROTOCOL_VERSION = 1 as const;

// Client->server init.
export const HANDSHAKE_TYPE_INIT = 1 as const;
// Server response with ephemeral key and nonce.
export const HANDSHAKE_TYPE_RESP = 2 as const;
// Client ack with auth tag.
export const HANDSHAKE_TYPE_ACK = 3 as const;

// Application payload record.
export const RECORD_FLAG_APP = 0 as const;
// Keepalive record.
export const RECORD_FLAG_PING = 1 as const;
// Rekey record.
export const RECORD_FLAG_REKEY = 2 as const;
