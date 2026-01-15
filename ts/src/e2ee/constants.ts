export const HANDSHAKE_MAGIC = "FSEH";
export const RECORD_MAGIC = "FSEC";
export const PROTOCOL_VERSION = 1 as const;

export const HANDSHAKE_TYPE_INIT = 1 as const;
export const HANDSHAKE_TYPE_RESP = 2 as const;
export const HANDSHAKE_TYPE_ACK = 3 as const;

export const RECORD_FLAG_APP = 0 as const;
export const RECORD_FLAG_PING = 1 as const;
export const RECORD_FLAG_REKEY = 2 as const;

