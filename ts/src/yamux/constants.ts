export const YAMUX_VERSION = 0 as const;

export const TYPE_DATA = 0 as const;
export const TYPE_WINDOW_UPDATE = 1 as const;
export const TYPE_PING = 2 as const;
export const TYPE_GO_AWAY = 3 as const;

export const FLAG_SYN = 1 as const;
export const FLAG_ACK = 2 as const;
export const FLAG_FIN = 4 as const;
export const FLAG_RST = 8 as const;

export const DEFAULT_MAX_STREAM_WINDOW = 256 * 1024;

