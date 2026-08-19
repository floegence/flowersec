export type PathKind = "direct" | "tunnel";

export type RawQuicConnectOptions = Readonly<{
  host: string;
  port: number;
  serverName: string;
  path: PathKind;
  trustRootsDer: readonly Uint8Array[];
  inboundBidirectionalStreamCapacity: number;
  handshakeTimeoutMs: number;
}>;

export type RawQuicConnectOptionsV3 = Readonly<{
  host: string;
  port: number;
  serverName: string;
  path: PathKind;
  tlsMode: "ca" | "pin";
  trustRootsDer?: readonly Uint8Array[];
  activeLeafDerSha256?: readonly Uint8Array[];
  inboundBidirectionalStreamCapacity: number;
  handshakeTimeoutMs: number;
}>;

export type RawQuicBindOptions = Readonly<{
  host: string;
  port: number;
  path: PathKind;
  certificateChainDer: readonly Uint8Array[];
  privateKeyDer: Uint8Array;
  inboundBidirectionalStreamCapacity: number;
  handshakeTimeoutMs?: number;
}>;

export interface NativeOperation<T> {
  result(): Promise<T>;
  cancel(): void;
}

export interface RawQuicStream {
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<number>;
  closeWrite(): Promise<void>;
  stopSending(): Promise<void>;
  reset(): Promise<void>;
  cancelPending(): void;
  abort(): void;
}

export interface RawQuicSession {
  readonly kind: "raw_quic";
  readonly path: PathKind;
  readonly wireVersion: 2 | 3;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly maxDatagramSize?: number;
  localAddress(): Readonly<{ host: string; port: number }>;
  peerAddress(): Readonly<{ host: string; port: number }>;
  openStream(): NativeOperation<RawQuicStream>;
  acceptStream(): NativeOperation<RawQuicStream>;
  sendDatagram(data: Uint8Array): "accepted" | "dropped_budget" | "dropped_carrier" | "too_large" | "unavailable";
  receiveDatagram(): NativeOperation<Uint8Array>;
  waitTermination(): Promise<void>;
  close(code?: number, reason?: string): Promise<void>;
  abort(): void;
}

export interface RawQuicListener {
  address(): Readonly<{ host: string; port: number }>;
  accept(): NativeOperation<RawQuicSession>;
  close(): Promise<void>;
  abort(): void;
}

export function contractVersion(): number;
export function connectRawQuic(options: RawQuicConnectOptions): NativeOperation<RawQuicSession>;
export function bindRawQuic(options: RawQuicBindOptions): Promise<RawQuicListener>;
export function connectRawQuicV3(options: RawQuicConnectOptionsV3): NativeOperation<RawQuicSession>;
export function bindRawQuicV3(options: RawQuicBindOptions): Promise<RawQuicListener>;
