export type PathKind = "direct" | "tunnel";

export type RawQuicConnectOptions = Readonly<{
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
  readonly wireVersion: 5;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly maxDatagramSize?: number;
  localAddress(): Readonly<{ host: string; port: number }>;
  peerAddress(): Readonly<{ host: string; port: number }>;
  openStream(): NativeOperation<RawQuicStream>;
  acceptStream(): NativeOperation<RawQuicStream>;
  sendDatagram(data: Uint8Array): "accepted" | "dropped_budget" | "dropped_carrier" | "too_large" | "unavailable";
  receiveDatagram(): NativeOperation<Uint8Array>;
  waitTermination(): Promise<void>;
  waitRemoteSessionClose(): Promise<boolean>;
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

export type WebTransportConnectOptions = Omit<RawQuicConnectOptions, "host" | "port" | "serverName"> & Readonly<{ url: string; origin: string }>;
export type WebTransportBindOptions = RawQuicBindOptions & Readonly<{ authorityHost: string; allowedOrigins: readonly string[] }>;
export interface WebTransportSession extends Omit<RawQuicSession, "kind" | "sendDatagram" | "localAddress" | "peerAddress"> {
  readonly kind: "webtransport";
  sendDatagram(data: Uint8Array): Promise<ReturnType<RawQuicSession["sendDatagram"]>>;
}
export interface WebTransportListener extends Omit<RawQuicListener, "accept"> {
  accept(): NativeOperation<WebTransportSession>;
}
export function connectWebTransport(options: WebTransportConnectOptions): NativeOperation<WebTransportSession>;
export function bindWebTransport(options: WebTransportBindOptions): Promise<WebTransportListener>;
