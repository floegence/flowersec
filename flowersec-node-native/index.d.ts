export type PathKind = "direct" | "tunnel";
/** Fixed SDK extension for configuring the original Node SQLite connection. */
export function sqliteExtensionPath(): string;
export interface NativePreparationLimits {
  readonly preauthInputBytes: number; readonly addressAttempts: number; readonly workUnits: number;
}
export interface NativePreparationUsage {
  readonly preauthInputBytes: number; readonly addressAttempts: number; readonly workUnits: number;
}
/** Only the native original budget factory creates accepted opaque handles. */
export interface NativeCandidatePreparationBudget { readonly nativePreparationHandle?: never }
export interface NativePreparationBudget {
  configure(limits: NativePreparationLimits): void;
  beginCandidate(limits: NativePreparationLimits): NativeCandidatePreparationBudget;
  usage(): NativePreparationUsage;
  close(): void;
}
export function createPreparationBudget(): NativePreparationBudget;
export type RawQuicConnectOptions = Readonly<{
  host: string; port: number; serverName: string; path: PathKind;
  tlsMode: "ca" | "pin"; trustRootsDer?: readonly Uint8Array[];
  activeLeafDerSha256?: readonly Uint8Array[];
  inboundBidirectionalStreamCapacity: number; readBufferBytes: number;
  datagramQueueBytes: number; handshakeTimeoutMs: number;
  preparationBudget?: NativeCandidatePreparationBudget;
}>;
export type RawQuicBindOptions = Readonly<{
  host: string; port: number; path: PathKind;
  certificateChainDer: readonly Uint8Array[]; privateKeyDer: Uint8Array;
  inboundBidirectionalStreamCapacity: number; readBufferBytes: number;
  datagramQueueBytes: number; handshakeTimeoutMs: number; pendingConnections: number;
  /** Dedicated one-candidate original owner; excludes shared capacity. */
  preparationBudget?: NativeCandidatePreparationBudget;
  /** Independent original network Prepare owner for each shared incoming. */
  incomingPreparationCapacity?: NativePreparationLimits;
}>;
export interface NativeOperation<T> { result(): Promise<T>; cancel(): void }
export interface NativeSubmission { completion(): Promise<void> }
export interface NativeStreamFailure extends Error {
  readonly source: "stream"; readonly reason: "normal_drained" | "direction_reset";
}
export interface RawQuicStream {
  read(maxBytes: number): NativeOperation<Uint8Array | null>;
  submit(data: Uint8Array): NativeSubmission | undefined;
  closeWrite(): Promise<void>;
  stopSending(reason?: "normal_drained"): Promise<void>;
  resetWrite(): Promise<void>;
  onWriteFailure(callback: (reason: "normal_drained" | "direction_reset") => void): () => void;
  waitTermination(): Promise<void>;
  abort(): void;
}
export interface RawQuicTLS {
  readonly version: "TLSv1.3";
  readonly alpn: "flowersec-direct/4" | "flowersec-tunnel/4";
  readonly earlyDataAccepted: false; readonly dedicatedConnection: true;
  readonly peerLeafDER: Uint8Array; readonly certificateVerified: boolean;
}
export interface RawQuicSession {
  readonly kind: "raw_quic"; readonly path: PathKind; readonly wireVersion: 4;
  readonly inboundBidirectionalStreamCapacity: number;
  /** End successful physical network Prepare once; repeat calls are harmless. */
  completePreparation(): void;
  tls(): RawQuicTLS;
  exportKeyingMaterial(length: number, label: string, context: Uint8Array): Uint8Array;
  localAddress(): Readonly<{ host: string; port: number }>;
  peerAddress(): Readonly<{ host: string; port: number }>;
  openStream(): NativeOperation<RawQuicStream>; acceptStream(): NativeOperation<RawQuicStream>;
  maxDatagramBytes(): number;
  receiveDatagram(maxBytes: number): NativeOperation<Uint8Array>;
  submitDatagram(data: Uint8Array): NativeSubmission | undefined;
  waitTermination(): Promise<void>; close(): Promise<void>; abort(): void;
}
export interface RawQuicListener {
  address(): Readonly<{ host: string; port: number }>;
  accept(): NativeOperation<RawQuicSession>;
  /** Seal new admission while existing connections retain their drain and cleanup owners. */
  stopAcceptingCurrent(): void;
  close(): Promise<void>; waitTermination(): Promise<void>; abort(): void;
}
export function contractVersion(): number;
export function connectRawQuic(options: RawQuicConnectOptions): NativeOperation<RawQuicSession>;
export function bindRawQuic(options: RawQuicBindOptions): Promise<RawQuicListener>;

export interface WebTransportRequest {
  readonly scheme: "https"; readonly authority: string; readonly path: string; readonly origin?: string;
  readonly tuple: "chromium_draft02" | "native_h3"; readonly protocol: "webtransport" | "webtransport-h3";
  readonly sessionFlowControl: false; readonly streamPrefixes: "rfc_webtransport"; readonly datagramContext: "rfc_h3_quarter_stream_id";
}
export interface WebTransportSession extends Omit<RawQuicSession, "kind" | "tls"> {
  readonly kind: "webtransport";
  tls(): Omit<RawQuicTLS, "alpn"> & Readonly<{ alpn: "h3" }>;
  request(): WebTransportRequest;
}
export interface WebTransportListener extends Omit<RawQuicListener, "accept"> {
  accept(): NativeOperation<WebTransportSession>;
}
export interface WebTransportBindOptions extends RawQuicBindOptions {
  readonly serverName: string;
  readonly connectPath: "/flowersec/webtransport/v4/direct" | "/flowersec/webtransport/v4/tunnel";
  readonly tuples: readonly ("chromium_draft02" | "native_h3")[];
  readonly allowedOrigins: readonly string[]; readonly allowAbsentOrigin: boolean;
  readonly headerBytes: number; readonly controlBytes: number;
}
export interface WebTransportConnectOptions extends RawQuicConnectOptions {
  readonly connectPath: "/flowersec/webtransport/v4/direct" | "/flowersec/webtransport/v4/tunnel";
  readonly tuple: "native_h3"; readonly headerBytes: number; readonly controlBytes: number;
}
export function bindWebTransport(options: WebTransportBindOptions): Promise<WebTransportListener>;
export function connectWebTransport(options: WebTransportConnectOptions): NativeOperation<WebTransportSession>;
