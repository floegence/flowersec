import { createRequire } from "node:module";

/** The native ABI is a current carrier contract, independent of wire records.
 * Version 4 adds actual TLS evidence, bounded reads, submission receipts and
 * stream termination. A previous ABI cannot supply these facts. */
export const nativeTransportContractVersion = 4;
export interface NativePreparationLimits { readonly preauthInputBytes: number; readonly addressAttempts: number; readonly workUnits: number }
export interface NativePreparationUsage { readonly preauthInputBytes: number; readonly addressAttempts: number; readonly workUnits: number }
/** Opaque original external handle; only the native budget factory can create
 * an accepted instance. A JavaScript object cannot assert prepaid usage. */
export interface NativeCandidatePreparationBudget { readonly nativePreparationHandle?: never }
export interface NativePreparationBudget {
  configure(limits: NativePreparationLimits): void;
  beginCandidate(limits: NativePreparationLimits): NativeCandidatePreparationBudget;
  usage(): NativePreparationUsage;
  close(): void;
}
export interface NativeOperation<T> { result(): Promise<T>; cancel(): void }
export interface NativeSubmission { completion(): Promise<void> }
export interface NativeStreamFailure extends Error { readonly source: "stream"; readonly reason: "normal_drained" | "direction_reset" }
export interface NativeRawStream {
  read(maxBytes: number): NativeOperation<Uint8Array | null>;
  /** All-or-none admission. Undefined or a throw means no native byte borrow.
   * A returned receipt transfers the borrow until its actual completion; the
   * receipt's completion accessor must return the original native task. */
  submit(data: Uint8Array): NativeSubmission | undefined;
  closeWrite(): Promise<void>;
  stopSending(reason?: "normal_drained"): Promise<void>;
  resetWrite(): Promise<void>;
  onWriteFailure(callback: (reason: "normal_drained" | "direction_reset") => void): () => void;
  waitTermination(): Promise<void>;
  abort(): void;
}
export interface NativeRawTLS {
  readonly version: "TLSv1.3";
  readonly alpn: "flowersec-direct/4" | "flowersec-tunnel/4" | "h3";
  readonly earlyDataAccepted: false;
  readonly dedicatedConnection: true;
  readonly peerLeafDER: Uint8Array;
  readonly certificateVerified: boolean;
}
export interface NativeRawSession {
  readonly kind: "raw_quic" | "webtransport";
  readonly wireVersion: 4;
  readonly path: "direct" | "tunnel";
  readonly inboundBidirectionalStreamCapacity: number;
  completePreparation?(): void;
  tls(): NativeRawTLS;
  exportKeyingMaterial(length: number, label: string, context: Uint8Array): Uint8Array;
  /** Complete native Flowersec envelope MTU; zero means unavailable. */
  maxDatagramBytes(): number;
  /** One actual bounded native read. Cancel requests termination and result()
   * settles only after its original receive task has stopped borrowing. */
  receiveDatagram(maxBytes: number): NativeOperation<Uint8Array>;
  /** All-or-none native queue admission, retaining bytes through completion. */
  submitDatagram(bytes: Uint8Array): NativeSubmission | undefined;
  openStream(): NativeOperation<NativeRawStream>;
  acceptStream(): NativeOperation<NativeRawStream>;
  localAddress(): Readonly<{ host: string; port: number }>;
  peerAddress(): Readonly<{ host: string; port: number }>;
  close(): Promise<void>;
  waitTermination(): Promise<void>;
  abort(): void;
}
export interface NativeRawConnectOptions {
  readonly host: string;
  readonly port: number;
  readonly serverName: string;
  readonly path: "direct" | "tunnel";
  readonly inboundBidirectionalStreamCapacity: number;
  readonly readBufferBytes: number;
  readonly datagramQueueBytes: number;
  readonly handshakeTimeoutMs: number;
  readonly preparationBudget?: NativeCandidatePreparationBudget;
  readonly tlsMode: "ca" | "pin";
  readonly trustRootsDer?: readonly Uint8Array[];
  readonly activeLeafDerSha256?: readonly Uint8Array[];
}
export interface NativeRawBindOptions {
  readonly host: string;
  readonly port: number;
  readonly path: "direct" | "tunnel";
  readonly certificateChainDer: readonly Uint8Array[];
  readonly privateKeyDer: Uint8Array;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly readBufferBytes: number;
  readonly datagramQueueBytes: number;
  readonly handshakeTimeoutMs: number;
  readonly pendingConnections: number;
  readonly preparationBudget?: NativeCandidatePreparationBudget;
  /** Independent original budget for each incoming/CID of a shared listener. */
  readonly incomingPreparationCapacity?: NativePreparationLimits;
}
export interface NativeRawListener {
  address(): Readonly<{ host: string; port: number }>;
  accept(): NativeOperation<NativeRawSession>;
  /** Seal new ingress while established sessions retain their native owner. */
  stopAcceptingCurrent(): void;
  close(): Promise<void>;
  waitTermination(): Promise<void>;
  abort(): void;
}
/** Original CONNECT metadata from the native H3 owner. Prefixes and context
 * remain native; no application callback can replace this transport evidence. */
export interface NativeWebTransportRequest {
  readonly scheme: "https"; readonly authority: string; readonly path: string;
  readonly origin?: string;
  readonly tuple: "chromium_draft02" | "native_h3";
  readonly protocol: "webtransport" | "webtransport-h3";
  readonly sessionFlowControl: false;
  readonly streamPrefixes: "rfc_webtransport";
  readonly datagramContext: "rfc_h3_quarter_stream_id";
}
export interface NativeWebTransportSession extends NativeRawSession {
  readonly kind: "webtransport";
  /** One immutable bounded copy; never synthesized from caller options. */
  request(): NativeWebTransportRequest;
}
export interface NativeWebTransportConnectOptions extends NativeRawConnectOptions {
  readonly connectPath: "/flowersec/webtransport/v4/direct" | "/flowersec/webtransport/v4/tunnel";
  readonly tuple: "native_h3";
  readonly headerBytes: number; readonly controlBytes: number;
}
export interface NativeWebTransportBindOptions extends NativeRawBindOptions {
  readonly serverName: string;
  readonly connectPath: "/flowersec/webtransport/v4/direct" | "/flowersec/webtransport/v4/tunnel";
  readonly tuples: readonly ("chromium_draft02" | "native_h3")[];
  readonly allowedOrigins: readonly string[]; readonly allowAbsentOrigin: boolean;
  readonly headerBytes: number; readonly controlBytes: number;
}
export interface NativeWebTransportListener extends Omit<NativeRawListener, "accept"> {
  accept(): NativeOperation<NativeWebTransportSession>;
}
export interface NativeTransportBinding {
  contractVersion(): number;
  createPreparationBudget?(): NativePreparationBudget;
  /** Copies every configuration field and TLS byte array synchronously,
   * before returning. Caller configuration is never borrowed by a native tail. */
  connectRawQuic(options: NativeRawConnectOptions): NativeOperation<NativeRawSession>;
  /** Copies every configuration field, certificate and private-key byte array
   * synchronously, before returning the actual bind task. */
  bindRawQuic(options: NativeRawBindOptions): Promise<NativeRawListener>;
  /** Original native H3 CONNECT task; no fallback, retries or pooling. */
  connectWebTransport(options: NativeWebTransportConnectOptions): NativeOperation<NativeWebTransportSession>;
  /** Validate the complete finite tuple and configured Origin before accept.
   * Each accepted session retains a dedicated H3/QUIC physical owner. */
  bindWebTransport(options: NativeWebTransportBindOptions): Promise<NativeWebTransportListener>;
}
export class NativeTransportUnavailableError extends Error {
  readonly code = "native_transport_unavailable";
  constructor() { super("native_transport_unavailable"); this.name = "NativeTransportUnavailableError"; }
}
/** Always select the product's installed current native provider. */
export function loadCurrentNativeTransport(): NativeTransportBinding {
  let candidate: Partial<NativeTransportBinding>;
  try { candidate = createRequire(import.meta.url)("@floegence/flowersec-node-native") as Partial<NativeTransportBinding>; }
  catch { throw new NativeTransportUnavailableError(); }
  if (candidate === null || typeof candidate !== "object" || typeof candidate.contractVersion !== "function" ||
      candidate.contractVersion() !== nativeTransportContractVersion || typeof candidate.connectRawQuic !== "function" || typeof candidate.bindRawQuic !== "function") throw new NativeTransportUnavailableError();
  return candidate as NativeTransportBinding;
}

/** Select WT separately so existing raw-only ABI4 remains usable for raw QUIC.
 * No presence check here is evidence that H3 negotiation actually succeeded. */
export function loadCurrentNativeWebTransport(): NativeTransportBinding {
  const binding = loadCurrentNativeTransport();
  if (typeof binding.connectWebTransport !== "function" || typeof binding.bindWebTransport !== "function") throw new NativeTransportUnavailableError();
  return binding;
}

/** Shared pure-byte native listener path. WT settings/header bounds remain
 * native-owned and are reserved before bind, with no application overrides. */
export function bindCurrentNativeListener(binding: NativeTransportBinding, options: NativeRawBindOptions, serverName: string,
  webTransport?: Readonly<{ headerBytes: number; controlBytes: number; tuples: readonly ("chromium_draft02" | "native_h3")[]; allowedOrigins: readonly string[]; allowAbsentOrigin: boolean }>): Promise<NativeRawListener> {
  return webTransport === undefined ? binding.bindRawQuic(options) : binding.bindWebTransport({ ...options, serverName,
    connectPath: options.path === "direct" ? "/flowersec/webtransport/v4/direct" : "/flowersec/webtransport/v4/tunnel", ...webTransport });
}
