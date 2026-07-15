import type { E2EE_Init } from "../gen/flowersec/e2ee/v1.gen.js";
import type { ChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as ControlRole, assertChannelInitGrant } from "../gen/flowersec/controlplane/v1.gen.js";
import { Role as TunnelRole, type Attach } from "../gen/flowersec/tunnel/v1.gen.js";
import { assertTunnelGrantContract, assertValidPSK, prepareChannelId } from "../client-connect/contract.js";
import { enforceTransportSecurity, type TransportSecurityPolicy } from "../client-connect/transportSecurity.js";
import { SDK_DEFAULTS } from "../defaults.js";
import { serverHandshake, ServerHandshakeCache, type Suite } from "../e2ee/handshake.js";
import { decodeHandshakeFrame } from "../e2ee/framing.js";
import { HANDSHAKE_TYPE_INIT, PROTOCOL_VERSION } from "../e2ee/constants.js";
import type { BinaryTransport } from "../e2ee/secureChannel.js";
import { readStreamHello, writeStreamHello } from "../streamhello/streamHello.js";
import { ByteReader } from "../yamux/byteReader.js";
import { YamuxSession, type YamuxLimits } from "../yamux/session.js";
import type { YamuxStream } from "../yamux/stream.js";
import { RpcServer, type RpcRouter, type RpcServerOptions } from "../rpc/server.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { AbortError, FlowersecError } from "../utils/errors.js";
import { WebSocketBinaryTransport, type WebSocketLike, type WebSocketLimits } from "../ws-client/binaryTransport.js";

export type { Suite } from "../e2ee/handshake.js";

export type EndpointPath = "direct" | "tunnel";

export type DirectHandshakeInit = Readonly<{
  channelId: string;
  version: number;
  suite: Suite;
  clientFeatures: number;
}>;

export type DirectHandshakeCredential = Readonly<{
  psk: Uint8Array | string;
  initExpireAtUnixS: number;
  commitAuthenticated?: () => void | Promise<void>;
}>;

export type DirectCredentialResolver = (
  init: DirectHandshakeInit,
) => DirectHandshakeCredential | Promise<DirectHandshakeCredential>;

export type EndpointOptions = Readonly<{
  signal?: AbortSignal;
  handshakeTimeoutMs?: number;
  handshakeClockSkewMs?: number;
  serverFeatures?: number;
  maxHandshakePayload?: number;
  maxRecordBytes?: number;
  maxBufferedBytes?: number;
  maxOutboundBufferedBytes?: number;
  outboundRecordChunkBytes?: number;
  webSocketLimits?: Partial<WebSocketLimits>;
  yamuxLimits?: Partial<YamuxLimits>;
  handshakeCache?: ServerHandshakeCache;
}>;

export type DirectAcceptOptions = EndpointOptions &
  Readonly<{
    secureTransport?: boolean;
    transportSecurityPolicy?: TransportSecurityPolicy;
  }>;

export type TunnelEndpointOptions = EndpointOptions &
  Readonly<{
    origin: string;
    connectTimeoutMs?: number;
    endpointInstanceId?: string;
    wsFactory: (url: string, origin: string) => WebSocketLike;
    transportSecurityPolicy?: TransportSecurityPolicy;
  }>;

export type EndpointStream = Readonly<{
  kind: string;
  stream: YamuxStream;
}>;

type StreamWaiter = {
  resolve: (stream: YamuxStream) => void;
  reject: (error: Error) => void;
  signal?: AbortSignal;
  onAbort?: () => void;
};

export class Session {
  readonly path: EndpointPath;
  readonly endpointInstanceId: string | undefined;
  private readonly streams: YamuxStream[] = [];
  private readonly waiters: StreamWaiter[] = [];
  private terminalError: Error | undefined;

  private constructor(
    path: EndpointPath,
    private readonly secure: Awaited<ReturnType<typeof serverHandshake>>,
    private readonly mux: YamuxSession,
    endpointInstanceId?: string,
  ) {
    this.path = path;
    this.endpointInstanceId = endpointInstanceId;
  }

  static create(
    path: EndpointPath,
    secure: Awaited<ReturnType<typeof serverHandshake>>,
    options: Readonly<{ yamuxLimits?: Partial<YamuxLimits>; endpointInstanceId?: string }> = {},
  ): Session {
    let session!: Session;
    const mux = new YamuxSession(
      {
        read: () => secure.read(),
        write: (bytes) => secure.write(bytes),
        close: () => secure.close(),
      },
      {
        client: false,
        ...(options.yamuxLimits === undefined ? {} : { limits: options.yamuxLimits }),
        onIncomingStream: (stream) => session.pushStream(stream),
        onTerminal: (error) => session.fail(error),
      },
    );
    session = new Session(path, secure, mux, options.endpointInstanceId);
    return session;
  }

  async openStream(kind: string, options: Readonly<{ signal?: AbortSignal }> = {}): Promise<YamuxStream> {
    const stream = await this.mux.openStream(options);
    try {
      await writeStreamHello((bytes) => stream.write(bytes), normalizeStreamKind(kind, this.path));
      return stream;
    } catch (error) {
      await stream.reset(asError(error));
      throw new FlowersecError({ path: this.path, stage: "rpc", code: "stream_hello_failed", message: "failed to write stream hello", cause: error });
    }
  }

  async acceptStream(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<EndpointStream> {
    const stream = await this.acceptRawStream(options.signal);
    try {
      const reader = new ByteReader(() => stream.read());
      const hello = await readStreamHello((length) => reader.readExactly(length));
      return { kind: hello.kind, stream };
    } catch (error) {
      await stream.reset(asError(error));
      throw new FlowersecError({ path: this.path, stage: "rpc", code: "stream_hello_failed", message: "failed to read stream hello", cause: error });
    }
  }

  async serveRPC(router: RpcRouter, options: RpcServerOptions & Readonly<{ signal?: AbortSignal }> = {}): Promise<void> {
    while (true) {
      const accepted = await this.acceptStream(options.signal === undefined ? {} : { signal: options.signal });
      if (accepted.kind !== "rpc") {
        await accepted.stream.reset(new Error(`unexpected stream kind ${accepted.kind}`));
        continue;
      }
      const reader = new ByteReader(() => accepted.stream.read());
      const server = new RpcServer(
        {
          readExactly: (length) => reader.readExactly(length),
          write: (bytes) => accepted.stream.write(bytes),
          close: (error) => { void accepted.stream.reset(asError(error)); },
        },
        options,
        router,
      );
      await server.serve(options.signal);
      return;
    }
  }

  probeLiveness(timeoutMs = SDK_DEFAULTS.transport.handshakeTimeoutMs): Promise<number> {
    return this.mux.probeLiveness(timeoutMs);
  }

  close(): void {
    this.fail(new Error("endpoint session closed"));
    this.mux.close();
    this.secure.close();
  }

  private pushStream(stream: YamuxStream): void {
    const waiter = this.waiters.shift();
    if (waiter == null) {
      this.streams.push(stream);
      return;
    }
    cleanupWaiter(waiter);
    waiter.resolve(stream);
  }

  private acceptRawStream(signal?: AbortSignal): Promise<YamuxStream> {
    if (signal?.aborted) return Promise.reject(new AbortError("accept stream aborted"));
    if (this.terminalError != null) return Promise.reject(this.terminalError);
    const stream = this.streams.shift();
    if (stream != null) return Promise.resolve(stream);
    return new Promise<YamuxStream>((resolve, reject) => {
      const waiter: StreamWaiter = { resolve, reject, ...(signal === undefined ? {} : { signal }) };
      waiter.onAbort = () => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        cleanupWaiter(waiter);
        reject(new AbortError("accept stream aborted"));
      };
      signal?.addEventListener("abort", waiter.onAbort, { once: true });
      this.waiters.push(waiter);
    });
  }

  private fail(error: Error): void {
    if (this.terminalError != null) return;
    this.terminalError = error;
    for (const waiter of this.waiters.splice(0)) {
      cleanupWaiter(waiter);
      waiter.reject(error);
    }
  }
}

export async function acceptDirect(
  websocket: WebSocketLike,
  handshake: Readonly<{ channelId: string; suite: Suite }> & DirectHandshakeCredential,
  options: DirectAcceptOptions = {},
): Promise<Session> {
  await enforceIncomingDirectTransport(options);
  const transport = new WebSocketBinaryTransport(websocket, webSocketTransportOptions(options));
  return await establishSession("direct", transport, handshake, options);
}

export async function acceptDirectResolved(
  websocket: WebSocketLike,
  resolver: DirectCredentialResolver,
  options: DirectAcceptOptions = {},
): Promise<Session> {
  await enforceIncomingDirectTransport(options);
  const transport = new WebSocketBinaryTransport(websocket, webSocketTransportOptions(options));
  const first = await transport.readBinary(readOptions(options));
  let init: E2EE_Init;
  try {
    const decoded = decodeHandshakeFrame(first, options.maxHandshakePayload ?? SDK_DEFAULTS.e2ee.maxHandshakePayloadBytes);
    if (decoded.handshakeType !== HANDSHAKE_TYPE_INIT) throw new Error("expected handshake init");
    init = JSON.parse(new TextDecoder().decode(decoded.payloadJsonUtf8)) as E2EE_Init;
    if (init.version !== PROTOCOL_VERSION || init.role !== 1 || (init.suite !== 1 && init.suite !== 2)) throw new Error("invalid handshake init");
  } catch (error) {
    transport.close();
    throw new FlowersecError({ path: "direct", stage: "handshake", code: "handshake_failed", message: "invalid handshake init", cause: error });
  }

  let credential: DirectHandshakeCredential;
  try {
    credential = await resolver({
      channelId: prepareChannelId(init.channel_id, "direct"),
      version: init.version,
      suite: init.suite,
      clientFeatures: init.client_features >>> 0,
    });
  } catch (error) {
    transport.close();
    throw new FlowersecError({ path: "direct", stage: "validate", code: "resolve_failed", message: "credential resolution failed", cause: error });
  }

  const replay = new PrefetchedTransport(transport, first);
  return await establishSession("direct", replay, {
    channelId: init.channel_id,
    suite: init.suite,
    ...credential,
  }, options);
}

export async function connectTunnel(
  grantInput: unknown,
  options: TunnelEndpointOptions,
): Promise<Session> {
  let grant: ChannelInitGrant;
  try {
    grant = assertChannelInitGrant(unwrapServerGrant(grantInput));
  } catch (error) {
    throw new FlowersecError({ path: "tunnel", stage: "validate", code: "invalid_input", message: "invalid ChannelInitGrant", cause: error });
  }
  assertTunnelGrantContract(grant, ControlRole.Role_server);
  const tunnelUrl = grant.tunnel_url.trim();
  if (tunnelUrl === "") throw new FlowersecError({ path: "tunnel", stage: "validate", code: "missing_tunnel_url", message: "missing tunnel_url" });
  if (grant.token.trim() === "") throw new FlowersecError({ path: "tunnel", stage: "validate", code: "missing_token", message: "missing token" });
  if (grant.channel_init_expire_at_unix_s <= 0) throw new FlowersecError({ path: "tunnel", stage: "validate", code: "missing_init_exp", message: "missing channel init expiry" });
  const origin = options.origin.trim();
  if (origin === "") throw new FlowersecError({ path: "tunnel", stage: "validate", code: "missing_origin", message: "missing origin" });
  await enforceTransportSecurity({ rawUrl: tunnelUrl, path: "tunnel", ...(options.transportSecurityPolicy === undefined ? {} : { policy: options.transportSecurityPolicy }) });

  const endpointInstanceId = normalizeEndpointInstanceId(options.endpointInstanceId);
  const websocket = options.wsFactory(tunnelUrl, origin);
  const transport = new WebSocketBinaryTransport(websocket, webSocketTransportOptions(options));
  try {
    await waitForOpen(websocket, options.connectTimeoutMs ?? SDK_DEFAULTS.transport.connectTimeoutMs, options.signal);
    const attach: Attach = {
      v: 1,
      channel_id: prepareChannelId(grant.channel_id, "tunnel"),
      role: TunnelRole.Role_server,
      token: grant.token.trim(),
      endpoint_instance_id: endpointInstanceId,
    };
    websocket.send(JSON.stringify(attach));
    return await establishSession("tunnel", transport, {
      channelId: grant.channel_id,
      suite: grant.default_suite,
      psk: assertValidPSK(grant.e2ee_psk_b64u, "tunnel"),
      initExpireAtUnixS: grant.channel_init_expire_at_unix_s,
    }, options, endpointInstanceId);
  } catch (error) {
    transport.close();
    if (error instanceof FlowersecError) throw error;
    throw new FlowersecError({ path: "tunnel", stage: "connect", code: "dial_failed", message: "endpoint tunnel connect failed", cause: error });
  }
}

async function establishSession(
  path: EndpointPath,
  transport: BinaryTransport,
  handshake: Readonly<{ channelId: string; suite: Suite }> & DirectHandshakeCredential,
  options: EndpointOptions,
  endpointInstanceId?: string,
): Promise<Session> {
  let psk: Uint8Array;
  try {
    psk = normalizePSK(handshake.psk, path);
  } catch (error) {
    transport.close();
    throw error;
  }
  try {
    const secure = await serverHandshake(transport, options.handshakeCache ?? new ServerHandshakeCache(), {
      channelId: prepareChannelId(handshake.channelId, path),
      suite: handshake.suite,
      psk,
      serverFeatures: options.serverFeatures ?? 0,
      initExpireAtUnixS: handshake.initExpireAtUnixS,
      clockSkewSeconds: Math.ceil((options.handshakeClockSkewMs ?? SDK_DEFAULTS.transport.handshakeClockSkewMs) / 1000),
      maxHandshakePayload: options.maxHandshakePayload ?? SDK_DEFAULTS.e2ee.maxHandshakePayloadBytes,
      maxRecordBytes: options.maxRecordBytes ?? SDK_DEFAULTS.e2ee.maxRecordBytes,
      outboundRecordChunkBytes: options.outboundRecordChunkBytes ?? SDK_DEFAULTS.e2ee.outboundRecordChunkBytes,
      maxBufferedBytes: options.maxBufferedBytes ?? SDK_DEFAULTS.e2ee.maxOutboundBufferedBytes,
      maxOutboundBufferedBytes: options.maxOutboundBufferedBytes ?? SDK_DEFAULTS.e2ee.maxOutboundBufferedBytes,
      timeoutMs: options.handshakeTimeoutMs ?? SDK_DEFAULTS.transport.handshakeTimeoutMs,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    try {
      await handshake.commitAuthenticated?.();
    } catch (error) {
      secure.close();
      throw new FlowersecError({ path, stage: "handshake", code: "credential_commit_failed", message: "credential commit failed", cause: error });
    }
    return Session.create(path, secure, {
      ...(options.yamuxLimits === undefined ? {} : { yamuxLimits: options.yamuxLimits }),
      ...(endpointInstanceId === undefined ? {} : { endpointInstanceId }),
    });
  } catch (error) {
    transport.close();
    if (error instanceof FlowersecError) throw error;
    throw new FlowersecError({ path, stage: "handshake", code: "handshake_failed", message: "endpoint handshake failed", cause: error });
  } finally {
    psk.fill(0);
  }
}

class PrefetchedTransport implements BinaryTransport {
  private first: Uint8Array | undefined;

  constructor(private readonly inner: BinaryTransport, first: Uint8Array) {
    this.first = first;
  }

  readBinary(options?: Readonly<{ signal?: AbortSignal; timeoutMs?: number }>): Promise<Uint8Array> {
    if (this.first != null) {
      const first = this.first;
      this.first = undefined;
      return Promise.resolve(first);
    }
    return this.inner.readBinary(options);
  }

  writeBinary(frame: Uint8Array, options?: Readonly<{ signal?: AbortSignal }>): Promise<void> {
    return this.inner.writeBinary(frame, options);
  }

  close(): void {
    this.inner.close();
  }
}

function normalizePSK(input: Uint8Array | string, path: EndpointPath): Uint8Array {
  try {
    const psk = typeof input === "string" ? base64urlDecode(input.trim()) : input.slice();
    if (psk.length !== 32) throw new Error("psk must be 32 bytes");
    return psk;
  } catch (error) {
    throw new FlowersecError({ path, stage: "validate", code: "invalid_psk", message: "invalid psk", cause: error });
  }
}

function normalizeEndpointInstanceId(input: string | undefined): string {
  const value = input ?? randomEndpointInstanceId();
  try {
    const bytes = base64urlDecode(value);
    if (bytes.length < 16 || bytes.length > 32) throw new Error("endpoint instance ID must decode to 16..32 bytes");
  } catch (error) {
    throw new FlowersecError({ path: "tunnel", stage: "validate", code: "invalid_endpoint_instance_id", message: "invalid endpoint instance ID", cause: error });
  }
  return value;
}

function randomEndpointInstanceId(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}

function normalizeStreamKind(kind: string, path: EndpointPath): string {
  const value = kind.trim();
  if (value === "") throw new FlowersecError({ path, stage: "validate", code: "missing_stream_kind", message: "missing stream kind" });
  return value;
}

function unwrapServerGrant(input: unknown): unknown {
  if (typeof input !== "object" || input == null || Array.isArray(input)) return input;
  const record = input as Record<string, unknown>;
  return record["grant_server"] ?? input;
}

function webSocketTransportOptions(options: EndpointOptions): Readonly<{ webSocketLimits?: Partial<WebSocketLimits> }> {
  return options.webSocketLimits === undefined ? {} : { webSocketLimits: options.webSocketLimits };
}

function readOptions(options: EndpointOptions): Readonly<{ signal?: AbortSignal; timeoutMs?: number }> {
  return {
    timeoutMs: options.handshakeTimeoutMs ?? SDK_DEFAULTS.transport.handshakeTimeoutMs,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  };
}

async function enforceIncomingDirectTransport(options: DirectAcceptOptions): Promise<void> {
  const rawUrl = options.secureTransport === false ? "ws://127.0.0.1/" : "wss://127.0.0.1/";
  await enforceTransportSecurity({ rawUrl, path: "direct", ...(options.transportSecurityPolicy === undefined ? {} : { policy: options.transportSecurityPolicy }) });
}

function waitForOpen(websocket: WebSocketLike, timeoutMs: number, signal?: AbortSignal): Promise<void> {
  if (websocket.readyState === 1) return Promise.resolve();
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) return Promise.reject(new RangeError("connectTimeoutMs must be non-negative"));
  return new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (timer != null) clearTimeout(timer);
      websocket.removeEventListener("open", onOpen);
      websocket.removeEventListener("error", onError);
      websocket.removeEventListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const finish = (error?: Error) => {
      cleanup();
      if (error == null) resolve(); else reject(error);
    };
    const onOpen = () => finish();
    const onError = () => finish(new Error("websocket open failed"));
    const onClose = () => finish(new Error("websocket closed before open"));
    const onAbort = () => finish(new AbortError("connect aborted"));
    websocket.addEventListener("open", onOpen);
    websocket.addEventListener("error", onError);
    websocket.addEventListener("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (timeoutMs > 0) timer = setTimeout(() => finish(new Error("websocket open timeout")), timeoutMs);
  });
}

function cleanupWaiter(waiter: StreamWaiter): void {
  if (waiter.onAbort != null) waiter.signal?.removeEventListener("abort", waiter.onAbort);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
