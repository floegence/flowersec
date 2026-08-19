import { YamuxSession, type ByteDuplex } from "../yamux/session.js";
import type { YamuxStream } from "../yamux/stream.js";
import { CarrierError, type CarrierSessionV3, type CarrierStreamV3 } from "./carrier.js";
import type { OperationOptionsV3, PathKind } from "./contract.js";

export type WebSocketBinaryTransportV3 = Readonly<{
  readBinary(options?: Readonly<{ signal?: AbortSignal; timeoutMs?: number }>): Promise<Uint8Array>;
  writeBinary(data: Uint8Array, options?: OperationOptionsV3): Promise<void>;
  flush(options?: OperationOptionsV3): Promise<void>;
  close(): void;
}>;

export type WebSocketResourcePolicyV3 = Readonly<{
  maxConcurrentStreams?: number;
  maxFrameBytes?: number;
  preferredWriteBytes?: number;
  maxStreamWriteQueueBytes?: number;
  maxStreamReceiveBytes?: number;
  maxSessionReceiveBytes?: number;
}>;

export function createWebSocketCarrierSessionV3(
  transport: WebSocketBinaryTransportV3,
  options: Readonly<{
    path: PathKind;
    client: boolean;
    inboundBidirectionalStreamCapacity: number;
    resourcePolicy?: WebSocketResourcePolicyV3;
  }>,
): CarrierSessionV3 {
  return new WebSocketYamuxCarrierSession(transport, options);
}

export function createServerWebSocketCarrierSessionV3(
  transport: WebSocketBinaryTransportV3,
  options: Readonly<{
    path: PathKind;
    inboundBidirectionalStreamCapacity: number;
    resourcePolicy?: WebSocketResourcePolicyV3;
  }>,
): CarrierSessionV3 {
  requireCapacity(options.inboundBidirectionalStreamCapacity);
  const carrier = new ServerWebSocketAdmissionCarrier(transport, options);
  serverAdmissionCarriers.set(carrier, carrier);
  return carrier;
}

const serverAdmissionCarriers = new WeakMap<CarrierSessionV3, ServerWebSocketAdmissionCarrier>();

export function configureServerWebSocketCarrierRoleV3(carrier: CarrierSessionV3, client: boolean): void {
  const server = serverAdmissionCarriers.get(carrier);
  if (server === undefined) throw new CarrierError("closed", "WebSocket carrier is not a server admission carrier");
  server.configureRole(client);
}

class ServerWebSocketAdmissionCarrier implements CarrierSessionV3 {
  readonly kind = "websocket" as const;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams = undefined;

  private admissionAvailable = true;
  private active: CarrierSessionV3 | undefined;
  private closed = false;
  private client = false;

  constructor(
    private readonly transport: WebSocketBinaryTransportV3,
    private readonly options: Readonly<{
      path: PathKind;
      inboundBidirectionalStreamCapacity: number;
      resourcePolicy?: WebSocketResourcePolicyV3;
    }>,
  ) {
    this.path = options.path;
    this.inboundBidirectionalStreamCapacity = options.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return await this.activate().openStream(options);
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    throwIfAborted(options.signal);
    if (this.closed) throw new CarrierError("closed", "WebSocket carrier is closed");
    if (this.admissionAvailable) {
      this.admissionAvailable = false;
      return new WebSocketAdmissionStream(this.transport);
    }
    return await this.activate().acceptStream(options);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.active === undefined) this.transport.close();
    else await this.active.close();
  }

  abort(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.active === undefined) this.transport.close();
    else this.active.abort();
  }

  async waitTermination(): Promise<void> {
    if (this.closed && this.active === undefined) return;
    await this.activate().waitTermination();
  }

  configureRole(client: boolean): void {
    if (this.closed || this.active !== undefined) throw new CarrierError("closed", "WebSocket carrier is already active");
    this.client = client;
  }

  private activate(): CarrierSessionV3 {
    if (this.closed) throw new CarrierError("closed", "WebSocket carrier is closed");
    if (this.admissionAvailable) {
      throw new CarrierError("closed", "WebSocket admission has not completed");
    }
    this.active ??= createWebSocketCarrierSessionV3(this.transport, {
      path: this.options.path,
      client: this.client,
      inboundBidirectionalStreamCapacity: this.options.inboundBidirectionalStreamCapacity,
      ...(this.options.resourcePolicy === undefined ? {} : { resourcePolicy: this.options.resourcePolicy }),
    });
    return this.active;
  }
}

class WebSocketAdmissionStream implements CarrierStreamV3 {
  private readComplete = false;
  private writeComplete = false;
  private readonly outbound: Uint8Array[] = [];

  constructor(private readonly transport: WebSocketBinaryTransportV3) {}

  async read(options: OperationOptionsV3 = {}): Promise<Uint8Array | null> {
    if (this.readComplete) return null;
    this.readComplete = true;
    return await this.transport.readBinary(options);
  }

  async write(data: Uint8Array, options: OperationOptionsV3 = {}): Promise<number> {
    throwIfAborted(options.signal);
    if (this.writeComplete) throw new CarrierError("write_closed", "admission response is closed");
    this.outbound.push(data.slice());
    return data.length;
  }

  async closeWrite(): Promise<void> {
    if (this.writeComplete) return;
    this.writeComplete = true;
    const length = this.outbound.reduce((total, chunk) => total + chunk.length, 0);
    const response = new Uint8Array(length);
    let offset = 0;
    for (const chunk of this.outbound) {
      response.set(chunk, offset);
      offset += chunk.length;
    }
    this.outbound.length = 0;
    await this.transport.writeBinary(response);
  }

  async stopSending(): Promise<void> {
    this.transport.close();
  }

  async reset(): Promise<void> {
    this.transport.close();
  }

  abort(): void {
    this.transport.close();
  }
}

class WebSocketYamuxCarrierSession implements CarrierSessionV3 {
  readonly kind = "websocket" as const;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams = undefined;

  private readonly incoming = new IncomingStreamQueue();
  private readonly yamux: YamuxSession;
  private readonly termination = deferred<void>();
  private terminalError: Error | undefined;
  private closed = false;

  constructor(
    private readonly transport: WebSocketBinaryTransportV3,
    options: Readonly<{
      path: PathKind;
      client: boolean;
      inboundBidirectionalStreamCapacity: number;
      resourcePolicy?: WebSocketResourcePolicyV3;
    }>,
  ) {
    requireCapacity(options.inboundBidirectionalStreamCapacity);
    this.path = options.path;
    this.inboundBidirectionalStreamCapacity = options.inboundBidirectionalStreamCapacity;
    const duplex: ByteDuplex = {
      read: async () => await transport.readBinary(),
      write: async (chunk) => await transport.writeBinary(chunk),
      close: () => transport.close(),
    };
    const policy = options.resourcePolicy ?? {};
    this.yamux = new YamuxSession(duplex, {
      client: options.client,
      limits: {
        maxActiveStreams: Math.max(
          policy.maxConcurrentStreams ?? this.inboundBidirectionalStreamCapacity,
          this.inboundBidirectionalStreamCapacity,
        ),
        maxInboundStreams: this.inboundBidirectionalStreamCapacity,
        ...(policy.maxFrameBytes === undefined ? {} : { maxFrameBytes: policy.maxFrameBytes }),
        ...(policy.preferredWriteBytes === undefined ? {} : { preferredOutboundFrameBytes: policy.preferredWriteBytes }),
        ...(policy.maxStreamWriteQueueBytes === undefined ? {} : { maxStreamWriteQueueBytes: policy.maxStreamWriteQueueBytes }),
        ...(policy.maxStreamReceiveBytes === undefined ? {} : { maxStreamReceiveBytes: policy.maxStreamReceiveBytes }),
        ...(policy.maxSessionReceiveBytes === undefined ? {} : { maxSessionReceiveBytes: policy.maxSessionReceiveBytes }),
      },
      onIncomingStream: (stream) => this.incoming.push(new YamuxCarrierStreamAdapter(stream)),
      onTerminal: (error) => {
        const failure = error instanceof CarrierError
          ? error
          : new CarrierError("closed", "WebSocket carrier terminated", error);
        this.closed = true;
        this.terminalError = failure;
        this.incoming.fail(failure);
        this.termination.resolve();
      },
    });
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    this.assertOpen();
    try {
      return new YamuxCarrierStreamAdapter(await this.yamux.openStream(options));
    } catch (error) {
      throw error instanceof CarrierError ? error : new CarrierError("closed", "WebSocket stream open failed", error);
    }
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    this.assertOpen();
    return await this.incoming.shift(options.signal);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    await this.transport.flush().catch(() => undefined);
    this.closeLocally();
  }

  abort(): void {
    this.closeLocally();
  }

  async waitTermination(): Promise<void> {
    await this.termination.promise;
    if (this.terminalError !== undefined) throw this.terminalError;
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
    if (this.closed) throw new CarrierError("closed", "WebSocket carrier is closed");
  }

  private closeLocally(): void {
    if (this.closed) return;
    this.closed = true;
    const failure = new CarrierError("closed", "WebSocket carrier is closed");
    this.incoming.fail(failure);
    this.yamux.close();
    this.termination.resolve();
  }
}

class YamuxCarrierStreamAdapter implements CarrierStreamV3 {
  constructor(private readonly stream: YamuxStream) {}

  async read(options: OperationOptionsV3 = {}): Promise<Uint8Array | null> {
    try {
      return await abortable(this.stream.read(), options.signal, () => this.stream.abort());
    } catch (error) {
      throw error instanceof CarrierError ? error : new CarrierError("reset", "WebSocket stream read failed", error);
    }
  }

  async write(data: Uint8Array, options: OperationOptionsV3 = {}): Promise<number> {
    throwIfAborted(options.signal);
    try {
      await abortable(this.stream.write(data), options.signal, () => this.stream.abort());
    } catch (error) {
      throw error instanceof CarrierError ? error : new CarrierError("reset", "WebSocket stream write failed", error);
    }
    return data.length;
  }

  async closeWrite(): Promise<void> {
    await this.stream.close();
  }

  async reset(): Promise<void> {
    await this.stream.reset();
  }

  async stopSending(): Promise<void> {
    throw new CarrierError(
      "stop_sending_unavailable",
      "WebSocket/Yamux cannot stop only the receive side of a bidirectional stream",
    );
  }

  abort(error?: Error): void {
    this.stream.abort(error);
  }
}

class IncomingStreamQueue {
  private readonly values: CarrierStreamV3[] = [];
  private readonly waiters = new Set<QueueWaiter>();
  private terminalError: Error | undefined;

  push(value: CarrierStreamV3): void {
    if (this.terminalError !== undefined) {
      value.abort(this.terminalError);
      return;
    }
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) this.values.push(value);
    else {
      this.waiters.delete(waiter);
      waiter.deliver(value);
    }
  }

  shift(signal?: AbortSignal): Promise<CarrierStreamV3> {
    throwIfAborted(signal);
    if (this.terminalError !== undefined) return Promise.reject(this.terminalError);
    const value = this.values.shift();
    if (value !== undefined) return Promise.resolve(value);
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", abort);
      };
      const waiter: QueueWaiter = {
        deliver: (stream) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(stream);
        },
        fail: (error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const abort = () => waiter.fail(new CarrierError("aborted", "carrier operation aborted"));
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted === true) abort();
    });
  }

  fail(error: Error): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    for (const stream of this.values) stream.abort(error);
    this.values.length = 0;
    for (const waiter of this.waiters) waiter.fail(error);
    this.waiters.clear();
  }
}

type QueueWaiter = Readonly<{
  deliver(stream: CarrierStreamV3): void;
  fail(error: Error): void;
}>;

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}>;

function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function requireCapacity(value: number): void {
  if (!Number.isInteger(value) || value < 3 || value > 130) {
    throw new RangeError("inboundBidirectionalStreamCapacity must be an integer from 3 to 130");
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw new CarrierError("aborted", "carrier operation aborted");
}

async function abortable<T>(promise: Promise<T>, signal: AbortSignal | undefined, onAbort: () => void): Promise<T> {
  if (signal === undefined) return await promise;
  throwIfAborted(signal);
  return await new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      onAbort();
      reject(new CarrierError("aborted", "carrier operation aborted"));
    };
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(value);
      },
      (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}
