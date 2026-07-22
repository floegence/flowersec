import type { CarrierKind, OperationOptionsV2, PathKind } from "./contract.js";
import { YamuxSession, type ByteDuplex } from "../yamux/session.js";
import type { YamuxStream } from "../yamux/stream.js";

export interface CarrierStreamV2 {
  read(options?: OperationOptionsV2): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptionsV2): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  /**
   * Synchronously initiates idempotent forced teardown. Pending and future
   * stream primitives must settle, but this call does not await cleanup.
   */
  abort(error?: Error): void;
}

export interface CarrierSessionV2 {
  readonly kind: CarrierKind;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  openStream(options?: OperationOptionsV2): Promise<CarrierStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<CarrierStreamV2>;
  close(error?: Readonly<{ code: number; reason: string }>): Promise<void>;
  /**
   * Synchronously initiates idempotent forced teardown. Pending and future
   * session and stream primitives must settle, but this call does not await cleanup.
   */
  abort(error?: Readonly<{ code: number; reason: string }>): void;
}

export class CarrierV2Error extends Error {
  constructor(readonly code: "aborted" | "closed" | "reset" | "write_closed", message: string) {
    super(message);
    this.name = "CarrierV2Error";
  }
}

export type WebSocketBinaryTransportV2 = Readonly<{
  readBinary(options?: Readonly<{ signal?: AbortSignal; timeoutMs?: number }>): Promise<Uint8Array>;
  writeBinary(data: Uint8Array, options?: OperationOptionsV2): Promise<void>;
  close(): void;
}>;

export type NativeCarrierStreamV2 = Readonly<{
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  /** See {@link CarrierStreamV2.abort}. */
  abort(error?: Error): void;
}>;

export type NativeCarrierSessionV2 = Readonly<{
  kind: "webtransport" | "raw_quic";
  path: PathKind;
  inboundBidirectionalStreamCapacity: number;
  openStream(options?: OperationOptionsV2): Promise<NativeCarrierStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<NativeCarrierStreamV2>;
  close(): Promise<void>;
  /** See {@link CarrierSessionV2.abort}. */
  abort(error?: Readonly<{ code: number; reason: string }>): void;
}>;

export type WebSocketResourcePolicyV2 = Readonly<{
  maxConcurrentStreams?: number;
  maxFrameBytes?: number;
  preferredWriteBytes?: number;
  maxStreamWriteQueueBytes?: number;
  maxStreamReceiveBytes?: number;
  maxSessionReceiveBytes?: number;
}>;

export function createWebSocketCarrierSessionV2(
  transport: WebSocketBinaryTransportV2,
  options: Readonly<{
    path: PathKind;
    client: boolean;
    inboundBidirectionalStreamCapacity: number;
    resourcePolicy?: WebSocketResourcePolicyV2;
  }>,
): CarrierSessionV2 {
  return new WebSocketYamuxCarrierSession(transport, options);
}

export function adaptNativeCarrierSessionV2(native: NativeCarrierSessionV2): CarrierSessionV2 {
  return new NativeCarrierSessionAdapter(native);
}

export function createMemoryCarrierPairV2(
  options: Readonly<{
    kind: CarrierKind;
    path: PathKind;
    inboundBidirectionalStreamCapacity: number;
    maxPendingStreams?: number;
  }>,
): readonly [CarrierSessionV2, CarrierSessionV2] {
  const maxPendingStreams = options.maxPendingStreams ?? 128;
  if (!Number.isInteger(maxPendingStreams) || maxPendingStreams < 1 || maxPendingStreams > 1_024) {
    throw new RangeError("maxPendingStreams must be an integer from 1 to 1024");
  }
  requireInboundBidirectionalStreamCapacity(options.inboundBidirectionalStreamCapacity);
  const link = new MemoryCarrierLink(
    options.kind,
    options.path,
    options.inboundBidirectionalStreamCapacity,
    maxPendingStreams,
  );
  const left = new MemoryCarrierSession(link, 0);
  const right = new MemoryCarrierSession(link, 1);
  link.attach(left, right);
  return [left, right];
}

class MemoryCarrierLink {
  readonly kind: CarrierKind;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly maxPendingStreams: number;

  private sessions: readonly [MemoryCarrierSession, MemoryCarrierSession] | undefined;
  private closedError: CarrierV2Error | undefined;
  private readonly streams = new Set<MemoryCarrierStream>();

  constructor(
    kind: CarrierKind,
    path: PathKind,
    inboundBidirectionalStreamCapacity: number,
    maxPendingStreams: number,
  ) {
    this.kind = kind;
    this.path = path;
    this.inboundBidirectionalStreamCapacity = inboundBidirectionalStreamCapacity;
    this.maxPendingStreams = maxPendingStreams;
  }

  attach(left: MemoryCarrierSession, right: MemoryCarrierSession): void {
    this.sessions = [left, right];
  }

  assertOpen(): void {
    if (this.closedError !== undefined) throw this.closedError;
  }

  open(side: 0 | 1): CarrierStreamV2 {
    this.assertOpen();
    const sessions = this.sessions;
    if (sessions === undefined) throw new Error("memory carrier is not attached");
    const peer = sessions[side === 0 ? 1 : 0];
    if (peer.pendingCount() >= this.maxPendingStreams) {
      throw new CarrierV2Error("closed", "carrier incoming stream queue exhausted");
    }
    const state = new MemoryStreamState(() => {
      this.streams.delete(local);
      this.streams.delete(remote);
    });
    const local = new MemoryCarrierStream(state, side);
    const remote = new MemoryCarrierStream(state, side === 0 ? 1 : 0);
    this.streams.add(local);
    this.streams.add(remote);
    peer.enqueue(remote);
    return local;
  }

  close(): void {
    if (this.closedError !== undefined) return;
    this.closedError = new CarrierV2Error("closed", "carrier session closed");
    for (const stream of [...this.streams]) stream.failFromSession(this.closedError);
    this.streams.clear();
    for (const session of this.sessions ?? []) session.fail(this.closedError);
  }
}

class MemoryCarrierSession implements CarrierSessionV2 {
  readonly kind: CarrierKind;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;

  private readonly incoming = new AsyncQueue<CarrierStreamV2>();
  private closed = false;

  constructor(private readonly link: MemoryCarrierLink, private readonly side: 0 | 1) {
    this.kind = link.kind;
    this.path = link.path;
    this.inboundBidirectionalStreamCapacity = link.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    throwIfAborted(options.signal);
    this.assertOpen();
    return this.link.open(this.side);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    this.assertOpen();
    return await this.incoming.shift(options.signal);
  }

  async close(): Promise<void> {
    this.link.close();
  }

  abort(): void {
    this.link.close();
  }

  enqueue(stream: CarrierStreamV2): void {
    if (this.closed) {
      void stream.reset();
      return;
    }
    this.incoming.push(stream);
  }

  pendingCount(): number {
    return this.incoming.size;
  }

  fail(error: CarrierV2Error): void {
    if (this.closed) return;
    this.closed = true;
    this.incoming.fail(error);
  }

  private assertOpen(): void {
    if (this.closed) throw new CarrierV2Error("closed", "carrier session closed");
    this.link.assertOpen();
  }
}

class MemoryStreamState {
  readonly inbound = [new AsyncQueue<Uint8Array | null>(), new AsyncQueue<Uint8Array | null>()] as const;
  readonly writeClosed = [false, false];
  terminalError: CarrierV2Error | undefined;
  private cleaned = false;

  constructor(private readonly onClean: () => void) {}

  finishIfClosed(): void {
    if (!this.cleaned && this.writeClosed[0] && this.writeClosed[1]) {
      this.cleaned = true;
      this.onClean();
    }
  }

  reset(): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = new CarrierV2Error("reset", "carrier stream reset");
    this.inbound[0].fail(this.terminalError);
    this.inbound[1].fail(this.terminalError);
    if (!this.cleaned) {
      this.cleaned = true;
      this.onClean();
    }
  }

  fail(error: CarrierV2Error): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.inbound[0].fail(error);
    this.inbound[1].fail(error);
  }
}

class MemoryCarrierStream implements CarrierStreamV2 {
  constructor(private readonly state: MemoryStreamState, private readonly side: 0 | 1) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    this.assertNotTerminal();
    return await this.state.inbound[this.side].shift(options.signal);
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    throwIfAborted(options.signal);
    this.assertNotTerminal();
    if (!(data instanceof Uint8Array)) throw new TypeError("carrier stream write requires Uint8Array");
    if (this.state.writeClosed[this.side]) {
      throw new CarrierV2Error("write_closed", "carrier stream write side is closed");
    }
    const peer = this.side === 0 ? 1 : 0;
    this.state.inbound[peer].push(data.slice());
    return data.length;
  }

  async closeWrite(): Promise<void> {
    this.assertNotTerminal();
    if (this.state.writeClosed[this.side]) return;
    this.state.writeClosed[this.side] = true;
    const peer = this.side === 0 ? 1 : 0;
    this.state.inbound[peer].push(null);
    this.state.finishIfClosed();
  }

  async reset(): Promise<void> {
    this.state.reset();
  }

  abort(): void {
    this.state.reset();
  }

  failFromSession(error: CarrierV2Error): void {
    this.state.fail(error);
  }

  private assertNotTerminal(): void {
    if (this.state.terminalError !== undefined) throw this.state.terminalError;
  }
}

class AsyncQueue<T> {
  private readonly values: T[] = [];
  private head = 0;
  private readonly waiters = new Set<QueueWaiter<T>>();
  private terminalError: Error | undefined;

  get size(): number {
    return this.values.length - this.head;
  }

  push(value: T): void {
    if (this.terminalError !== undefined) return;
    const waiter = this.waiters.values().next().value as QueueWaiter<T> | undefined;
    if (waiter !== undefined) {
      waiter.deliver(value);
      return;
    }
    this.values.push(value);
  }

  shift(signal?: AbortSignal): Promise<T> {
    throwIfAborted(signal);
    if (this.terminalError !== undefined) return Promise.reject(this.terminalError);
    if (this.head < this.values.length) {
      const value = this.values[this.head++]!;
      this.compact();
      return Promise.resolve(value);
    }
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", onAbort);
      };
      const waiter: QueueWaiter<T> = {
        deliver: (value) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(value);
        },
        fail: (error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const onAbort = () => waiter.fail(abortedError());
      this.waiters.add(waiter);
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted === true) onAbort();
    });
  }

  fail(error: Error): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.values.length = 0;
    this.head = 0;
    for (const waiter of [...this.waiters]) waiter.fail(error);
  }

  private compact(): void {
    if (this.head > 1_024 && this.head * 2 > this.values.length) {
      this.values.splice(0, this.head);
      this.head = 0;
    }
  }
}

type QueueWaiter<T> = Readonly<{
  deliver: (value: T) => void;
  fail: (error: Error) => void;
}>;

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw abortedError();
}

function abortedError(): CarrierV2Error {
  return new CarrierV2Error("aborted", "carrier operation aborted");
}

class WebSocketYamuxCarrierSession implements CarrierSessionV2 {
  readonly kind = "websocket" as const;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;

  private readonly incoming = new AsyncQueue<CarrierStreamV2>();
  private readonly yamux: YamuxSession;
  private terminalError: Error | undefined;

  constructor(
    transport: WebSocketBinaryTransportV2,
    options: Readonly<{
      path: PathKind;
      client: boolean;
      inboundBidirectionalStreamCapacity: number;
      resourcePolicy?: WebSocketResourcePolicyV2;
    }>,
  ) {
    requireInboundBidirectionalStreamCapacity(options.inboundBidirectionalStreamCapacity);
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
        ...(policy.preferredWriteBytes === undefined
          ? {}
          : { preferredOutboundFrameBytes: policy.preferredWriteBytes }),
        ...(policy.maxStreamWriteQueueBytes === undefined
          ? {}
          : { maxStreamWriteQueueBytes: policy.maxStreamWriteQueueBytes }),
        ...(policy.maxStreamReceiveBytes === undefined
          ? {}
          : { maxStreamReceiveBytes: policy.maxStreamReceiveBytes }),
        ...(policy.maxSessionReceiveBytes === undefined
          ? {}
          : { maxSessionReceiveBytes: policy.maxSessionReceiveBytes }),
      },
      onIncomingStream: (stream) => this.incoming.push(new YamuxCarrierStreamAdapter(stream)),
      onTerminal: (error) => {
        this.terminalError = error;
        this.incoming.fail(error);
      },
    });
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    this.assertOpen();
    return new YamuxCarrierStreamAdapter(await this.yamux.openStream(options));
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    this.assertOpen();
    return await this.incoming.shift(options.signal);
  }

  async close(): Promise<void> {
    this.yamux.close();
  }

  abort(): void {
    this.yamux.close();
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
  }
}

class YamuxCarrierStreamAdapter implements CarrierStreamV2 {
  constructor(private readonly stream: YamuxStream) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    return await abortable(this.stream.read(), options.signal, () => this.stream.abort());
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    throwIfAborted(options.signal);
    await abortable(this.stream.write(data), options.signal, () => this.stream.abort());
    return data.length;
  }

  async closeWrite(): Promise<void> {
    await this.stream.close();
  }

  async reset(): Promise<void> {
    await this.stream.reset();
  }

  abort(error?: Error): void {
    this.stream.abort(error);
  }
}

class NativeCarrierSessionAdapter implements CarrierSessionV2 {
  readonly kind: "webtransport" | "raw_quic";
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;

  constructor(private readonly native: NativeCarrierSessionV2) {
    this.kind = native.kind;
    this.path = native.path;
    this.inboundBidirectionalStreamCapacity = native.inboundBidirectionalStreamCapacity;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new NativeCarrierStreamAdapter(await this.native.openStream(options));
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new NativeCarrierStreamAdapter(await this.native.acceptStream(options));
  }

  async close(): Promise<void> {
    await this.native.close();
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.native.abort(error);
  }
}

function requireInboundBidirectionalStreamCapacity(value: number): void {
  if (!Number.isInteger(value) || value < 3 || value > 130) {
    throw new RangeError("inboundBidirectionalStreamCapacity must be an integer from 3 to 130");
  }
}

class NativeCarrierStreamAdapter implements CarrierStreamV2 {
  constructor(private readonly native: NativeCarrierStreamV2) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    return await abortable(this.native.read(), options.signal, () => this.native.abort());
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    throwIfAborted(options.signal);
    return await abortable(this.native.write(data), options.signal, () => this.native.abort());
  }

  async closeWrite(): Promise<void> {
    await this.native.closeWrite();
  }

  async reset(): Promise<void> {
    await this.native.reset();
  }

  abort(error?: Error): void {
    this.native.abort(error);
  }
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
      reject(abortedError());
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
