import type { CarrierKind, OperationOptionsV2, PathKind } from "./contract.js";

export type CarrierErrorCode =
  | "aborted"
  | "closed"
  | "reset"
  | "stop_sending"
  | "stop_sending_unavailable"
  | "write_closed"
  | "datagram_unavailable";

export class CarrierError extends Error {
  constructor(readonly code: CarrierErrorCode, message: string, readonly cause?: unknown) {
    super(message);
    this.name = "CarrierError";
  }
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}>;

function deferred<T>(): Deferred<T> {
  let resolvePromise!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolve) => { resolvePromise = resolve; });
  return { promise, resolve: (value) => resolvePromise(value) };
}

export interface CarrierStreamV2 {
  read(options?: OperationOptionsV2): Promise<Uint8Array | null>;
  write(data: Uint8Array, options?: OperationOptionsV2): Promise<number>;
  closeWrite(): Promise<void>;
  stopSending(): Promise<void>;
  reset(): Promise<void>;
  /**
   * Synchronously initiates idempotent forced teardown. Pending and future
   * stream primitives must settle, but this call does not await cleanup.
   */
  abort(error?: Error): void;
}

export interface CarrierUnreliableDatagramsV2 {
  readonly maxDatagramSize: number;
  send(
    data: Uint8Array,
    options?: Readonly<{ signal?: AbortSignal; expiresAt?: number }>,
  ): Promise<"accepted" | "dropped_budget" | "dropped_expired" | "dropped_carrier">;
  receive(options?: OperationOptionsV2): Promise<Uint8Array>;
}

export interface CarrierSessionV2 {
  readonly kind: CarrierKind;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams?: CarrierUnreliableDatagramsV2 | undefined;
  openStream(options?: OperationOptionsV2): Promise<CarrierStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<CarrierStreamV2>;
  waitTermination(): Promise<void>;
  close(error?: Readonly<{ code: number; reason: string }>): Promise<void>;
  /**
   * Synchronously initiates idempotent forced teardown. Pending and future
   * session and stream primitives must settle, but this call does not await cleanup.
   */
  abort(error?: Readonly<{ code: number; reason: string }>): void;
}

export type NativeCarrierStreamV2 = Readonly<{
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<number>;
  closeWrite(): Promise<void>;
  stopSending(): Promise<void>;
  reset(): Promise<void>;
  /** See {@link CarrierStreamV2.abort}. */
  abort(error?: Error): void;
}>;

export type NativeCarrierSessionV2 = Readonly<{
  kind: "webtransport" | "raw_quic";
  path: PathKind;
  inboundBidirectionalStreamCapacity: number;
  unreliableDatagrams?: CarrierUnreliableDatagramsV2 | undefined;
  openStream(options?: OperationOptionsV2): Promise<NativeCarrierStreamV2>;
  acceptStream(options?: OperationOptionsV2): Promise<NativeCarrierStreamV2>;
  waitTermination(): Promise<void>;
  close(): Promise<void>;
  /** See {@link CarrierSessionV2.abort}. */
  abort(error?: Readonly<{ code: number; reason: string }>): void;
}>;

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
  private closedError: CarrierError | undefined;
  private readonly streams = new Set<MemoryCarrierStream>();
  private readonly termination = deferred<void>();

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
      throw new CarrierError("closed", "carrier incoming stream queue exhausted");
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
    this.closedError = new CarrierError("closed", "carrier session closed");
    for (const stream of [...this.streams]) stream.failFromSession(this.closedError);
    this.streams.clear();
    for (const session of this.sessions ?? []) session.fail(this.closedError);
    this.termination.resolve();
  }

  waitTermination(): Promise<void> {
    return this.termination.promise;
  }
}

class MemoryCarrierSession implements CarrierSessionV2 {
  readonly kind: CarrierKind;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams = undefined;

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

  async waitTermination(): Promise<void> {
    await this.link.waitTermination();
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

  fail(error: CarrierError): void {
    if (this.closed) return;
    this.closed = true;
    this.incoming.fail(error);
  }

  private assertOpen(): void {
    if (this.closed) throw new CarrierError("closed", "carrier session closed");
    this.link.assertOpen();
  }
}

class MemoryStreamState {
  readonly inbound = [new AsyncQueue<Uint8Array | null>(), new AsyncQueue<Uint8Array | null>()] as const;
  readonly writeClosed = [false, false];
  readonly readStopped = [false, false];
  terminalError: CarrierError | undefined;
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
    this.terminalError = new CarrierError("reset", "carrier stream reset");
    this.inbound[0].fail(this.terminalError);
    this.inbound[1].fail(this.terminalError);
    if (!this.cleaned) {
      this.cleaned = true;
      this.onClean();
    }
  }

  stopSending(side: 0 | 1): void {
    if (this.terminalError !== undefined || this.readStopped[side]) return;
    this.readStopped[side] = true;
    this.inbound[side].fail(new CarrierError("stop_sending", "carrier stream receive side stopped"));
  }

  fail(error: CarrierError): void {
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
      throw new CarrierError("write_closed", "carrier stream write side is closed");
    }
    const peer = this.side === 0 ? 1 : 0;
    if (this.state.readStopped[peer]) {
      throw new CarrierError("stop_sending", "carrier peer stopped receiving this stream");
    }
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

  async stopSending(): Promise<void> {
    this.state.stopSending(this.side);
  }

  abort(): void {
    this.state.reset();
  }

  failFromSession(error: CarrierError): void {
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

function abortedError(): CarrierError {
  return new CarrierError("aborted", "carrier operation aborted");
}

class NativeCarrierSessionAdapter implements CarrierSessionV2 {
  readonly kind: "webtransport" | "raw_quic";
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierUnreliableDatagramsV2 | undefined;

  constructor(private readonly native: NativeCarrierSessionV2) {
    this.kind = native.kind;
    this.path = native.path;
    this.inboundBidirectionalStreamCapacity = native.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = native.unreliableDatagrams;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new NativeCarrierStreamAdapter(await this.native.openStream(options));
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return new NativeCarrierStreamAdapter(await this.native.acceptStream(options));
  }

  async waitTermination(): Promise<void> {
    await this.native.waitTermination();
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

  async stopSending(): Promise<void> {
    await this.native.stopSending();
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
