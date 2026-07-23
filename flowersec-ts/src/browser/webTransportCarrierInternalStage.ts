export type BrowserWebTransportBidirectionalStreamInternalStage = Readonly<{
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}>;

export type BrowserWebTransportDatagramDuplexInternalStage = Readonly<{
  readonly maxDatagramSize: number;
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
}>;

export type BrowserWebTransportLikeInternalStage = Readonly<{
  ready: Promise<void>;
  closed: Promise<unknown>;
  incomingBidirectionalStreams: ReadableStream<BrowserWebTransportBidirectionalStreamInternalStage>;
  incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;
  datagrams?: BrowserWebTransportDatagramDuplexInternalStage;
  createBidirectionalStream(): Promise<BrowserWebTransportBidirectionalStreamInternalStage>;
  close(closeInfo?: Readonly<{ closeCode?: number; reason?: string }>): void;
}>;

export type BrowserWebTransportFactoryInternalStage = (
  url: string,
) => BrowserWebTransportLikeInternalStage;

export type BrowserWebTransportCarrierStreamInternalStage = Readonly<{
  read(): Promise<Uint8Array | null>;
  write(data: Uint8Array): Promise<number>;
  closeWrite(): Promise<void>;
  reset(): Promise<void>;
  abort(error?: Error): void;
}>;

export type BrowserWebTransportUnreliableDatagramsInternalStage = Readonly<{
  readonly maxDatagramSize: number;
  send(
    data: Uint8Array,
    options?: Readonly<{ signal?: AbortSignal; expiresAt?: number }>,
  ): Promise<"accepted" | "dropped_budget" | "dropped_expired">;
  receive(options?: Readonly<{ signal?: AbortSignal }>): Promise<Uint8Array>;
}>;

export type BrowserWebTransportCarrierInternalStage = Readonly<{
  kind: "webtransport";
  path: "direct" | "tunnel";
  inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: BrowserWebTransportUnreliableDatagramsInternalStage | undefined;
  requireUnreliableDatagrams(): Promise<BrowserWebTransportUnreliableDatagramsInternalStage>;
  openStream(options?: Readonly<{ signal?: AbortSignal }>): Promise<BrowserWebTransportCarrierStreamInternalStage>;
  acceptStream(options?: Readonly<{ signal?: AbortSignal }>): Promise<BrowserWebTransportCarrierStreamInternalStage>;
  close(): Promise<void>;
  abort(error?: Readonly<{ code: number; reason: string }>): void;
}>;

export type CreateBrowserWebTransportCarrierInternalStageOptions = Readonly<{
  path: "direct" | "tunnel";
  signal?: AbortSignal;
  closeTimeoutMs?: number;
  maxIncomingStreams?: number;
  datagramSendBudgetBytes?: number;
  now?: () => number;
  webTransportFactory?: BrowserWebTransportFactoryInternalStage;
}>;

type CarrierErrorCode =
  | "invalid_webtransport_url"
  | "operation_aborted"
  | "carrier_closed"
  | "datagram_too_large"
  | "datagram_unavailable"
  | "stream_reset"
  | "write_closed"
  | "webtransport_unavailable";

export class BrowserWebTransportCarrierInternalStageError extends Error {
  readonly code: CarrierErrorCode;

  constructor(code: CarrierErrorCode, message: string) {
    super(message);
    this.name = "BrowserWebTransportCarrierInternalStageError";
    this.code = code;
  }
}

const DIRECT_PATH = "/flowersec/webtransport/v2/direct";
const TUNNEL_PATH = "/flowersec/webtransport/v2/tunnel";
const DEFAULT_CLOSE_TIMEOUT_MS = 1_000;
const MAX_CLOSE_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_INCOMING_STREAMS = 130;
const DEFAULT_DATAGRAM_SEND_BUDGET_MULTIPLIER = 64;

export async function createBrowserWebTransportCarrierInternalStage(
  rawURL: string | URL,
  options: CreateBrowserWebTransportCarrierInternalStageOptions,
): Promise<BrowserWebTransportCarrierInternalStage> {
  const url = validateURL(rawURL, options.path);
  const closeTimeoutMs = normalizeCloseTimeout(options.closeTimeoutMs);
  const maxIncomingStreams = normalizeMaxIncomingStreams(options.maxIncomingStreams);
  const factory = options.webTransportFactory ?? defaultWebTransportFactory;
  const transport = factory(url);
  let nativeCloseIssued = false;
  const closeNative = () => {
    if (nativeCloseIssued) return;
    nativeCloseIssued = true;
    transport.close({ closeCode: 6, reason: "WebTransport establishment canceled" });
  };

  try {
    await waitWithSignal(transport.ready, options.signal, closeNative);
    return new BrowserWebTransportCarrier(
      transport,
      options.path,
      closeTimeoutMs,
      maxIncomingStreams,
      options.datagramSendBudgetBytes,
      options.now ?? Date.now,
    );
  } catch (error) {
    closeNative();
    throw error;
  }
}

class BrowserWebTransportCarrier implements BrowserWebTransportCarrierInternalStage {
  readonly kind = "webtransport" as const;
  readonly path: "direct" | "tunnel";
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: BrowserWebTransportUnreliableDatagrams | undefined;

  private readonly bidirectionalReader: ReadableStreamDefaultReader<BrowserWebTransportBidirectionalStreamInternalStage>;
  private readonly unidirectionalReader: ReadableStreamDefaultReader<ReadableStream<Uint8Array>>;
  private readonly queuedIncoming: BrowserWebTransportCarrierStream[] = [];
  private readonly acceptWaiters = new Set<AcceptWaiter>();
  private readonly transport: BrowserWebTransportLikeInternalStage;
  private readonly closeTimeoutMs: number;
  private terminalError: Error | undefined;
  private closing = false;
  private closePromise: Promise<void> | undefined;
  private activeIncomingStreams = 0;
  private transportCloseIssued = false;
  private readerCleanupIssued = false;

  constructor(
    transport: BrowserWebTransportLikeInternalStage,
    path: "direct" | "tunnel",
    closeTimeoutMs: number,
    private readonly maxIncomingStreams: number,
    datagramSendBudgetBytes: number | undefined,
    now: () => number,
  ) {
    this.transport = transport;
    this.path = path;
    this.inboundBidirectionalStreamCapacity = maxIncomingStreams;
    this.closeTimeoutMs = closeTimeoutMs;
    this.bidirectionalReader = transport.incomingBidirectionalStreams.getReader();
    this.unidirectionalReader = transport.incomingUnidirectionalStreams.getReader();
    this.unreliableDatagrams = createUnreliableDatagrams(
      transport.datagrams,
      datagramSendBudgetBytes,
      now,
    );
    void this.pumpIncomingBidirectionalStreams();
    void this.rejectIncomingUnidirectionalStreams();
    void transport.closed.then(
      () => {
        this.handleTransportClosed(carrierClosedError());
      },
      (error: unknown) => {
        this.handleTransportClosed(asError(error));
      },
    );
  }

  async requireUnreliableDatagrams(): Promise<BrowserWebTransportUnreliableDatagramsInternalStage> {
    this.assertOpen();
    if (this.unreliableDatagrams === undefined) {
      throw new BrowserWebTransportCarrierInternalStageError(
        "datagram_unavailable",
        "WebTransport DATAGRAM was not negotiated by this browser transport",
      );
    }
    return this.unreliableDatagrams;
  }

  async openStream(
    options: Readonly<{ signal?: AbortSignal }> = {},
  ): Promise<BrowserWebTransportCarrierStreamInternalStage> {
    this.assertOpen();
    throwIfAborted(options.signal);
    const pending = this.transport.createBidirectionalStream();
    const native = await waitWithSignal(pending, options.signal, undefined, (lateStream) => {
      abortNativeStream(lateStream);
    });
    if (this.closing || this.terminalError !== undefined) {
      abortNativeStream(native);
      this.assertOpen();
    }
    return new BrowserWebTransportCarrierStream(native, this.closeTimeoutMs);
  }

  acceptStream(
    options: Readonly<{ signal?: AbortSignal }> = {},
  ): Promise<BrowserWebTransportCarrierStreamInternalStage> {
    try {
      this.assertOpen();
      throwIfAborted(options.signal);
    } catch (error) {
      return Promise.reject(error);
    }

    const queued = this.queuedIncoming.shift();
    if (queued !== undefined) return Promise.resolve(queued);

    return new Promise<BrowserWebTransportCarrierStreamInternalStage>((resolve, reject) => {
      let settled = false;
      const waiter: AcceptWaiter = {
        deliver: (stream) => {
          if (settled) return false;
          settled = true;
          cleanup();
          resolve(stream);
          return true;
        },
        fail: (error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const onAbort = () => {
        waiter.fail(abortedError());
      };
      const cleanup = () => {
        this.acceptWaiters.delete(waiter);
        options.signal?.removeEventListener("abort", onAbort);
      };
      this.acceptWaiters.add(waiter);
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted === true) onAbort();
    });
  }

  close(): Promise<void> {
    this.closePromise ??= this.closeOnce();
    return this.closePromise;
  }

  abort(_error?: Readonly<{ code: number; reason: string }>): void {
    this.closing = true;
    const closeError = carrierClosedError();
    this.failAcceptWaiters(closeError);
    for (const stream of this.queuedIncoming.splice(0)) stream.abort(closeError);
    this.unreliableDatagrams?.abort(closeError);
    this.closeTransport(6, "flowersec carrier aborted");
    if (!this.readerCleanupIssued) {
      this.readerCleanupIssued = true;
      void this.bidirectionalReader.cancel(closeError).catch(() => undefined);
      void this.unidirectionalReader.cancel(closeError).catch(() => undefined);
    }
  }

  private async closeOnce(): Promise<void> {
    this.closing = true;
    const closeError = carrierClosedError();
    this.failAcceptWaiters(closeError);
    const queued = this.queuedIncoming.splice(0);

    if (this.unreliableDatagrams !== undefined) {
      await settleWithin(this.unreliableDatagrams.close(), this.closeTimeoutMs);
    }

    this.closeTransport(0, "flowersec carrier close");

    this.readerCleanupIssued = true;
    const cleanup = Promise.allSettled([
      this.bidirectionalReader.cancel(closeError),
      this.unidirectionalReader.cancel(closeError),
      ...queued.map(async (stream) => await stream.reset()),
    ]);
    await settleWithin(Promise.allSettled([this.transport.closed, cleanup]), this.closeTimeoutMs);
    this.abort();
  }

  private closeTransport(closeCode: number, reason: string): void {
    if (this.transportCloseIssued) return;
    this.transportCloseIssued = true;
    try {
      this.transport.close({ closeCode, reason });
    } catch {
      // The native transport may already be closed.
    }
  }

  private async pumpIncomingBidirectionalStreams(): Promise<void> {
    try {
      while (!this.closing) {
        const result = await this.bidirectionalReader.read();
        if (result.done) {
          if (!this.closing) this.handleTransportClosed(carrierClosedError());
          return;
        }
        if (this.activeIncomingStreams >= this.maxIncomingStreams) {
          abortNativeStream(result.value);
          continue;
        }
        this.activeIncomingStreams++;
        let released = false;
        this.deliverIncoming(new BrowserWebTransportCarrierStream(result.value, this.closeTimeoutMs, () => {
          if (released) return;
          released = true;
          this.activeIncomingStreams = Math.max(0, this.activeIncomingStreams - 1);
        }));
      }
    } catch (error) {
      if (!this.closing) this.handleTransportClosed(asError(error));
    }
  }

  private async rejectIncomingUnidirectionalStreams(): Promise<void> {
    try {
      while (!this.closing) {
        const result = await this.unidirectionalReader.read();
        if (result.done) return;
        void result.value.cancel(new Error("unidirectional application stream rejected")).catch(() => {});
      }
    } catch {
      // Transport closure is handled by the closed promise and bidi pump.
    }
  }

  private deliverIncoming(stream: BrowserWebTransportCarrierStream): void {
    if (this.closing || this.terminalError !== undefined) {
      void stream.reset();
      return;
    }
    for (const waiter of this.acceptWaiters) {
      if (waiter.deliver(stream)) return;
    }
    this.queuedIncoming.push(stream);
  }

  private handleTransportClosed(error: Error): void {
    if (this.closing || this.terminalError !== undefined) return;
    this.terminalError = error;
    this.failAcceptWaiters(error);
    for (const stream of this.queuedIncoming.splice(0)) void stream.reset();
    this.unreliableDatagrams?.abort(error);
    void this.bidirectionalReader.cancel(error).catch(() => {});
    void this.unidirectionalReader.cancel(error).catch(() => {});
  }

  private failAcceptWaiters(error: Error): void {
    for (const waiter of [...this.acceptWaiters]) waiter.fail(error);
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
    if (this.closing) throw carrierClosedError();
  }
}

class BrowserWebTransportUnreliableDatagrams implements BrowserWebTransportUnreliableDatagramsInternalStage {
  readonly maxDatagramSize: number;

  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private readonly incoming = new DatagramQueue();
  private pendingSendBytes = 0;
  private terminalError: Error | undefined;
  private closing = false;
  private abortIssued = false;
  private closePromise: Promise<void> | undefined;

  constructor(
    native: BrowserWebTransportDatagramDuplexInternalStage,
    private readonly sendBudgetBytes: number,
    private readonly now: () => number,
  ) {
    this.maxDatagramSize = native.maxDatagramSize;
    this.reader = native.readable.getReader();
    this.writer = native.writable.getWriter();
    void this.pumpIncoming();
  }

  async send(
    data: Uint8Array,
    options: Readonly<{ signal?: AbortSignal; expiresAt?: number }> = {},
  ): Promise<"accepted" | "dropped_budget" | "dropped_expired"> {
    this.assertOpen();
    throwIfAborted(options.signal);
    if (!(data instanceof Uint8Array)) throw new TypeError("WebTransport datagram send requires Uint8Array");
    if (data.byteLength < 1 || data.byteLength > this.maxDatagramSize) {
      throw new BrowserWebTransportCarrierInternalStageError(
        "datagram_too_large",
        `WebTransport datagram must contain 1 to ${this.maxDatagramSize} bytes`,
      );
    }
    const expiresAt = normalizeExpiry(options.expiresAt);
    if (expiresAt !== undefined && expiresAt <= this.now()) return "dropped_expired";
    if (this.pendingSendBytes + data.byteLength > this.sendBudgetBytes) return "dropped_budget";

    this.pendingSendBytes += data.byteLength;
    try {
      if (expiresAt !== undefined && expiresAt <= this.now()) return "dropped_expired";
      await waitWithSignal(this.writer.write(data.slice()), options.signal);
      return "accepted";
    } catch (error) {
      if (this.closing || this.terminalError !== undefined) throw carrierClosedError();
      throw error;
    } finally {
      this.pendingSendBytes -= data.byteLength;
    }
  }

  async receive(options: Readonly<{ signal?: AbortSignal }> = {}): Promise<Uint8Array> {
    this.assertOpen();
    return await this.incoming.shift(options.signal);
  }

  close(): Promise<void> {
    this.closePromise ??= this.closeOnce();
    return this.closePromise;
  }

  abort(error: Error = carrierClosedError()): void {
    if (this.abortIssued) return;
    this.abortIssued = true;
    this.closing = true;
    this.terminalError = error;
    this.incoming.fail(error);
    void this.reader.cancel(error).catch(() => undefined);
    void this.writer.abort(error).catch(() => undefined);
  }

  private async closeOnce(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    const error = carrierClosedError();
    this.terminalError = error;
    this.incoming.fail(error);
    await Promise.allSettled([this.reader.cancel(error), this.writer.close()]);
  }

  private async pumpIncoming(): Promise<void> {
    try {
      while (!this.closing) {
        const result = await this.reader.read();
        if (result.done) {
          this.fail(carrierClosedError());
          return;
        }
        if (result.value.byteLength < 1 || result.value.byteLength > this.maxDatagramSize) continue;
        this.incoming.push(result.value.slice());
      }
    } catch (error) {
      if (!this.closing) this.fail(asError(error));
    }
  }

  private fail(error: Error): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.incoming.fail(error);
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
    if (this.closing) throw carrierClosedError();
  }
}

class DatagramQueue {
  private readonly values: Uint8Array[] = [];
  private readonly waiters = new Set<DatagramWaiter>();
  private terminalError: Error | undefined;

  push(value: Uint8Array): void {
    if (this.terminalError !== undefined) return;
    const waiter = this.waiters.values().next().value as DatagramWaiter | undefined;
    if (waiter !== undefined) {
      waiter.deliver(value);
      return;
    }
    this.values.push(value);
  }

  shift(signal?: AbortSignal): Promise<Uint8Array> {
    throwIfAborted(signal);
    if (this.terminalError !== undefined) return Promise.reject(this.terminalError);
    const value = this.values.shift();
    if (value !== undefined) return Promise.resolve(value);
    return new Promise<Uint8Array>((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", onAbort);
      };
      const waiter: DatagramWaiter = {
        deliver: (next) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(next);
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
    for (const waiter of [...this.waiters]) waiter.fail(error);
  }
}

type DatagramWaiter = Readonly<{
  deliver(value: Uint8Array): void;
  fail(error: Error): void;
}>;

class BrowserWebTransportCarrierStream implements BrowserWebTransportCarrierStreamInternalStage {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private resetPromise: Promise<void> | undefined;
  private closeWritePromise: Promise<void> | undefined;
  private readClosed = false;
  private writeClosed = false;
  private released = false;

  constructor(
    native: BrowserWebTransportBidirectionalStreamInternalStage,
    private readonly resetTimeoutMs: number,
    private readonly onRelease: () => void = () => undefined,
  ) {
    this.reader = native.readable.getReader();
    this.writer = native.writable.getWriter();
  }

  async read(): Promise<Uint8Array | null> {
    this.assertNotReset();
    try {
      const result = await this.reader.read();
      if (result.done) {
        this.readClosed = true;
        this.releaseIfComplete();
        return null;
      }
      return result.value;
    } catch (error) {
      this.release();
      throw error;
    }
  }

  async write(data: Uint8Array): Promise<number> {
    this.assertNotReset();
    if (this.closeWritePromise !== undefined) {
      throw new BrowserWebTransportCarrierInternalStageError("write_closed", "carrier stream write side is closed");
    }
    if (!(data instanceof Uint8Array)) throw new TypeError("carrier stream write requires Uint8Array");
    try {
      await this.writer.ready;
      await this.writer.write(data);
      return data.byteLength;
    } catch (error) {
      this.release();
      throw error;
    }
  }

  closeWrite(): Promise<void> {
    if (this.resetPromise !== undefined) return this.resetPromise;
    this.closeWritePromise ??= this.writer.close().then(
      () => {
        this.writeClosed = true;
        this.releaseIfComplete();
      },
      (error: unknown) => {
        this.release();
        throw error;
      },
    );
    return this.closeWritePromise;
  }

  reset(): Promise<void> {
    this.resetPromise ??= settleWithin(
      resetReaderAndWriter(this.reader, this.writer),
      this.resetTimeoutMs,
    ).finally(() => this.release());
    return this.resetPromise;
  }

  abort(error: Error = new BrowserWebTransportCarrierInternalStageError(
    "stream_reset",
    "carrier stream aborted",
  )): void {
    if (this.resetPromise === undefined) {
      void this.writer.abort(error).catch(() => undefined);
      void this.reader.cancel(error).catch(() => undefined);
    }
    this.release();
  }

  private assertNotReset(): void {
    if (this.resetPromise !== undefined) {
      throw new BrowserWebTransportCarrierInternalStageError("stream_reset", "carrier stream is reset");
    }
  }

  private releaseIfComplete(): void {
    if (this.readClosed && this.writeClosed) this.release();
  }

  private release(): void {
    if (this.released) return;
    this.released = true;
    this.onRelease();
  }
}

type AcceptWaiter = Readonly<{
  deliver: (stream: BrowserWebTransportCarrierStream) => boolean;
  fail: (error: Error) => void;
}>;

function validateURL(rawURL: string | URL, path: "direct" | "tunnel"): string {
  let parsed: URL;
  try {
    parsed = new URL(rawURL);
  } catch {
    throw invalidURLError();
  }
  const expectedPath = path === "direct" ? DIRECT_PATH : TUNNEL_PATH;
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname === "" ||
    parsed.pathname !== expectedPath ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.href !== `${parsed.origin}${expectedPath}`
  ) {
    throw invalidURLError();
  }
  return parsed.href;
}

function normalizeCloseTimeout(value: number | undefined): number {
  const timeout = value ?? DEFAULT_CLOSE_TIMEOUT_MS;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > MAX_CLOSE_TIMEOUT_MS) {
    throw new RangeError(`closeTimeoutMs must be an integer from 1 to ${MAX_CLOSE_TIMEOUT_MS}`);
  }
  return timeout;
}

function normalizeMaxIncomingStreams(value: number | undefined): number {
  const limit = value ?? DEFAULT_MAX_INCOMING_STREAMS;
  if (!Number.isInteger(limit) || limit < 1 || limit > 130) {
    throw new RangeError("maxIncomingStreams must be an integer from 1 to 130");
  }
  return limit;
}

function createUnreliableDatagrams(
  native: BrowserWebTransportDatagramDuplexInternalStage | undefined,
  configuredBudgetBytes: number | undefined,
  now: () => number,
): BrowserWebTransportUnreliableDatagrams | undefined {
  if (native === undefined || !Number.isSafeInteger(native.maxDatagramSize) || native.maxDatagramSize < 1) {
    return undefined;
  }
  const defaultBudget = native.maxDatagramSize * DEFAULT_DATAGRAM_SEND_BUDGET_MULTIPLIER;
  const budget = configuredBudgetBytes ?? defaultBudget;
  if (!Number.isSafeInteger(budget) || budget < native.maxDatagramSize) {
    throw new RangeError("datagramSendBudgetBytes must be a safe integer at least maxDatagramSize");
  }
  const sampledNow = now();
  if (!Number.isFinite(sampledNow)) throw new TypeError("now must return a finite timestamp");
  return new BrowserWebTransportUnreliableDatagrams(native, budget, now);
}

function normalizeExpiry(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError("expiresAt must be a non-negative safe integer Unix timestamp in milliseconds");
  }
  return value;
}

function defaultWebTransportFactory(url: string): BrowserWebTransportLikeInternalStage {
  const candidate = (globalThis as unknown as { WebTransport?: unknown }).WebTransport;
  if (typeof candidate !== "function") {
    throw new BrowserWebTransportCarrierInternalStageError(
      "webtransport_unavailable",
      "WebTransport is unavailable in this browser runtime",
    );
  }
  const Constructor = candidate as new (url: string) => BrowserWebTransportLikeInternalStage;
  return new Constructor(url);
}

function waitWithSignal<T>(
  promise: Promise<T>,
  signal: AbortSignal | undefined,
  onAbort?: () => void,
  onLateValue?: (value: T) => void,
): Promise<T> {
  if (signal === undefined) return promise;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", abort);
    const abort = () => {
      if (settled) return;
      settled = true;
      cleanup();
      onAbort?.();
      reject(abortedError());
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
    promise.then(
      (value) => {
        if (settled) {
          onLateValue?.(value);
          return;
        }
        settled = true;
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error);
      },
    );
  });
}

function abortNativeStream(native: BrowserWebTransportBidirectionalStreamInternalStage): void {
  const reader = native.readable.getReader();
  const writer = native.writable.getWriter();
  const error = new BrowserWebTransportCarrierInternalStageError("stream_reset", "carrier stream aborted");
  void writer.abort(error).catch(() => undefined);
  void reader.cancel(error).catch(() => undefined);
}

async function resetReaderAndWriter(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  writer: WritableStreamDefaultWriter<Uint8Array>,
): Promise<void> {
  const error = new BrowserWebTransportCarrierInternalStageError("stream_reset", "carrier stream reset");
  await Promise.allSettled([writer.abort(error), reader.cancel(error)]);
}

async function settleWithin(promise: Promise<unknown>, timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(finish, timeoutMs);
    promise.then(finish, finish);
  });
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw abortedError();
}

function invalidURLError(): BrowserWebTransportCarrierInternalStageError {
  return new BrowserWebTransportCarrierInternalStageError(
    "invalid_webtransport_url",
    "WebTransport URL must use the exact registered HTTPS path without credentials, query, or fragment",
  );
}

function abortedError(): BrowserWebTransportCarrierInternalStageError {
  return new BrowserWebTransportCarrierInternalStageError("operation_aborted", "carrier operation aborted");
}

function carrierClosedError(): BrowserWebTransportCarrierInternalStageError {
  return new BrowserWebTransportCarrierInternalStageError("carrier_closed", "WebTransport carrier closed");
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
