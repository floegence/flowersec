import {
  CarrierError,
  type CarrierUnreliableDatagramsV2,
  type NativeCarrierSessionV2,
  type NativeCarrierStreamV2,
} from "../v2/carrier.js";
import type { OperationOptionsV2, PathKind } from "../v2/contract.js";

export type WebTransportBidirectionalLikeV2 = Readonly<{
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}>;

export type WebTransportDatagramsLikeV2 = Readonly<{
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  maxDatagramSize?: number;
}>;

export type WebTransportSessionLikeV2 = Readonly<{
  closed: Promise<unknown>;
  incomingBidirectionalStreams: ReadableStream<WebTransportBidirectionalLikeV2>;
  datagrams: WebTransportDatagramsLikeV2;
  createBidirectionalStream(): Promise<WebTransportBidirectionalLikeV2>;
  close(info?: Readonly<{ closeCode: number; reason: string }>): void;
}>;

export function adaptWebTransportCarrierSessionV2(
  native: WebTransportSessionLikeV2,
  options: Readonly<{
    path: PathKind;
    inboundBidirectionalStreamCapacity: number;
    datagramMaxSize?: number;
  }>,
): NativeCarrierSessionV2 {
  requireWebTransportSessionSurfaceV2(native);
  return new WebTransportCarrierSessionAdapter(native, options);
}

export function hasWebTransportConstructorSurfaceV2(value: unknown): boolean {
  if (typeof value !== "function") return false;
  const prototype = (value as { prototype?: unknown }).prototype;
  return typeof prototype === "object" && prototype !== null &&
    typeof (prototype as { createBidirectionalStream?: unknown }).createBidirectionalStream === "function" &&
    typeof (prototype as { close?: unknown }).close === "function" &&
    "incomingBidirectionalStreams" in prototype &&
    "datagrams" in prototype &&
    "ready" in prototype &&
    "closed" in prototype;
}

function requireWebTransportSessionSurfaceV2(value: WebTransportSessionLikeV2): void {
  if (
    typeof value.createBidirectionalStream !== "function" ||
    typeof value.close !== "function" ||
    typeof value.incomingBidirectionalStreams?.getReader !== "function" ||
    typeof value.datagrams?.readable?.getReader !== "function" ||
    typeof value.datagrams?.writable?.getWriter !== "function" ||
    typeof value.closed?.then !== "function"
  ) {
    throw new TypeError("WebTransport runtime lacks the required stream, DATAGRAM, close, or termination surface");
  }
}

class WebTransportCarrierSessionAdapter implements NativeCarrierSessionV2 {
  readonly kind = "webtransport" as const;
  readonly path: PathKind;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierUnreliableDatagramsV2 | undefined;

  private readonly incoming: ReadableStreamDefaultReader<WebTransportBidirectionalLikeV2>;
  private readonly incomingQueue = new IncomingWebTransportStreamQueue();
  private readonly streams = new Set<WebTransportCarrierStreamAdapter>();
  private readonly datagramsAdapter: WebTransportDatagramAdapter;
  private closed = false;
  private terminalError: CarrierError | undefined;
  private closePromise: Promise<void> | undefined;
  private activeIncomingStreams = 0;

  constructor(
    private readonly native: WebTransportSessionLikeV2,
    options: Readonly<{
      path: PathKind;
      inboundBidirectionalStreamCapacity: number;
      datagramMaxSize?: number;
    }>,
  ) {
    if (!Number.isInteger(options.inboundBidirectionalStreamCapacity) || options.inboundBidirectionalStreamCapacity < 3) {
      throw new RangeError("WebTransport carrier stream capacity must be at least 3");
    }
    this.path = options.path;
    this.inboundBidirectionalStreamCapacity = options.inboundBidirectionalStreamCapacity;
    this.incoming = native.incomingBidirectionalStreams.getReader();
    this.datagramsAdapter = new WebTransportDatagramAdapter(native.datagrams, options.datagramMaxSize);
    this.unreliableDatagrams = this.datagramsAdapter;
    void this.pumpIncoming();
    void native.closed.then(
      () => { this.terminate(new CarrierError("closed", "WebTransport carrier is closed")); },
      (error: unknown) => {
        this.terminate(carrierFailure("WebTransport closed with an error", error));
      },
    );
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<NativeCarrierStreamV2> {
    this.assertOpen();
    if (options.signal?.aborted === true) throw abortedCarrierError(options.signal.reason);
    const pending = this.native.createBidirectionalStream();
    let stream: WebTransportBidirectionalLikeV2;
    try {
      stream = await carrierCall(raceAbort(pending, options.signal), "WebTransport failed to open a stream");
    } catch (error) {
      if (isAborted(options.signal)) {
        void pending.then((late) => abortNativeStream(late, abortedCarrierError()), () => undefined);
      }
      throw error;
    }
    try {
      this.assertOpen();
    } catch (error) {
      abortNativeStream(stream, asError(error));
      throw error;
    }
    return this.track(stream);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<NativeCarrierStreamV2> {
    this.assertOpen();
    return await this.incomingQueue.shift(options.signal);
  }

  async waitTermination(): Promise<void> {
    try {
      await this.native.closed;
    } catch (error) {
      throw carrierFailure("WebTransport terminated with an error", error);
    }
  }

  close(): Promise<void> {
    this.closePromise ??= this.closeOnce({ closeCode: 0, reason: "" });
    return this.closePromise;
  }

  abort(error: Readonly<{ code: number; reason: string }> = { code: 6, reason: "carrier aborted" }): void {
    if (this.closed) return;
    this.terminate(new CarrierError("aborted", "WebTransport carrier aborted"));
    try {
      this.native.close({ closeCode: error.code, reason: error.reason });
    } catch (cause) {
      this.terminalError = carrierFailure("WebTransport abort failed", cause);
    }
  }

  private async closeOnce(info: Readonly<{ closeCode: number; reason: string }>): Promise<void> {
    if (this.closed) return;
    this.terminate(new CarrierError("closed", "WebTransport carrier is closed"));
    try {
      this.native.close(info);
      await this.native.closed;
    } catch (error) {
      throw carrierFailure("WebTransport close failed", error);
    }
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
    if (this.closed) throw new CarrierError("closed", "WebTransport carrier is closed");
  }

  private track(
    native: WebTransportBidirectionalLikeV2,
    incoming = false,
  ): WebTransportCarrierStreamAdapter {
    if (incoming) this.activeIncomingStreams += 1;
    let stream!: WebTransportCarrierStreamAdapter;
    stream = new WebTransportCarrierStreamAdapter(native, () => {
      this.streams.delete(stream);
      if (incoming) this.activeIncomingStreams = Math.max(0, this.activeIncomingStreams - 1);
    });
    this.streams.add(stream);
    return stream;
  }

  private async pumpIncoming(): Promise<void> {
    try {
      while (!this.closed) {
        const result = await this.incoming.read();
        if (result.done || result.value === undefined) {
          this.terminate(new CarrierError("closed", "WebTransport incoming streams closed"));
          return;
        }
        if (this.activeIncomingStreams >= this.inboundBidirectionalStreamCapacity) {
          abortNativeStream(result.value, new CarrierError("reset", "WebTransport inbound stream capacity exceeded"));
          continue;
        }
        this.incomingQueue.push(this.track(result.value, true));
      }
    } catch (error) {
      if (!this.closed) this.terminate(carrierFailure("WebTransport stream accept failed", error));
    }
  }

  private terminate(error: CarrierError): void {
    if (this.closed) return;
    this.closed = true;
    if (error.code !== "closed") this.terminalError = error;
    this.incomingQueue.fail(error);
    for (const stream of [...this.streams]) stream.abort(error);
    this.streams.clear();
    this.datagramsAdapter.abort(error);
  }
}

class WebTransportCarrierStreamAdapter implements NativeCarrierStreamV2 {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private readClosed = false;
  private readStopError: CarrierError | undefined;
  private writeClosed = false;
  private terminalError: CarrierError | undefined;
  private closeWritePromise: Promise<void> | undefined;
  private stopSendingPromise: Promise<void> | undefined;
  private resetPromise: Promise<void> | undefined;
  private released = false;

  constructor(
    stream: WebTransportBidirectionalLikeV2,
    private readonly onRelease: () => void,
  ) {
    this.reader = stream.readable.getReader();
    this.writer = stream.writable.getWriter();
  }

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    this.assertReadable();
    if (this.readClosed) return null;
    const result = await carrierCall(raceAbort(this.reader.read(), options.signal), "WebTransport stream read failed", "reset");
    if (result.done || result.value === undefined) {
      this.readClosed = true;
      this.releaseIfComplete();
      return null;
    }
    return result.value.slice();
  }

  async write(data: Uint8Array): Promise<number> {
    this.assertNotTerminal();
    if (this.writeClosed) throw new CarrierError("write_closed", "WebTransport stream write side is closed");
    await carrierCall(this.writer.write(data.slice()), "WebTransport stream write failed", "reset");
    return data.byteLength;
  }

  closeWrite(): Promise<void> {
    if (this.closeWritePromise !== undefined) return this.closeWritePromise;
    this.assertNotTerminal();
    this.writeClosed = true;
    this.closeWritePromise = carrierCall(this.writer.close(), "WebTransport stream FIN failed", "reset")
      .then(() => { this.releaseIfComplete(); });
    return this.closeWritePromise;
  }

  stopSending(): Promise<void> {
    if (this.stopSendingPromise !== undefined) return this.stopSendingPromise;
    this.assertNotTerminal();
    const stopped = new CarrierError("stop_sending", "WebTransport stream receive side stopped");
    this.readClosed = true;
    this.readStopError = stopped;
    this.stopSendingPromise ??= carrierCall(
      this.reader.cancel(stopped),
      "WebTransport STOP_SENDING failed",
      "stop_sending",
    ).then(() => { this.releaseIfComplete(); });
    return this.stopSendingPromise;
  }

  reset(): Promise<void> {
    this.resetPromise ??= this.resetOnce();
    return this.resetPromise;
  }

  abort(error: Error = new CarrierError("aborted", "WebTransport stream aborted")): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error instanceof CarrierError
      ? error
      : new CarrierError("aborted", "WebTransport stream aborted", error);
    this.readClosed = true;
    this.writeClosed = true;
    void this.writer.abort(this.terminalError).catch(() => undefined);
    void this.reader.cancel(this.terminalError).catch(() => undefined);
    this.release();
  }

  private async resetOnce(): Promise<void> {
    if (this.terminalError !== undefined) return;
    this.writeClosed = true;
    this.readClosed = true;
    const error = new CarrierError("reset", "WebTransport stream reset");
    this.terminalError = error;
    try {
      await Promise.allSettled([this.writer.abort(error), this.reader.cancel(error)]);
    } finally {
      this.release();
    }
  }

  private assertReadable(): void {
    this.assertNotTerminal();
    if (this.readStopError !== undefined) throw this.readStopError;
  }

  private assertNotTerminal(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
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

class WebTransportDatagramAdapter implements CarrierUnreliableDatagramsV2 {
  readonly maxDatagramSize: number;
  private readonly readable: ReadableStreamDefaultReader<Uint8Array>;
  private readonly writable: WritableStreamDefaultWriter<Uint8Array>;
  private readonly incoming = new IncomingDatagramQueue();
  private terminalError: CarrierError | undefined;

  constructor(native: WebTransportDatagramsLikeV2, configuredMaxSize: number | undefined) {
    const maxDatagramSize = configuredMaxSize ?? native.maxDatagramSize;
    if (!Number.isInteger(maxDatagramSize) || maxDatagramSize! < 1) {
      throw new TypeError("WebTransport runtime did not provide a valid DATAGRAM size");
    }
    this.maxDatagramSize = maxDatagramSize!;
    this.readable = native.readable.getReader();
    this.writable = native.writable.getWriter();
    void this.pumpIncoming();
  }

  async send(
    data: Uint8Array,
    options: Readonly<{ signal?: AbortSignal; expiresAt?: number }> = {},
  ): Promise<"accepted" | "dropped_budget" | "dropped_expired" | "dropped_carrier"> {
    this.assertOpen();
    if (options.signal?.aborted === true) throw abortedCarrierError(options.signal.reason);
    if (options.expiresAt !== undefined && options.expiresAt <= Date.now()) return "dropped_expired";
    if (data.byteLength < 1 || data.byteLength > this.maxDatagramSize) return "dropped_carrier";
    try {
      await raceAbort(this.writable.write(data.slice()), options.signal);
      return "accepted";
    } catch (error) {
      if (isAborted(options.signal)) throw abortedCarrierError(error);
      if (this.terminalError !== undefined) throw this.terminalError;
      return "dropped_carrier";
    }
  }

  async receive(options: OperationOptionsV2 = {}): Promise<Uint8Array> {
    this.assertOpen();
    return await this.incoming.shift(options.signal);
  }

  abort(error: CarrierError): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.incoming.fail(error);
    void this.writable.abort(error).catch(() => undefined);
  }

  private assertOpen(): void {
    if (this.terminalError !== undefined) throw this.terminalError;
  }

  private async pumpIncoming(): Promise<void> {
    try {
      while (this.terminalError === undefined) {
        const result = await this.readable.read();
        if (result.done || result.value === undefined) {
          this.abort(new CarrierError("closed", "WebTransport datagrams closed"));
          return;
        }
        if (result.value.byteLength < 1 || result.value.byteLength > this.maxDatagramSize) continue;
        this.incoming.push(result.value.slice());
      }
    } catch (error) {
      if (this.terminalError === undefined) {
        this.abort(carrierFailure("WebTransport datagram receive failed", error));
      }
    }
  }
}

class IncomingWebTransportStreamQueue {
  private readonly values: WebTransportCarrierStreamAdapter[] = [];
  private readonly waiters = new Set<Readonly<{
    deliver(stream: WebTransportCarrierStreamAdapter): void;
    fail(error: Error): void;
  }>>();
  private terminalError: Error | undefined;

  push(stream: WebTransportCarrierStreamAdapter): void {
    if (this.terminalError !== undefined) {
      stream.abort(this.terminalError);
      return;
    }
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) this.values.push(stream);
    else waiter.deliver(stream);
  }

  shift(signal?: AbortSignal): Promise<WebTransportCarrierStreamAdapter> {
    if (signal?.aborted === true) return Promise.reject(abortedCarrierError(signal.reason));
    if (this.terminalError !== undefined) return Promise.reject(this.terminalError);
    const value = this.values.shift();
    if (value !== undefined) return Promise.resolve(value);
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", abort);
      };
      const waiter = {
        deliver: (stream: WebTransportCarrierStreamAdapter) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(stream);
        },
        fail: (error: Error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const abort = () => waiter.fail(abortedCarrierError(signal?.reason));
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
    for (const waiter of [...this.waiters]) waiter.fail(error);
  }
}

class IncomingDatagramQueue {
  private readonly values: Uint8Array[] = [];
  private readonly waiters = new Set<Readonly<{
    deliver(value: Uint8Array): void;
    fail(error: Error): void;
  }>>();
  private terminalError: Error | undefined;

  push(value: Uint8Array): void {
    if (this.terminalError !== undefined) return;
    const waiter = this.waiters.values().next().value;
    if (waiter === undefined) this.values.push(value);
    else waiter.deliver(value);
  }

  shift(signal?: AbortSignal): Promise<Uint8Array> {
    if (signal?.aborted === true) return Promise.reject(abortedCarrierError(signal.reason));
    if (this.terminalError !== undefined) return Promise.reject(this.terminalError);
    const value = this.values.shift();
    if (value !== undefined) return Promise.resolve(value);
    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        this.waiters.delete(waiter);
        signal?.removeEventListener("abort", abort);
      };
      const waiter = {
        deliver: (next: Uint8Array) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(next);
        },
        fail: (error: Error) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        },
      };
      const abort = () => waiter.fail(abortedCarrierError(signal?.reason));
      this.waiters.add(waiter);
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted === true) abort();
    });
  }

  fail(error: Error): void {
    if (this.terminalError !== undefined) return;
    this.terminalError = error;
    this.values.length = 0;
    for (const waiter of [...this.waiters]) waiter.fail(error);
  }
}

function abortNativeStream(stream: WebTransportBidirectionalLikeV2, error: Error): void {
  const reader = stream.readable.getReader();
  const writer = stream.writable.getWriter();
  void reader.cancel(error).catch(() => undefined);
  void writer.abort(error).catch(() => undefined);
}

function abortedCarrierError(cause?: unknown): CarrierError {
  return new CarrierError("aborted", "WebTransport operation aborted", cause);
}

function isAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

async function raceAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await promise;
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

async function carrierCall<T>(
  promise: Promise<T>,
  message: string,
  code: "closed" | "reset" | "stop_sending" = "closed",
): Promise<T> {
  try {
    return await promise;
  } catch (error) {
    if (error instanceof CarrierError) throw error;
    if (error instanceof DOMException && error.name === "AbortError" ||
        error instanceof Error && error.name === "AbortError") {
      throw new CarrierError("aborted", message, error);
    }
    throw new CarrierError(code, message, error);
  }
}

function carrierFailure(message: string, cause: unknown): CarrierError {
  return cause instanceof CarrierError ? cause : new CarrierError("closed", message, cause);
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
