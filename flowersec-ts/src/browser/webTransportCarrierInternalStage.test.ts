import { readFileSync } from "node:fs";
import { afterEach, describe, expect, test, vi } from "vitest";

import {
  createBrowserWebTransportCarrierInternalStage,
  type BrowserWebTransportBidirectionalStreamInternalStage,
  type BrowserWebTransportLikeInternalStage,
} from "./webTransportCarrierInternalStage.js";

describe("browser WebTransport carrier internal stage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  test("feature-detects WebTransport and validates exact HTTPS path URLs", async () => {
    vi.stubGlobal("WebTransport", undefined);
    await expect(
      createBrowserWebTransportCarrierInternalStage(
        "https://direct.example/flowersec/webtransport/v2/direct",
        { path: "direct" },
      ),
    ).rejects.toMatchObject({ code: "webtransport_unavailable" });

    for (const [path, rawURL] of [
      ["direct", "https://direct.example/flowersec/webtransport/v2/direct"],
      ["tunnel", "https://tunnel.example:8443/flowersec/webtransport/v2/tunnel"],
    ] as const) {
      const fake = new FakeWebTransport();
      fake.resolveReady();
      const factory = vi.fn(() => fake);
      const carrier = await createBrowserWebTransportCarrierInternalStage(rawURL, {
        path,
        webTransportFactory: factory,
      });
      expect(factory).toHaveBeenCalledWith(rawURL);
      expect(carrier.kind).toBe("webtransport");
      expect(carrier.path).toBe(path);
      await carrier.close();
    }

    for (const [path, rawURL] of [
      ["direct", "http://direct.example/flowersec/webtransport/v2/direct"],
      ["direct", "https://direct.example/flowersec/webtransport/v2/tunnel"],
      ["tunnel", "https://tunnel.example/flowersec/webtransport/v2/direct"],
      ["direct", "https://user@direct.example/flowersec/webtransport/v2/direct"],
      ["direct", "https://direct.example/flowersec/webtransport/v2/direct?token=secret"],
      ["direct", "https://direct.example/flowersec/webtransport/v2/direct?"],
      ["direct", "https://direct.example/flowersec/webtransport/v2/direct#fragment"],
      ["direct", "https://direct.example/flowersec/webtransport/v2/direct#"],
    ] as const) {
      const factory = vi.fn(() => new FakeWebTransport());
      await expect(
        createBrowserWebTransportCarrierInternalStage(rawURL, {
          path,
          webTransportFactory: factory,
        }),
      ).rejects.toMatchObject({ code: "invalid_webtransport_url" });
      expect(factory).not.toHaveBeenCalled();
    }
  });

  test("maps four logical streams to four distinct native bidi streams with backpressure and FIN", async () => {
    const fake = new FakeWebTransport();
    const outgoingOne = new FakeNativeBidirectionalStream("outgoing-one");
    const outgoingTwo = new FakeNativeBidirectionalStream("outgoing-two");
    const incomingOne = new FakeNativeBidirectionalStream("incoming-one");
    const incomingTwo = new FakeNativeBidirectionalStream("incoming-two");
    fake.outgoing.push(outgoingOne, outgoingTwo);
    fake.resolveReady();

    const carrier = await createCarrier(fake);
    const streamOne = await carrier.openStream();
    const streamTwo = await carrier.openStream();
    fake.enqueueIncomingBidirectional(incomingOne.native);
    fake.enqueueIncomingBidirectional(incomingTwo.native);
    const streamThree = await carrier.acceptStream();
    const streamFour = await carrier.acceptStream();

    expect(fake.createBidirectionalStream).toHaveBeenCalledTimes(2);

    const writeGate = outgoingOne.blockNextWrite();
    let firstWriteFinished = false;
    const firstWrite = streamOne.write(Uint8Array.of(1)).then((count) => {
      firstWriteFinished = true;
      return count;
    });
    await flushTasks();
    expect(firstWriteFinished).toBe(false);
    writeGate.resolve();

    await expect(firstWrite).resolves.toBe(1);
    await expect(streamTwo.write(Uint8Array.of(2))).resolves.toBe(1);
    await expect(streamThree.write(Uint8Array.of(3))).resolves.toBe(1);
    await expect(streamFour.write(Uint8Array.of(4))).resolves.toBe(1);
    expect(outgoingOne.writes).toEqual([Uint8Array.of(1)]);
    expect(outgoingTwo.writes).toEqual([Uint8Array.of(2)]);
    expect(incomingOne.writes).toEqual([Uint8Array.of(3)]);
    expect(incomingTwo.writes).toEqual([Uint8Array.of(4)]);

    outgoingOne.enqueueRead(Uint8Array.of(11));
    outgoingTwo.enqueueRead(Uint8Array.of(12));
    incomingOne.enqueueRead(Uint8Array.of(13));
    incomingTwo.enqueueRead(Uint8Array.of(14));
    await expect(streamOne.read()).resolves.toEqual(Uint8Array.of(11));
    await expect(streamTwo.read()).resolves.toEqual(Uint8Array.of(12));
    await expect(streamThree.read()).resolves.toEqual(Uint8Array.of(13));
    await expect(streamFour.read()).resolves.toEqual(Uint8Array.of(14));

    await streamOne.closeWrite();
    expect(outgoingOne.writeClose).toHaveBeenCalledTimes(1);
    expect(outgoingOne.writeAbort).not.toHaveBeenCalled();
    await carrier.close();
  });

  test("resets only the selected native stream with RESET and STOP equivalents", async () => {
    const fake = new FakeWebTransport();
    const first = new FakeNativeBidirectionalStream("first");
    const second = new FakeNativeBidirectionalStream("second");
    fake.outgoing.push(first, second);
    fake.resolveReady();
    const carrier = await createCarrier(fake);
    const firstStream = await carrier.openStream();
    const secondStream = await carrier.openStream();

    await firstStream.reset();
    expect(first.writeAbort).toHaveBeenCalledTimes(1);
    expect(first.readCancel).toHaveBeenCalledTimes(1);
    expect(second.writeAbort).not.toHaveBeenCalled();
    expect(second.readCancel).not.toHaveBeenCalled();
    expect(fake.close).not.toHaveBeenCalled();

    await expect(secondStream.write(Uint8Array.of(9, 8))).resolves.toBe(2);
    await secondStream.closeWrite();
    expect(second.writes).toEqual([Uint8Array.of(9, 8)]);
    expect(second.writeClose).toHaveBeenCalledTimes(1);
    await carrier.close();
  });

  test("bounds a hanging native reset and releases incoming stream capacity", async () => {
    vi.useFakeTimers();
    const fake = new FakeWebTransport();
    fake.resolveReady();
    const carrier = await createCarrier(fake, 25, 1);
    const hanging = new FakeNativeBidirectionalStream("hanging-reset", { hangReset: true });
    fake.enqueueIncomingBidirectional(hanging.native);
    const stream = await carrier.acceptStream();

    let resetFinished = false;
    const resetting = stream.reset().then(() => { resetFinished = true; });
    await vi.advanceTimersByTimeAsync(24);
    expect(resetFinished).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(resetFinished).toBe(true);

    const replacement = new FakeNativeBidirectionalStream("replacement");
    fake.enqueueIncomingBidirectional(replacement.native);
    const accepted = carrier.acceptStream();
    await expect(accepted).resolves.toBeDefined();
    await resetting;
    await carrier.close();
  });

  test("awaits ready and makes canceled accepts and opens lossless", async () => {
    const fake = new FakeWebTransport();
    let carrierReady = false;
    const carrierPromise = createCarrier(fake).then((carrier) => {
      carrierReady = true;
      return carrier;
    });
    await flushTasks();
    expect(carrierReady).toBe(false);
    fake.resolveReady();
    const carrier = await carrierPromise;

    const acceptAbort = new AbortController();
    const canceledAccept = carrier.acceptStream({ signal: acceptAbort.signal });
    acceptAbort.abort();
    await expect(canceledAccept).rejects.toMatchObject({ code: "operation_aborted" });

    const queuedNative = new FakeNativeBidirectionalStream("queued-after-cancel");
    fake.enqueueIncomingBidirectional(queuedNative.native);
    const accepted = await carrier.acceptStream();
    await expect(accepted.write(Uint8Array.of(7))).resolves.toBe(1);
    expect(queuedNative.writes).toEqual([Uint8Array.of(7)]);

    const alreadyQueuedNative = new FakeNativeBidirectionalStream("queued-before-cancel");
    fake.enqueueIncomingBidirectional(alreadyQueuedNative.native);
    await flushTasks();
    const preCanceledController = new AbortController();
    preCanceledController.abort();
    await expect(
      carrier.acceptStream({ signal: preCanceledController.signal }),
    ).rejects.toMatchObject({ code: "operation_aborted" });
    const acceptedAfterPreCancel = await carrier.acceptStream();
    await expect(acceptedAfterPreCancel.write(Uint8Array.of(8))).resolves.toBe(1);
    expect(alreadyQueuedNative.writes).toEqual([Uint8Array.of(8)]);

    const lateOpen = deferred<BrowserWebTransportBidirectionalStreamInternalStage>();
    fake.createBidirectionalStream.mockImplementationOnce(async () => await lateOpen.promise);
    const openAbort = new AbortController();
    const canceledOpen = carrier.openStream({ signal: openAbort.signal });
    openAbort.abort();
    await expect(canceledOpen).rejects.toMatchObject({ code: "operation_aborted" });
    const lateNative = new FakeNativeBidirectionalStream("late-open");
    lateOpen.resolve(lateNative.native);
    await eventually(() => {
      expect(lateNative.writeAbort).toHaveBeenCalledTimes(1);
      expect(lateNative.readCancel).toHaveBeenCalledTimes(1);
    });

    await carrier.close();
  });

  test("cancels incoming unidirectional streams and bounds close even if closed never settles", async () => {
    vi.useFakeTimers();
    const fake = new FakeWebTransport({
      settleClosedOnClose: false,
      settleIncomingSourceCancel: false,
    });
    fake.resolveReady();
    const carrier = await createCarrier(fake, 25);
    const incomingUni = new FakeIncomingUnidirectionalStream();
    fake.enqueueIncomingUnidirectional(incomingUni.readable);
    await vi.waitFor(() => {
      expect(incomingUni.cancel).toHaveBeenCalledTimes(1);
    });

    let closeFinished = false;
    const closePromise = carrier.close().then(() => {
      closeFinished = true;
    });
    await vi.advanceTimersByTimeAsync(24);
    expect(closeFinished).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await closePromise;
    expect(fake.close).toHaveBeenCalledTimes(1);
    expect(fake.bidirectionalSourceCancel).toHaveBeenCalledTimes(1);
    expect(fake.unidirectionalSourceCancel).toHaveBeenCalledTimes(1);
  });

  test("closes a ready wait canceled by its caller", async () => {
    const fake = new FakeWebTransport();
    const controller = new AbortController();
    const creating = createBrowserWebTransportCarrierInternalStage(
      "https://direct.example/flowersec/webtransport/v2/direct",
      {
        path: "direct",
        signal: controller.signal,
        closeTimeoutMs: 25,
        webTransportFactory: () => fake,
      },
    );
    controller.abort();
    await expect(creating).rejects.toMatchObject({ code: "operation_aborted" });
    expect(fake.close).toHaveBeenCalledTimes(1);
  });

  test("reserves control and RPC capacity in addition to N=1 application stream", async () => {
    const fake = new FakeWebTransport();
    fake.resolveReady();
    const carrier = await createCarrier(fake, 25, 3);
    const firstNative = new FakeNativeBidirectionalStream("first-inbound");
    fake.enqueueIncomingBidirectional(firstNative.native);
    const first = await carrier.acceptStream();

    const secondNative = new FakeNativeBidirectionalStream("second-inbound");
    fake.enqueueIncomingBidirectional(secondNative.native);
    const second = await carrier.acceptStream();
    const thirdNative = new FakeNativeBidirectionalStream("third-inbound");
    fake.enqueueIncomingBidirectional(thirdNative.native);
    const third = await carrier.acceptStream();

    const rejectedNative = new FakeNativeBidirectionalStream("fourth-inbound");
    fake.enqueueIncomingBidirectional(rejectedNative.native);
    await eventually(() => {
      expect(rejectedNative.writeAbort).toHaveBeenCalledTimes(1);
      expect(rejectedNative.readCancel).toHaveBeenCalledTimes(1);
    });

    await first.reset();
    const nextNative = new FakeNativeBidirectionalStream("next-inbound");
    fake.enqueueIncomingBidirectional(nextNative.native);
    const next = await carrier.acceptStream();
    await expect(next.write(Uint8Array.of(6))).resolves.toBe(1);
    expect(nextNative.writes).toEqual([Uint8Array.of(6)]);
    await second.reset();
    await third.reset();
    await carrier.close();
  });

  test("keeps the adapter carrier-only and its factory package-internal", () => {
    const source = readFileSync(new URL("./webTransportCarrierInternalStage.ts", import.meta.url), "utf8");
    const browserIndex = readFileSync(new URL("./index.ts", import.meta.url), "utf8");
    expect(source.toLowerCase()).not.toContain("ya" + "mux");
    expect(source.toLowerCase()).not.toContain("data" + "gram");
    expect(source).not.toContain("SessionV2");
    expect(source).not.toContain("ByteStreamV2");
    expect(browserIndex).not.toContain(
      'export { createBrowserWebTransportCarrierInternalStage } from "./webTransportCarrierInternalStage.js";',
    );
    expect(browserIndex).not.toMatch(/export \{[^}]*createBrowserWebTransportSession/);
  });
});

async function createCarrier(fake: FakeWebTransport, closeTimeoutMs = 25, maxIncomingStreams?: number) {
  return await createBrowserWebTransportCarrierInternalStage(
    "https://direct.example/flowersec/webtransport/v2/direct",
    {
      path: "direct",
      closeTimeoutMs,
      ...(maxIncomingStreams === undefined ? {} : { maxIncomingStreams }),
      webTransportFactory: () => fake,
    },
  );
}

class FakeWebTransport implements BrowserWebTransportLikeInternalStage {
  readonly readyState = deferred<void>();
  readonly closedState = deferred<unknown>();
  readonly ready = this.readyState.promise;
  readonly closed = this.closedState.promise;
  readonly outgoing: FakeNativeBidirectionalStream[] = [];
  readonly createBidirectionalStream = vi.fn(async () => {
    const next = this.outgoing.shift();
    if (next === undefined) throw new Error("missing fake outgoing stream");
    return next.native;
  });
  readonly close = vi.fn(() => {
    if (this.settleClosedOnClose) this.closedState.resolve(undefined);
  });
  readonly bidirectionalSourceCancel = vi.fn((): void | Promise<void> => undefined);
  readonly unidirectionalSourceCancel = vi.fn((): void | Promise<void> => undefined);
  readonly incomingBidirectionalStreams: ReadableStream<BrowserWebTransportBidirectionalStreamInternalStage>;
  readonly incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;

  private readonly settleClosedOnClose: boolean;
  private bidirectionalController!: ReadableStreamDefaultController<BrowserWebTransportBidirectionalStreamInternalStage>;
  private unidirectionalController!: ReadableStreamDefaultController<ReadableStream<Uint8Array>>;

  constructor(
    options: Readonly<{
      settleClosedOnClose?: boolean;
      settleIncomingSourceCancel?: boolean;
    }> = {},
  ) {
    this.settleClosedOnClose = options.settleClosedOnClose ?? true;
    if (options.settleIncomingSourceCancel === false) {
      this.bidirectionalSourceCancel.mockImplementation(async () => await new Promise<void>(() => {}));
      this.unidirectionalSourceCancel.mockImplementation(async () => await new Promise<void>(() => {}));
    }
    this.incomingBidirectionalStreams = new ReadableStream({
      start: (controller) => {
        this.bidirectionalController = controller;
      },
      cancel: this.bidirectionalSourceCancel,
    });
    this.incomingUnidirectionalStreams = new ReadableStream({
      start: (controller) => {
        this.unidirectionalController = controller;
      },
      cancel: this.unidirectionalSourceCancel,
    });
  }

  resolveReady(): void {
    this.readyState.resolve();
  }

  enqueueIncomingBidirectional(stream: BrowserWebTransportBidirectionalStreamInternalStage): void {
    this.bidirectionalController.enqueue(stream);
  }

  enqueueIncomingUnidirectional(stream: ReadableStream<Uint8Array>): void {
    this.unidirectionalController.enqueue(stream);
  }
}

class FakeNativeBidirectionalStream {
  readonly writes: Uint8Array[] = [];
  readonly readCancel = vi.fn();
  readonly writeClose = vi.fn();
  readonly writeAbort = vi.fn();
  readonly native: BrowserWebTransportBidirectionalStreamInternalStage;

  private readController!: ReadableStreamDefaultController<Uint8Array>;
  private nextWriteGate: Deferred<void> | undefined;

  constructor(
    readonly label: string,
    options: Readonly<{ hangReset?: boolean }> = {},
  ) {
    const readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.readController = controller;
      },
      cancel: this.readCancel,
    });
    const writable = new WritableStream<Uint8Array>({
      write: async (data) => {
        this.writes.push(new Uint8Array(data));
        const gate = this.nextWriteGate;
        this.nextWriteGate = undefined;
        if (gate !== undefined) await gate.promise;
      },
      close: this.writeClose,
      abort: this.writeAbort,
    });
    this.native = { readable, writable };
    if (options.hangReset === true) {
      this.readCancel.mockImplementation(async () => await new Promise<void>(() => undefined));
      this.writeAbort.mockImplementation(async () => await new Promise<void>(() => undefined));
    }
  }

  enqueueRead(data: Uint8Array): void {
    this.readController.enqueue(data);
  }

  blockNextWrite(): Deferred<void> {
    const gate = deferred<void>();
    this.nextWriteGate = gate;
    return gate;
  }
}

class FakeIncomingUnidirectionalStream {
  readonly cancel = vi.fn();
  readonly readable = new ReadableStream<Uint8Array>({ cancel: this.cancel });
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (reason?: unknown) => void;
}>;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function flushTasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      assertion();
      return;
    } catch (error) {
      if (attempt === 19) throw error;
      await flushTasks();
    }
  }
}
