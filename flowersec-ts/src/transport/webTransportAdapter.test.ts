import { describe, expect, test, vi } from "vitest";

import {
  adaptWebTransportCarrierSessionV2,
  type WebTransportBidirectionalLikeV2,
  type WebTransportSessionLikeV2,
} from "./webTransportAdapter.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);

describe("runtime-neutral WebTransport carrier adapter", () => {
  test("identifies each missing native runtime surface", () => {
    expect(() => adaptWebTransportCarrierSessionV2({
      closed: Promise.resolve(),
      incomingBidirectionalStreams: undefined,
      datagrams: undefined,
      createBidirectionalStream: undefined,
      close: undefined,
    } as unknown as WebTransportSessionLikeV2, {
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    })).toThrow(
      "WebTransport runtime lacks required outgoing bidirectional streams, incoming bidirectional streams, incoming DATAGRAMs, outgoing DATAGRAMs, close",
    );
  });

  test("maps stream FIN, DATAGRAM, and close without runtime-specific session logic", async () => {
    const outgoing = streamFixture({ reads: [bytes("reply")] });
    const incoming = streamFixture({ reads: [bytes("request")] });
    const runtime = runtimeFixture();
    runtime.outgoingStreams.push(Promise.resolve(outgoing.stream));
    runtime.incomingStreams.enqueue(incoming.stream);
    runtime.incomingDatagrams.enqueue(bytes("datagram-in"));
    const carrier = runtime.adapt(10);

    const opened = await carrier.openStream();
    expect(await opened.write(bytes("request"))).toBe(7);
    await opened.closeWrite();
    expect(outgoing.writes.map((value) => new TextDecoder().decode(value))).toEqual(["request"]);
    expect(new TextDecoder().decode((await opened.read())!)).toBe("reply");

    const accepted = await carrier.acceptStream();
    expect(new TextDecoder().decode((await accepted.read())!)).toBe("request");
    expect(await carrier.unreliableDatagrams!.send(bytes("datagram-out"))).toBe("accepted");
    expect(new TextDecoder().decode((await carrier.unreliableDatagrams!.receive()))).toBe("datagram-in");
    expect(runtime.datagramWrites).toHaveLength(1);

    const closing = carrier.close();
    runtime.termination.resolve();
    await closing;
    await carrier.close();
    expect(runtime.close).toHaveBeenCalledTimes(1);
  });

  test("aborts a stream that arrives after open cancellation wins", async () => {
    const runtime = runtimeFixture();
    const late = streamFixture();
    const opening = deferred<WebTransportBidirectionalLikeV2>();
    runtime.outgoingStreams.push(opening.promise);
    const carrier = runtime.adapt();
    const controller = new AbortController();
    const pending = carrier.openStream({ signal: controller.signal });

    controller.abort(new Error("caller stopped"));
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    opening.resolve(late.stream);
    await eventually(() => {
      expect(late.cancel).toHaveBeenCalledTimes(1);
      expect(late.abort).toHaveBeenCalledTimes(1);
    });
  });

  test("rejects excess inbound streams and preserves capacity until accepted streams finish", async () => {
    const runtime = runtimeFixture();
    const streams = Array.from({ length: 4 }, () => streamFixture());
    const carrier = runtime.adapt(3);
    for (const stream of streams) runtime.incomingStreams.enqueue(stream.stream);

    await eventually(() => {
      expect(streams[3]!.cancel).toHaveBeenCalledTimes(1);
      expect(streams[3]!.abort).toHaveBeenCalledTimes(1);
    });
    const accepted = await Promise.all([
      carrier.acceptStream(), carrier.acceptStream(), carrier.acceptStream(),
    ]);
    await accepted[0]!.reset();
    const replacement = streamFixture();
    runtime.incomingStreams.enqueue(replacement.stream);
    expect(await carrier.acceptStream()).toBeDefined();
    expect(replacement.abort).not.toHaveBeenCalled();
  });

  test("serves multiple stream and DATAGRAM waiters in arrival order", async () => {
    const runtime = runtimeFixture();
    const carrier = runtime.adapt();
    const streamWaiters = [carrier.acceptStream(), carrier.acceptStream()];
    const datagramWaiters = [
      carrier.unreliableDatagrams!.receive(),
      carrier.unreliableDatagrams!.receive(),
    ];
    const first = streamFixture({ reads: [bytes("first")] });
    const second = streamFixture({ reads: [bytes("second")] });

    runtime.incomingStreams.enqueue(first.stream);
    runtime.incomingStreams.enqueue(second.stream);
    runtime.incomingDatagrams.enqueue(bytes("one"));
    runtime.incomingDatagrams.enqueue(bytes("two"));

    expect(new TextDecoder().decode((await (await streamWaiters[0]!).read())!)).toBe("first");
    expect(new TextDecoder().decode((await (await streamWaiters[1]!).read())!)).toBe("second");
    expect((await Promise.all(datagramWaiters)).map((value) => new TextDecoder().decode(value)))
      .toEqual(["one", "two"]);
  });

  test("termination rejects every stream and DATAGRAM waiter", async () => {
    const runtime = runtimeFixture();
    const carrier = runtime.adapt();
    const accepts = [carrier.acceptStream(), carrier.acceptStream()];
    const receives = [
      carrier.unreliableDatagrams!.receive(),
      carrier.unreliableDatagrams!.receive(),
    ];

    runtime.termination.reject(new Error("peer vanished"));

    for (const pending of [...accepts, ...receives]) {
      await expect(pending).rejects.toMatchObject({ code: "closed" });
    }
    await expect(carrier.waitTermination()).rejects.toMatchObject({ code: "closed" });
  });

  test.each([
    ["read", "read failed", "reset"],
    ["write", "write failed", "reset"],
    ["closeWrite", "FIN failed", "reset"],
    ["stopSending", "STOP_SENDING failed", "stop_sending"],
  ] as const)("maps native stream %s failure", async (operation, message, code) => {
    const runtime = runtimeFixture();
    const fixture = streamFixture(operation === "read"
      ? { readError: new Error("read failed") }
      : operation === "write"
        ? { writeError: new Error("write failed") }
        : operation === "closeWrite"
          ? { closeError: new Error("FIN failed") }
          : { cancelError: new Error("STOP_SENDING failed") });
    runtime.outgoingStreams.push(Promise.resolve(fixture.stream));
    const stream = await runtime.adapt().openStream();

    const result = operation === "read" ? stream.read()
      : operation === "write" ? stream.write(bytes("data"))
      : operation === "closeWrite" ? stream.closeWrite()
      : stream.stopSending();
    await expect(result).rejects.toMatchObject({ code, cause: expect.objectContaining({ message }) });
  });

  test("drops invalid, oversized, and expired DATAGRAMs and supports receive and send cancellation", async () => {
    const runtime = runtimeFixture({ pendingDatagramWrite: true });
    const carrier = runtime.adapt();
    runtime.incomingDatagrams.enqueue(new Uint8Array());
    runtime.incomingDatagrams.enqueue(new Uint8Array(1_201));
    runtime.incomingDatagrams.enqueue(bytes("valid"));

    expect(new TextDecoder().decode(await carrier.unreliableDatagrams!.receive())).toBe("valid");
    expect(await carrier.unreliableDatagrams!.send(new Uint8Array())).toBe("dropped_carrier");
    expect(await carrier.unreliableDatagrams!.send(new Uint8Array(1_201))).toBe("dropped_carrier");
    expect(await carrier.unreliableDatagrams!.send(bytes("late"), { expiresAt: Date.now() - 1 }))
      .toBe("dropped_expired");

    const sendController = new AbortController();
    const sending = carrier.unreliableDatagrams!.send(bytes("pending"), { signal: sendController.signal });
    sendController.abort();
    await expect(sending).rejects.toMatchObject({ code: "aborted" });

    const receiveController = new AbortController();
    const receiving = carrier.unreliableDatagrams!.receive({ signal: receiveController.signal });
    receiveController.abort();
    await expect(receiving).rejects.toMatchObject({ code: "aborted" });
  });

  test("releases native close and stream abort resources exactly once", async () => {
    const runtime = runtimeFixture();
    const fixture = streamFixture();
    runtime.outgoingStreams.push(Promise.resolve(fixture.stream));
    const carrier = runtime.adapt();
    await carrier.openStream();

    carrier.abort({ code: 9, reason: "test" });
    carrier.abort({ code: 9, reason: "test" });
    await carrier.close();

    expect(runtime.close).toHaveBeenCalledTimes(1);
    expect(fixture.cancel).toHaveBeenCalledTimes(1);
    expect(fixture.abort).toHaveBeenCalledTimes(1);
    expect(runtime.abortDatagramWriter).toHaveBeenCalledTimes(1);
  });
});

function runtimeFixture(options: Readonly<{ pendingDatagramWrite?: boolean }> = {}) {
  const termination = deferred<void>();
  const incomingStreams = controlledReadable<WebTransportBidirectionalLikeV2>();
  const incomingDatagrams = controlledReadable<Uint8Array>();
  const outgoingStreams: Promise<WebTransportBidirectionalLikeV2>[] = [];
  const datagramWrites: Uint8Array[] = [];
  const abortDatagramWriter = vi.fn();
  const close = vi.fn(() => undefined);
  const native: WebTransportSessionLikeV2 = {
    closed: termination.promise,
    incomingBidirectionalStreams: incomingStreams.readable,
    createBidirectionalStream: vi.fn(async () => await (outgoingStreams.shift() ?? Promise.reject(new Error("no outgoing fixture")))),
    datagrams: {
      maxDatagramSize: 1_200,
      readable: incomingDatagrams.readable,
      writable: new WritableStream<Uint8Array>({
        write: options.pendingDatagramWrite === true
          ? () => new Promise<void>(() => undefined)
          : (value) => { datagramWrites.push(value.slice()); },
        abort: abortDatagramWriter,
      }),
    },
    close,
  };
  return {
    termination,
    incomingStreams,
    incomingDatagrams,
    outgoingStreams,
    datagramWrites,
    abortDatagramWriter,
    close,
    adapt: (capacity = 3) => adaptWebTransportCarrierSessionV2(native, {
      path: "direct",
      inboundBidirectionalStreamCapacity: capacity,
    }),
  };
}

function streamFixture(options: Readonly<{
  reads?: readonly Uint8Array[];
  readError?: Error;
  writeError?: Error;
  closeError?: Error;
  cancelError?: Error;
}> = {}) {
  const writes: Uint8Array[] = [];
  const cancel = vi.fn(async () => {
    if (options.cancelError !== undefined) throw options.cancelError;
  });
  const abort = vi.fn(async () => undefined);
  const readable = options.readError === undefined
    ? new ReadableStream<Uint8Array>({
        start(controller) {
          for (const value of options.reads ?? []) controller.enqueue(value);
        },
        cancel,
      })
    : new ReadableStream<Uint8Array>({ start(controller) { controller.error(options.readError); }, cancel });
  return {
    writes,
    cancel,
    abort,
    stream: {
      readable,
      writable: new WritableStream<Uint8Array>({
        write(value) {
          if (options.writeError !== undefined) throw options.writeError;
          writes.push(value.slice());
        },
        close() {
          if (options.closeError !== undefined) throw options.closeError;
        },
        abort,
      }),
    },
  } satisfies Readonly<{
    writes: Uint8Array[];
    cancel: ReturnType<typeof vi.fn>;
    abort: ReturnType<typeof vi.fn>;
    stream: WebTransportBidirectionalLikeV2;
  }>;
}

function controlledReadable<T>() {
  let controller!: ReadableStreamDefaultController<T>;
  return {
    readable: new ReadableStream<T>({ start(value) { controller = value; } }),
    enqueue: (value: T) => { controller.enqueue(value); },
    close: () => { controller.close(); },
    error: (cause: unknown) => { controller.error(cause); },
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    try {
      assertion();
      return;
    } catch (error) {
      if (attempt === 19) throw error;
      await Promise.resolve();
    }
  }
}
