import { setImmediate } from "node:timers/promises";
import { expect, test } from "vitest";
import { CarrierError } from "./carrier.js";
import { adaptWebTransportCarrierSessionV3, type WebTransportBidirectionalLikeV3 } from "./webTransportCarrier.js";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function controlledStream() {
  let reader!: ReadableStreamDefaultController<Uint8Array>;
  const entered = deferred<void>();
  const completion = deferred<void>();
  const aborted = deferred<unknown>();
  const readable = new ReadableStream<Uint8Array>({ start(controller) { reader = controller; } });
  const writable = new WritableStream<Uint8Array>({
    close() { entered.resolve(); return completion.promise; },
    abort(reason) { aborted.resolve(reason); },
  });
  return { readable, writable, reader, entered, completion, aborted };
}

function setup() {
  let incoming!: ReadableStreamDefaultController<WebTransportBidirectionalLikeV3>;
  const closed = deferred<unknown>();
  const carrier = adaptWebTransportCarrierSessionV3({
    closed: closed.promise,
    incomingBidirectionalStreams: new ReadableStream({ start(controller) { incoming = controller; } }),
    datagrams: { readable: new ReadableStream(), writable: new WritableStream(), maxDatagramSize: 1_200 },
    async createBidirectionalStream() { throw new Error("unexpected outgoing stream"); },
    close(info) { closed.resolve(info); },
  }, { path: "direct", inboundBidirectionalStreamCapacity: 3 });
  return { carrier, closed, incoming };
}

test.each([
  [undefined, false], [{ closeCode: 1 }, false], [{ closeCode: 0, reason: "session closed" }, false],
  [{ closeCode: 1, reason: "session closed " }, false], [{ closeCode: 1, reason: "session closed" }, true],
] as const)("checks the remote session close event %j", async (info, expected) => {
  const { carrier, closed } = setup();
  closed.resolve(info);
  expect(await carrier.waitRemoteSessionClose!()).toBe(expected);
});

test("does not accept a local close as a remote session close event", async () => {
  const { carrier, closed } = setup();
  await carrier.close({ code: 1, reason: "session closed" });
  expect(await closed.promise).toEqual({ closeCode: 1, reason: "session closed" });
  expect(await carrier.waitRemoteSessionClose!()).toBe(false);
});

test("holds inbound capacity after read EOF until the native FIN completes", async () => {
  const { carrier, incoming } = setup();
  const native = controlledStream();
  try {
    incoming.enqueue(native);
    const stream = await carrier.acceptStream();
    for (let index = 0; index < 2; index++) {
      incoming.enqueue(controlledStream());
      await carrier.acceptStream();
    }
    const closing = stream.closeWrite();
    await native.entered.promise;
    await expect(stream.write(new Uint8Array([1]))).rejects.toMatchObject({ code: "write_closed" });
    native.reader.close();
    const overflow = controlledStream();
    incoming.enqueue(overflow);
    const aborted = await Promise.race([overflow.aborted.promise, setImmediate("still open")]);
    expect(aborted).toMatchObject({ code: "reset" });
    native.completion.resolve();
    await closing;
    const replacement = controlledStream();
    incoming.enqueue(replacement);
    replacement.reader.enqueue(new Uint8Array([7]));
    await expect((await carrier.acceptStream()).read()).resolves.toEqual(new Uint8Array([7]));
  } finally {
    native.completion.resolve();
    await carrier.close();
  }
});

test("preserves buffered data and releases capacity after the last bytes without an EOF read", async () => {
  const { carrier, incoming } = setup();
  const native = controlledStream();
  try {
    incoming.enqueue(native);
    const stream = await carrier.acceptStream();
    for (let index = 0; index < 2; index++) {
      incoming.enqueue(controlledStream());
      await carrier.acceptStream();
    }
    native.reader.enqueue(Uint8Array.of(42));
    native.reader.close();
    native.completion.resolve();
    await stream.closeWrite();
    const overflow = controlledStream();
    incoming.enqueue(overflow);
    await expect(overflow.aborted.promise).resolves.toMatchObject({ code: "reset" });
    await expect(stream.read()).resolves.toEqual(Uint8Array.of(42));
    incoming.enqueue(controlledStream());
    await expect(carrier.acceptStream()).resolves.toBeDefined();
  } finally { await carrier.close(); }
});

test.each(["session", "peer read reset", "local reset"] as const)(
  "rejects pending native FIN with the first %s error before the sink settles", async (cause) => {
    const { carrier, incoming, closed } = setup();
    const native = controlledStream();
    incoming.enqueue(native);
    const stream = await carrier.acceptStream();
    const outcome = stream.closeWrite().then(() => "success", (reason: unknown) => reason);
    await native.entered.promise;
    let reset: Promise<void> | undefined;
    try {
      if (cause === "session") {
        native.reader.close();
        await expect(stream.read()).resolves.toBeNull();
        closed.reject(new Error("carrier gone"));
        await expect(carrier.waitTermination()).rejects.toThrow("WebTransport terminated");
      } else if (cause === "peer read reset") {
        native.reader.error(new Error("peer reset"));
      } else {
        reset = stream.reset();
      }
      const readError = await stream.read().catch((error: unknown) => error);
      expect(readError).toBeInstanceOf(CarrierError);
      const first = await Promise.race([outcome, setImmediate("still pending")]);
      expect(first).toBe(readError);
      native.completion.reject(new Error("late native FIN failure"));
      await expect(stream.closeWrite()).rejects.toBe(first);
      await expect(stream.read()).rejects.toBe(first);
    } finally {
      native.completion.resolve();
      await reset;
      await carrier.close();
    }
  },
);

test("native FIN rejection terminates the stream with the same error seen by a pending read", async () => {
  const { carrier, incoming } = setup();
  const native = controlledStream();
  incoming.enqueue(native);
  const stream = await carrier.acceptStream();
  try {
    const reading = stream.read().catch((reason: unknown) => reason);
    const closing = stream.closeWrite().catch((reason: unknown) => reason);
    await native.entered.promise;
    const cause = new Error("sink rejected FIN");
    native.completion.reject(cause);
    const first = await closing;
    expect(first).toMatchObject({ code: "reset", cause });
    expect(await Promise.race([reading, setImmediate("still pending")])).toBe(first);
    await expect(stream.write(new Uint8Array([1]))).rejects.toBe(first);
  } finally {
    await carrier.close();
  }
});
