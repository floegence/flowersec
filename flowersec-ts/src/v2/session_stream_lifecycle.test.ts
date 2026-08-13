import { describe, expect, test } from "vitest";

import {
  createMemoryCarrierPairV2,
  type CarrierSessionV2,
  type CarrierStreamV2,
} from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { CipherSuiteV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "./session.js";
import { nodeSessionRuntimeV2 } from "../node/sessionRuntime.js";

const LEGACY_RECEIVE_BUFFER_BYTES = 4 * 1024 * 1024;
const DATA_CHUNK_BYTES = 16_384;

function config(role: "client" | "server", maxInboundStreams = 1): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-stream-lifecycle",
    sessionContractHash: new Uint8Array(32).fill(0x91),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x92),
    maxInboundStreams,
    localAdmissionBinding: new Uint8Array(32).fill(0x93),
    peerAdmissionBinding: new Uint8Array(32).fill(0x93),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV2,
  };
}

async function establishPair(
  maxInboundStreams = 1,
): Promise<readonly [SessionV2, SessionV2]> {
  const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({
    kind: "webtransport",
    path: "direct",
    inboundBidirectionalStreamCapacity: maxInboundStreams + 2,
  });
  return await Promise.all([
    establishSessionV2(clientCarrier, config("client", maxInboundStreams)),
    establishSessionV2(serverCarrier, config("server", maxInboundStreams)),
  ]);
}

async function establishFaultPair(): Promise<readonly [SessionV2, SessionV2, FaultInjectingCarrier]> {
  const [rawClientCarrier, serverCarrier] = createMemoryCarrierPairV2({
    kind: "webtransport",
    path: "direct",
    inboundBidirectionalStreamCapacity: 3,
  });
  const clientCarrier = new FaultInjectingCarrier(rawClientCarrier);
  const [client, server] = await Promise.all([
    establishSessionV2(clientCarrier, config("client")),
    establishSessionV2(serverCarrier, config("server")),
  ]);
  return [client, server, clientCarrier];
}

describe("SessionV2 stream lifecycle regressions", () => {
  test("lets a slow consumer drain more than the legacy fixed receive buffer without resetting", async () => {
    const [client, server] = await establishPair();
    const opening = client.openStream("slow-consumer");
    const incoming = await server.acceptStream();
    const outgoing = await opening;
    const payload = Uint8Array.from(
      { length: LEGACY_RECEIVE_BUFFER_BYTES + DATA_CHUNK_BYTES },
      (_value, index) => index % 251,
    );

    // Deliberately do not read until all records exceed the former fixed-buffer limit.
    await outgoing.write(payload);
    await outgoing.closeWrite();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(incoming.stream.terminalError).toBeUndefined();

    let received = 0;
    while (true) {
      const chunk = await incoming.stream.read();
      if (chunk === null) break;
      expect(chunk).toEqual(payload.subarray(received, received + chunk.length));
      received += chunk.length;
    }
    expect(received).toBe(payload.length);
    expect(incoming.stream.terminalError).toBeUndefined();
    expect(server.terminalError).toBeUndefined();

    await incoming.stream.closeWrite();
    await client.close();
  }, 15_000);

  test("makes a carrier DATA write failure terminal and releases exactly one stream permit", async () => {
    const [client, server, carrier] = await establishFaultPair();
    const opening = client.openStream("failed-data-write");
    const incoming = await server.acceptStream();
    const stream = await opening;
    const application = carrier.latestApplicationStream();
    application.failNextWrite(new Error("injected DATA write failure"));

    await expect(stream.write(Uint8Array.of(1))).rejects.toThrow("injected DATA write failure");
    await assertTerminalStream(stream, "injected DATA write failure");
    await expectPeerReset(incoming.stream.read());
    expect(client.terminalError).toBeUndefined();
    await eventually(() => expect(application.resetCalls).toBe(1));
    expect(application.abortCalls).toBe(0);

    await assertOnePermitWasReleased(client, server);
    await client.close();
  });

  test("makes a canceled in-flight DATA write terminal instead of reusing its sequence", async () => {
    const [client, server, carrier] = await establishFaultPair();
    const opening = client.openStream("canceled-data-write");
    const incoming = await server.acceptStream();
    const stream = await opening;
    const application = carrier.latestApplicationStream();
    const controller = new AbortController();
    const blocked = application.blockNextWrite(controller.signal);
    const writing = stream.write(Uint8Array.of(2), { signal: controller.signal });
    await blocked;
    controller.abort(new Error("cancel DATA write"));

    await expect(settlementWithin(writing, 1_000)).resolves.toBe("settled");
    await expect(writing).rejects.toThrow("cancel DATA write");
    await assertTerminalStream(stream, "cancel DATA write");
    await expectPeerReset(incoming.stream.read());
    expect(client.terminalError).toBeUndefined();
    await eventually(() => expect(application.resetCalls).toBe(1));
    expect(application.abortCalls).toBe(0);

    await assertOnePermitWasReleased(client, server);
    await client.close();
  }, 15_000);

  test("makes a FIN record write failure terminal and does not report a later closeWrite as success", async () => {
    const [client, server, carrier] = await establishFaultPair();
    const opening = client.openStream("failed-fin-record");
    const incoming = await server.acceptStream();
    const stream = await opening;
    const application = carrier.latestApplicationStream();
    application.failNextWrite(new Error("injected FIN record failure"));

    await expect(stream.closeWrite()).rejects.toThrow("injected FIN record failure");
    await assertTerminalStream(stream, "injected FIN record failure");
    await expectPeerReset(incoming.stream.read());
    expect(client.terminalError).toBeUndefined();
    await eventually(() => expect(application.resetCalls).toBe(1));
    expect(application.abortCalls).toBe(0);

    await assertOnePermitWasReleased(client, server);
    await client.close();
  });

  test("makes a carrier closeWrite failure terminal after the FIN record was committed", async () => {
    const [client, server, carrier] = await establishFaultPair();
    const opening = client.openStream("failed-carrier-fin");
    const incoming = await server.acceptStream();
    const stream = await opening;
    const application = carrier.latestApplicationStream();
    application.failNextCloseWrite(new Error("injected carrier closeWrite failure"));

    await expect(stream.closeWrite()).rejects.toThrow("injected carrier closeWrite failure");
    await assertTerminalStream(stream, "injected carrier closeWrite failure");
    await eventually(() => expect(incoming.stream.terminalError).toMatchObject({ code: "stream_reset" }));
    expect(client.terminalError).toBeUndefined();
    await eventually(() => expect(application.resetCalls).toBe(1));
    expect(application.abortCalls).toBe(0);

    await assertOnePermitWasReleased(client, server);
    await client.close();
  });

  test("defines close as reset while preserving sibling streams", async () => {
    const [client, server] = await establishPair(2);
    const closingOpen = client.openStream("close-me");
    const closingIncoming = await server.acceptStream();
    const closing = await closingOpen;
    const siblingOpen = client.openStream("sibling");
    const siblingIncoming = await server.acceptStream();
    const sibling = await siblingOpen;

    await closing.close();
    await expectPeerReset(closingIncoming.stream.read());
    await expect(closing.write(Uint8Array.of(3))).rejects.toMatchObject({ code: "stream_reset" });
    await sibling.write(Uint8Array.of(4));
    expect(await siblingIncoming.stream.read()).toEqual(Uint8Array.of(4));
    expect(client.terminalError).toBeUndefined();
    expect(server.terminalError).toBeUndefined();

    await sibling.reset();
    await client.close();
  });

  test("applies a control reset to a stream released after clean bidirectional FIN", async () => {
    const [client, server] = await establishPair(2);
    const opening = client.openStream("late-reset-after-fin");
    const incoming = await server.acceptStream();
    const outgoing = await opening;

    await outgoing.closeWrite();
    expect(await incoming.stream.read()).toBeNull();
    await incoming.stream.closeWrite();
    expect(await outgoing.read()).toBeNull();
    expect(outgoing.terminalError).toBeUndefined();

    await incoming.stream.reset();
    await eventually(() => expect(outgoing.terminalError).toMatchObject({ code: "stream_reset" }));
    await expect(outgoing.read()).rejects.toMatchObject({ code: "stream_reset" });

    const siblingOpening = client.openStream("late-reset-sibling");
    const siblingIncoming = await server.acceptStream();
    const sibling = await siblingOpening;
    await sibling.write(Uint8Array.of(5));
    expect(await siblingIncoming.stream.read()).toEqual(Uint8Array.of(5));
    await sibling.reset();
    await client.close();
  });

  test("keeps late reset observable beyond the former released-stream cache limit", async () => {
    const [client, server] = await establishPair();
    const retained: Array<Awaited<ReturnType<SessionV2["openStream"]>>> = [];
    let firstPeer: Awaited<ReturnType<SessionV2["acceptStream"]>> | undefined;

    for (let index = 0; index < 1_025; index++) {
      const opening = client.openStream(`completed-${index}`);
      const incoming = await server.acceptStream();
      const outgoing = await opening;
      retained.push(outgoing);
      firstPeer ??= incoming;
      await outgoing.closeWrite();
      expect(await incoming.stream.read()).toBeNull();
      await incoming.stream.closeWrite();
      expect(await outgoing.read()).toBeNull();
    }

    expect(retained[0]!.terminalError).toBeUndefined();
    await firstPeer!.stream.reset();
    await eventually(() => expect(retained[0]!.terminalError).toMatchObject({ code: "stream_reset" }));
    await expect(retained[0]!.read()).rejects.toMatchObject({ code: "stream_reset" });
    await client.close();
  }, 30_000);
});

async function assertTerminalStream(
  stream: Awaited<ReturnType<SessionV2["openStream"]>>,
  message: string,
): Promise<void> {
  expect(stream.terminalError).toBeInstanceOf(Error);
  await expect(stream.write(Uint8Array.of(9))).rejects.toThrow(message);
  await expect(stream.closeWrite()).rejects.toThrow(message);
}

async function assertOnePermitWasReleased(client: SessionV2, server: SessionV2): Promise<void> {
  const nextOpening = client.openStream("permit-owner");
  const nextIncoming = await server.acceptStream();
  const next = await nextOpening;
  expect(nextIncoming.kind).toBe("permit-owner");

  const thirdOpening = client.openStream("must-wait");
  await expect(settlementWithin(thirdOpening, 25)).resolves.toBe("pending");

  await next.reset();
  await expectPeerReset(nextIncoming.stream.read());
  const thirdIncoming = await server.acceptStream();
  const third = await thirdOpening;
  expect(thirdIncoming.kind).toBe("must-wait");
  await third.reset();
}

class FaultInjectingCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams;
  private opens = 0;
  private readonly applicationStreams: FaultInjectingStream[] = [];

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    this.opens++;
    if (this.opens === 1) return stream;
    const wrapped = new FaultInjectingStream(stream);
    this.applicationStreams.push(wrapped);
    return wrapped;
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> {
    await this.inner.close(error);
  }

  async waitTermination(): Promise<void> {
    await this.inner.waitTermination();
  }

  abort(error?: Readonly<{ code: number; reason: string }>): void {
    this.inner.abort(error);
  }

  latestApplicationStream(): FaultInjectingStream {
    const stream = this.applicationStreams.at(-1);
    if (stream === undefined) throw new Error("no application stream was opened");
    return stream;
  }
}

class FaultInjectingStream implements CarrierStreamV2 {
  resetCalls = 0;
  abortCalls = 0;
  private writeFailure: Error | undefined;
  private closeWriteFailure: Error | undefined;
  private blockedWrite: Readonly<{ entered: Deferred<void>; signal: AbortSignal }> | undefined;

  constructor(private readonly inner: CarrierStreamV2) {}

  async read(options: OperationOptionsV2 = {}): Promise<Uint8Array | null> {
    return await this.inner.read(options);
  }

  async write(data: Uint8Array, options: OperationOptionsV2 = {}): Promise<number> {
    const failure = this.writeFailure;
    if (failure !== undefined) {
      this.writeFailure = undefined;
      throw failure;
    }
    const blocked = this.blockedWrite;
    if (blocked !== undefined) {
      this.blockedWrite = undefined;
      blocked.entered.resolve();
      await aborted(blocked.signal);
    }
    return await this.inner.write(data, options);
  }

  async closeWrite(): Promise<void> {
    const failure = this.closeWriteFailure;
    if (failure !== undefined) {
      this.closeWriteFailure = undefined;
      throw failure;
    }
    await this.inner.closeWrite();
  }

  async reset(): Promise<void> {
    this.resetCalls++;
    await this.inner.reset();
  }

  async stopSending(): Promise<void> {
    await this.inner.stopSending();
  }

  abort(error?: Error): void {
    this.abortCalls++;
    void error;
  }

  failNextWrite(error: Error): void {
    this.writeFailure = error;
  }

  blockNextWrite(signal: AbortSignal): Promise<void> {
    const entered = deferred<void>();
    this.blockedWrite = { entered, signal };
    return entered.promise;
  }

  failNextCloseWrite(error: Error): void {
    this.closeWriteFailure = error;
  }
}

type Deferred<T> = Readonly<{
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
}>;

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

async function aborted(signal?: AbortSignal): Promise<never> {
  if (signal?.aborted === true) throw signal.reason;
  return await new Promise<never>((_resolve, reject) => {
    signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
  });
}

async function settlementWithin(promise: Promise<unknown>, timeoutMs: number): Promise<"settled" | "pending"> {
  return await Promise.race([
    promise.then(() => "settled" as const, () => "settled" as const),
    new Promise<"pending">((resolve) => setTimeout(() => resolve("pending"), timeoutMs)),
  ]);
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    try {
      assertion();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
  assertion();
}

async function expectPeerReset(operation: Promise<unknown>): Promise<void> {
  await expect(operation).rejects.toMatchObject({ code: "stream_reset" });
}
