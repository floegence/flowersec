import { describe, expect, test } from "vitest";

import {
  createMemoryCarrierPairV2,
  type CarrierSessionV2,
  type CarrierStreamV2,
} from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { CipherSuiteV2 } from "./protocol.js";
import { SessionV2, establishSessionV2, type SessionConfigV2 } from "./session.js";
import { nodeSessionRuntimeV2 } from "../node/sessionRuntime.js";

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const text = (value: Uint8Array): string => new TextDecoder().decode(value);

function configs(maxInboundStreams = 8): readonly [SessionConfigV2, SessionConfigV2] {
  const common = {
    path: "direct" as const,
    channelID: "session-v2-test",
    sessionContractHash: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: Uint8Array.from({ length: 32 }, (_, index) => 0xa0 + index),
    maxInboundStreams,
    localAdmissionBinding: Uint8Array.from({ length: 32 }, (_, index) => 0x40 + index),
    peerAdmissionBinding: Uint8Array.from({ length: 32 }, (_, index) => 0x40 + index),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV2,
  };
  return [{ ...common, role: "client" }, { ...common, role: "server" }];
}

async function establishPair(maxInboundStreams = 8): Promise<readonly [SessionV2, SessionV2]> {
  const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({ kind: "webtransport", path: "direct", inboundBidirectionalStreamCapacity: maxInboundStreams + 2 });
  const [clientConfig, serverConfig] = configs(maxInboundStreams);
  return await Promise.all([
    establishSessionV2(clientCarrier, clientConfig),
    establishSessionV2(serverCarrier, serverConfig),
  ]);
}

function blockCarrierWritesAfter(
  inner: CarrierSessionV2,
  blocked: () => boolean,
  applicationOnly = false,
): CarrierSessionV2 {
  let opens = 0;
  const wrapStream = async (stream: CarrierStreamV2): Promise<CarrierStreamV2> => ({
    read: (options) => stream.read(options),
    write: (data, options = {}) => {
      if (!blocked()) return stream.write(data, options);
      return new Promise<number>((_resolve, reject) => {
        if (options.signal?.aborted === true) {
          reject(options.signal.reason);
          return;
        }
        options.signal?.addEventListener("abort", () => reject(options.signal!.reason), { once: true });
      });
    },
    closeWrite: () => stream.closeWrite(),
    reset: () => stream.reset(),
    stopSending: () => stream.stopSending(),
    abort: (error) => stream.abort(error),
  });
  return {
    kind: inner.kind,
    path: inner.path,
    inboundBidirectionalStreamCapacity: inner.inboundBidirectionalStreamCapacity,
    unreliableDatagrams: inner.unreliableDatagrams,
    openStream: async (options) => {
      const stream = await inner.openStream(options);
      opens++;
      return applicationOnly && opens === 1 ? stream : await wrapStream(stream);
    },
    acceptStream: async (options) => await wrapStream(await inner.acceptStream(options)),
    close: (error) => inner.close(error),
    abort: (error) => inner.abort(error),
    waitTermination: () => inner.waitTermination(),
  };
}

function failApplicationCloseWrite(inner: CarrierSessionV2): CarrierSessionV2 {
  let opens = 0;
  const wrapStream = (stream: CarrierStreamV2): CarrierStreamV2 => ({
    read: (options) => stream.read(options),
    write: (data, options) => stream.write(data, options),
    closeWrite: async () => { throw new Error("injected application FIN failure"); },
    reset: () => stream.reset(),
    stopSending: () => stream.stopSending(),
    abort: (error) => stream.abort(error),
  });
  return {
    kind: inner.kind,
    path: inner.path,
    inboundBidirectionalStreamCapacity: inner.inboundBidirectionalStreamCapacity,
    unreliableDatagrams: inner.unreliableDatagrams,
    openStream: async (options) => {
      const stream = await inner.openStream(options);
      opens++;
      return opens === 1 ? stream : wrapStream(stream);
    },
    acceptStream: (options) => inner.acceptStream(options),
    close: (error) => inner.close(error),
    abort: (error) => inner.abort(error),
    waitTermination: () => inner.waitTermination(),
  };
}

class BlockedResetCarrier implements CarrierSessionV2 {
  readonly kind;
  readonly path;
  readonly inboundBidirectionalStreamCapacity: number;
  applicationOpens = 0;
  applicationResetCalls = 0;
  controlWriteBlocked = false;
  private readonly controlGate = deferred<void>();
  private blockControl = false;
  private blockApplication = false;

  constructor(private readonly inner: CarrierSessionV2) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
  }

  blockNextResetAndDataWrite(): void {
    this.blockControl = true;
    this.blockApplication = true;
  }

  releaseControlWrite(): void { this.controlGate.resolve(); }

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    const control = this.applicationOpens === 0;
    this.applicationOpens++;
    return this.wrap(stream, control);
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.controlGate.resolve(); this.inner.abort(error); }

  private wrap(stream: CarrierStreamV2, control: boolean): CarrierStreamV2 {
    return {
      read: (options) => stream.read(options),
      write: async (data, options = {}) => {
        if (control && this.blockControl) {
          this.blockControl = false;
          this.controlWriteBlocked = true;
          await this.controlGate.promise;
          return await stream.write(data, options);
        }
        if (!control && this.blockApplication) {
          this.blockApplication = false;
          return await new Promise<number>((_resolve, reject) => {
            if (options.signal?.aborted === true) reject(options.signal.reason);
            else options.signal?.addEventListener("abort", () => reject(options.signal!.reason), { once: true });
          });
        }
        return await stream.write(data, options);
      },
      closeWrite: () => stream.closeWrite(),
      reset: async () => {
        if (!control) this.applicationResetCalls++;
        await stream.reset();
      },
      stopSending: () => stream.stopSending(),
      abort: (error) => stream.abort(error),
    };
  }
}

function deferred<T>(): Readonly<{ promise: Promise<T>; resolve(value: T | PromiseLike<T>): void }> {
  let resolvePromise!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolve) => { resolvePromise = resolve; });
  return { promise, resolve: resolvePromise };
}

describe("SessionV2", () => {
  test("aborts a liveness control write with the operation signal", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    let blocked = false;
    const [client] = await Promise.all([
      establishSessionV2(blockCarrierWritesAfter(rawClient, () => blocked), configs()[0]),
      establishSessionV2(serverCarrier, configs()[1]),
    ]);
    blocked = true;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error("liveness deadline")), 20);
    try {
      const outcome = await Promise.race([
        client.probeLiveness({ signal: controller.signal }).then(() => "resolved", (error) => error),
        new Promise<string>((resolve) => setTimeout(() => resolve("hung"), 100)),
      ]);
      expect(outcome).not.toBe("hung");
      expect(outcome).toBeInstanceOf(Error);
    } finally {
      clearTimeout(timer);
      rawClient.abort({ code: 6, reason: "test cleanup" });
      serverCarrier.abort({ code: 6, reason: "test cleanup" });
    }
  });

  test("rejects an N=1 physical-capacity mismatch before opening the control stream", async () => {
    const [inner] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    let opens = 0;
    const mismatched: CarrierSessionV2 = {
      kind: inner.kind,
      path: inner.path,
      inboundBidirectionalStreamCapacity: 4,
      openStream: async (options) => {
        opens++;
        return await inner.openStream(options);
      },
      acceptStream: async (options) => await inner.acceptStream(options),
      close: async (error) => await inner.close(error),
      abort: (error) => inner.abort(error),
      waitTermination: () => inner.waitTermination(),
    };
    const [clientConfig] = configs(1);
    await expect(establishSessionV2(mismatched, clientConfig)).rejects.toThrow("capacity mismatch");
    expect(opens).toBe(0);
  });

  test("establishes through READY and carries bidirectional encrypted logical streams", async () => {
    const [client, server] = await establishPair();
    expect(client).toBeInstanceOf(SessionV2);
    expect(server.path).toBe("direct");

    const opened = client.openStream("echo", { metadata: { locale: "zh-CN", retry: 2 } });
    const incoming = await server.acceptStream();
    const clientStream = await opened;
    expect(incoming.id).toBe(1n);
    expect(incoming.kind).toBe("echo");
    expect(incoming.metadata).toEqual({ locale: "zh-CN", retry: 2 });

    await clientStream.write(bytes("request"));
    expect(text((await incoming.stream.read())!)).toBe("request");
    await clientStream.closeWrite();
    expect(await incoming.stream.read()).toBeNull();
    await incoming.stream.write(bytes("response"));
    expect(text((await clientStream.read())!)).toBe("response");
    await incoming.stream.closeWrite();
    expect(await clientStream.read()).toBeNull();
    expect(clientStream.terminalError).toBeUndefined();

    expect(await client.probeLiveness()).toBeGreaterThanOrEqual(0);
    await client.close();
    await expect(server.acceptStream()).rejects.toThrow("closed");
    expect(server.terminalError).toBeInstanceOf(Error);
  });

  test("backpressures a slow reader instead of resetting after the receive high-water mark", async () => {
    const [client, server] = await establishPair();
    const opened = client.openStream("slow-reader");
    const incoming = await server.acceptStream();
    const stream = await opened;
    const payload = new Uint8Array(4 * 1024 * 1024 + 16_384).fill(0x5a);

    await stream.write(payload);
    let received = 0;
    while (true) {
      const chunk = await incoming.stream.read();
      if (chunk === null) break;
      received += chunk.length;
      if (received === payload.length) break;
    }
    expect(received).toBe(payload.length);
    expect(incoming.stream.terminalError).toBeUndefined();

    await stream.reset();
    await client.close();
  });

  test("resumes stream rekey after a backpressured reader consumes earlier data", async () => {
    const [client, server] = await establishPair();
    const opened = client.openStream("slow-reader-rekey");
    const incoming = await server.acceptStream();
    const stream = await opened;
    const payload = new Uint8Array(4 * 1024 * 1024 + 16_384).fill(0x33);

    let writeSettled = false;
    let rekeySettled = false;
    const writing = stream.write(payload).then((written) => {
      writeSettled = true;
      return written;
    });
    const rekeying = client.rekey().then(() => { rekeySettled = true; });
    expect(writeSettled).toBe(false);
    expect(rekeySettled).toBe(false);

    let received = 0;
    while (received < payload.length) {
      const chunk = await incoming.stream.read();
      if (chunk === null) throw new Error("unexpected FIN before the backpressured payload completed");
      expect(chunk.every((value) => value === 0x33)).toBe(true);
      received += chunk.length;
    }
    expect(received).toBe(payload.length);
    expect(await writing).toBe(payload.length);
    await Promise.race([
      rekeying,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("stream rekey did not resume after capacity became available")), 500)),
    ]);
    expect(writeSettled).toBe(true);
    expect(rekeySettled).toBe(true);
    expect(incoming.stream.terminalError).toBeUndefined();

    await stream.reset();
    await client.close();
  });

  test("resets a stream when a pending application write is canceled", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    let blocked = false;
    const [client, server] = await Promise.all([
      establishSessionV2(blockCarrierWritesAfter(rawClient, () => blocked, true), configs()[0]),
      establishSessionV2(serverCarrier, configs()[1]),
    ]);
    const opened = client.openStream("cancel-write");
    const incoming = await server.acceptStream();
    const stream = await opened;
    blocked = true;
    const controller = new AbortController();
    const writing = stream.write(Uint8Array.of(1), { signal: controller.signal });
    controller.abort(new Error("cancel application write"));

    await expect(writing).rejects.toThrow("cancel application write");
    expect(stream.terminalError).toMatchObject({ message: "cancel application write" });
    await expect(incoming.stream.read()).rejects.toThrow("reset");
    await client.close();
  });

  test("settles a canceled write and releases its permit before ordered reset commit", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const blocked = new BlockedResetCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV2(blocked, configs(1)[0]),
      establishSessionV2(serverCarrier, configs(1)[1]),
    ]);
    const internals = sessionInternals(client);
    let localResetCommits = 0;
    const commitLocalReset = internals.commitLocalReset.bind(client);
    internals.commitLocalReset = (id) => { localResetCommits++; commitLocalReset(id); };
    const opened = client.openStream("cancel-write-before-reset-commit");
    await server.acceptStream();
    const stream = await opened;
    blocked.blockNextResetAndDataWrite();
    const controller = new AbortController();
    const writing = stream.write(Uint8Array.of(1), { signal: controller.signal });
    controller.abort(new Error("cancel while reset control is blocked"));

    await expect(Promise.race([
      writing,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("canceled write did not settle")), 100)),
    ])).rejects.toThrow("cancel while reset control is blocked");
    await eventually(() => expect(blocked.controlWriteBlocked).toBe(true));
    expect(localResetCommits).toBe(0);
    expect(blocked.applicationResetCalls).toBe(0);

    const nextOpen = client.openStream("permit-released-before-reset-commit");
    void nextOpen.catch(() => undefined);
    await eventually(() => expect(blocked.applicationOpens).toBe(3));

    blocked.releaseControlWrite();
    await eventually(() => expect(localResetCommits).toBe(1));
    await eventually(() => expect(blocked.applicationResetCalls).toBe(1));
    rawClient.abort({ code: 6, reason: "test cleanup" });
    serverCarrier.abort({ code: 6, reason: "test cleanup" });
  });

  test("does not commit local FIN when the carrier half-close fails", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    const [client, server] = await Promise.all([
      establishSessionV2(failApplicationCloseWrite(rawClient), configs()[0]),
      establishSessionV2(serverCarrier, configs()[1]),
    ]);
    const opened = client.openStream("failed-fin");
    const incoming = await server.acceptStream();
    const stream = await opened;

    const firstClose = stream.closeWrite();
    const secondClose = stream.closeWrite();
    await expect(firstClose).rejects.toThrow("injected application FIN failure");
    await expect(secondClose).rejects.toThrow("injected application FIN failure");
    expect(stream.terminalError).toMatchObject({ message: "injected application FIN failure" });
    await expect(stream.closeWrite()).rejects.toThrow("injected application FIN failure");
    await expect(incoming.stream.read()).rejects.toThrow("reset");
    await client.close();
  });

  test("isolates reset, enforces stream limits, and preserves canceled accepts", async () => {
    const [client, server] = await establishPair(2);
    const firstOpen = client.openStream("first");
    const firstIncoming = await server.acceptStream();
    const first = await firstOpen;
    const secondOpen = client.openStream("second");
    const secondIncoming = await server.acceptStream();
    const second = await secondOpen;

    const third = client.openStream("third");
    await expect(Promise.race([
      third.then(() => "opened"),
      new Promise<string>((resolve) => setTimeout(() => resolve("blocked"), 20)),
    ])).resolves.toBe("blocked");

    await first.reset();
    await expect(firstIncoming.stream.read()).rejects.toThrow("reset");
    const thirdIncoming = await server.acceptStream();
    const thirdStream = await third;
    expect(thirdIncoming.kind).toBe("third");
    await second.write(bytes("still-live"));
    expect(text((await secondIncoming.stream.read())!)).toBe("still-live");
    await thirdStream.reset();

    const controller = new AbortController();
    const canceled = server.acceptStream({ signal: controller.signal });
    controller.abort();
    await expect(canceled).rejects.toThrow("aborted");

    const afterCanceledOpen = client.openStream("after-canceled-accept");
    const afterCanceledIncoming = await Promise.race([
      server.acceptStream(),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("next accept was consumed")), 100)),
    ]);
    const afterCanceled = await afterCanceledOpen;
    expect(afterCanceledIncoming.kind).toBe("after-canceled-accept");
    await afterCanceled.reset();
    await client.close();
  });

  test("returns a queued outbound permit when the waiting open is canceled", async () => {
    const [client, server] = await establishPair(1);
    const firstOpen = client.openStream("permit-owner");
    const firstIncoming = await server.acceptStream();
    const first = await firstOpen;

    const controller = new AbortController();
    const canceled = client.openStream("canceled-waiter", { signal: controller.signal });
    controller.abort();
    await expect(canceled).rejects.toThrow("aborted");
    await first.reset();
    await expect(firstIncoming.stream.read()).rejects.toThrow("reset");

    const nextOpen = client.openStream("after-canceled-waiter");
    const nextIncoming = await server.acceptStream();
    const next = await Promise.race([
      nextOpen,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("permit leaked to canceled waiter")), 100)),
    ]);
    expect(nextIncoming.kind).toBe("after-canceled-waiter");
    await next.reset();
    await client.close();
  });
});

type SessionInternals = {
  commitLocalReset(id: bigint): void;
};

function sessionInternals(session: SessionV2): SessionInternals {
  return session as unknown as SessionInternals;
}

async function eventually(assertion: () => void): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try { assertion(); return; } catch { await new Promise((resolve) => setTimeout(resolve, 1)); }
  }
  assertion();
}
