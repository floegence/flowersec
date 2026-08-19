import { describe, expect, test } from "vitest";

import { createMemoryCarrierPairV3, type CarrierSessionV3, type CarrierStreamV3 } from "./carrier.js";
import type { OperationOptionsV3 } from "./contract.js";
import { CipherSuiteV3, InnerTypeV3 } from "./protocol.js";
import { establishSessionV3, SessionV3Error, type SessionConfigV3, type SessionV3 } from "./session.js";
import { nodeSessionRuntimeV3 } from "./nodeSessionRuntime.js";

function config(role: "client" | "server"): SessionConfigV3 {
  return {
    role,
    path: "direct",
    channelID: "session-v3-control-terminal",
    sessionContractHash: new Uint8Array(32).fill(0x41),
    suite: CipherSuiteV3.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x42),
    maxInboundStreams: 1,
    localAdmissionBinding: new Uint8Array(32).fill(0x43),
    peerAdmissionBinding: new Uint8Array(32).fill(0x43),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV3,
    idleTimeoutMs: 0,
    closeTimeoutMs: 500,
  };
}

describe("SessionV3 control terminal serialization", () => {
  test("seals queued responses and appends GOAWAY, SESSION_CLOSE, and FIN after owned cleanup", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    await client.openStream("terminal-reset");
    await server.acceptStream();
    const internals = sessionInternals(client);

    clientCarrier.blockNextControlWrite();
    const active = internals.sendControl(InnerTypeV3.Ping, new Uint8Array(8));
    await clientCarrier.blockedWriteEntered.promise;
    const cleanup = internals.sendControlCleanup(InnerTypeV3.StreamReset, idReason(1n, 6));
    const pong = internals.sendControlResponse(InnerTypeV3.Pong, new Uint8Array(8));
    const rekeyACK = internals.sendControlResponse(InnerTypeV3.SessionKeyUpdateACK, new Uint8Array(20));
    const closing = client.close();

    await expect(internals.sendControl(InnerTypeV3.Ping, new Uint8Array(8))).rejects.toThrow(/sealed|closed/);
    await expect(internals.sendControlCleanup(InnerTypeV3.StreamReset, idReason(3n, 6))).resolves.toBe(false);
    await expect(internals.sendControlResponse(InnerTypeV3.Pong, new Uint8Array(8))).resolves.toBe(false);
    clientCarrier.releaseBlockedWrite();

    await expect(active).resolves.toBeUndefined();
    await expect(cleanup).resolves.toBe(true);
    await expect(pong).resolves.toBe(false);
    await expect(rekeyACK).resolves.toBe(false);
    await expect(closing).resolves.toBeUndefined();
    expect(clientCarrier.controlEvents).toEqual(["write", "write", "write", "write", "fin"]);
    expect(clientCarrier.writesAfterFIN).toBe(0);
    expect(clientCarrier.aborts).toBe(0);
  });

  test("does not commit a receive rekey when its ACK is suppressed", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const sendControlResponse = internals.sendControlResponse.bind(client);
    internals.sendControlResponse = async (type) => {
      expect(type).toBe(InnerTypeV3.SessionKeyUpdateACK);
      return false;
    };

    await internals.receiveSessionRekeyBeforeDeadline(sessionRekeyPayload(), new AbortController().signal);

    expect(internals.receiveEpoch).toBe(0);
    expect(internals.receiveTransition).toBe(0n);
    expect(internals.pendingReceiveEpoch).toBeUndefined();
    expect([...internals.receiveRoots.keys()]).toEqual([0]);
    internals.sendControlResponse = sendControlResponse;
    await client.close();
    await server.waitTermination();
  });

  test("does not consume a session rekey transition when prepare is cancelled", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const entered = deferred<void>();
    const release = deferred<void>();
    const controller = new AbortController();
    const originalWait = internals.waitOutboundFrontier;
    internals.waitOutboundFrontier = async (_watermark, signal) => {
      entered.resolve();
      await abortableWait(release.promise, signal);
    };
    try {
      const operation = client.rekey({ signal: controller.signal });
      await entered.promise;
      controller.abort(new SessionV3Error("aborted", "test cancellation"));
      await expect(operation).rejects.toMatchObject({ code: "aborted" });
      expect(internals.nextTransition).toBe(1n);
    } finally {
      release.resolve();
      internals.waitOutboundFrontier = originalWait;
      await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
    }
  });

  test("caller cancellation after rekey commit does not terminate the session", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const entered = deferred<void>();
    const release = deferred<void>();
    const originalSendResponse = serverInternals.sendControlResponse.bind(server);
    serverInternals.sendControlResponse = async (type, payload) => {
      if (type === InnerTypeV3.SessionKeyUpdateACK) {
        entered.resolve();
        await release.promise;
      }
      return await originalSendResponse(type, payload);
    };
    const controller = new AbortController();
    const operation = client.rekey({ signal: controller.signal });
    await entered.promise;
    controller.abort(new SessionV3Error("aborted", "test cancellation"));
    await expect(operation).rejects.toMatchObject({ code: "aborted" });
    release.resolve();
    const internals = sessionInternals(client);
    await waitFor(() => internals.sendEpoch === 1 && internals.pendingSessionRekey === undefined);
    expect(client.terminalError).toBeUndefined();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });

  test("session failure rejects and clears a pending session rekey ACK immediately", async () => {
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV3({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV3(clientCarrier, config("client")),
      establishSessionV3(serverCarrier, config("server")),
    ]);
    const serverInternals = sessionInternals(server);
    const entered = deferred<void>();
    const release = deferred<void>();
    const originalSendResponse = serverInternals.sendControlResponse.bind(server);
    serverInternals.sendControlResponse = async (type, payload) => {
      if (type === InnerTypeV3.SessionKeyUpdateACK) {
        entered.resolve();
        await release.promise;
      }
      return await originalSendResponse(type, payload);
    };
    const operation = client.rekey();
    await entered.promise;
    const clientInternals = sessionInternals(client);
    expect(clientInternals.pendingSessionRekey).toBeDefined();
    clientInternals.fail(new SessionV3Error("closed", "test failure"), false);
    await expect(operation).rejects.toMatchObject({ code: "closed" });
    expect(clientInternals.pendingSessionRekey).toBeUndefined();
    release.resolve();
    await Promise.all([client.close().catch(() => undefined), server.close().catch(() => undefined)]);
  });
});

type SessionInternals = {
  sendControl(type: InnerTypeV3, payload: Uint8Array): Promise<void>;
  sendControlResponse(type: InnerTypeV3, payload: Uint8Array): Promise<boolean>;
  sendControlCleanup(type: InnerTypeV3, payload: Uint8Array): Promise<boolean>;
  receiveSessionRekeyBeforeDeadline(payload: Uint8Array, signal: AbortSignal): Promise<void>;
  receiveEpoch: number;
  receiveTransition: bigint;
  pendingReceiveEpoch: number | undefined;
  receiveRoots: Map<number, unknown>;
  nextTransition: bigint;
  sendEpoch: number;
  pendingSessionRekey: unknown;
  waitOutboundFrontier(watermark: bigint, signal: AbortSignal): Promise<void>;
  fail(error: Error, abortCarrier?: boolean): void;
};

function sessionInternals(session: SessionV3): SessionInternals {
  return session as unknown as SessionInternals;
}

async function abortableWait<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw signal.reason;
  return await new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    void promise.then(
      (value) => { signal.removeEventListener("abort", abort); resolve(value); },
      (error) => { signal.removeEventListener("abort", abort); reject(error); },
    );
  });
}

async function waitFor(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for session rekey");
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
}

class TerminalOrderingCarrier implements CarrierSessionV3 {
  readonly kind: CarrierSessionV3["kind"];
  readonly path: CarrierSessionV3["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV3["unreliableDatagrams"];
  readonly blockedWriteEntered = deferred<void>();
  readonly controlEvents: string[] = [];
  writesAfterFIN = 0;
  aborts = 0;
  private opens = 0;
  private tracking = false;
  private blockNext = false;
  private fin = false;
  private readonly blockedWriteRelease = deferred<void>();

  constructor(private readonly inner: CarrierSessionV3) {
    this.kind = inner.kind;
    this.path = inner.path;
    this.inboundBidirectionalStreamCapacity = inner.inboundBidirectionalStreamCapacity;
    this.unreliableDatagrams = inner.unreliableDatagrams;
  }

  blockNextControlWrite(): void {
    this.tracking = true;
    this.blockNext = true;
  }

  releaseBlockedWrite(): void {
    this.blockedWriteRelease.resolve();
  }

  async openStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    const stream = await this.inner.openStream(options);
    const control = this.opens++ === 0;
    return control ? this.wrapControl(stream) : stream;
  }

  async acceptStream(options: OperationOptionsV3 = {}): Promise<CarrierStreamV3> {
    return await this.inner.acceptStream(options);
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.aborts++; this.inner.abort(error); }

  private wrapControl(stream: CarrierStreamV3): CarrierStreamV3 {
    return {
      read: async (options) => await stream.read(options),
      write: async (data, options) => {
        if (this.tracking) {
          if (this.fin) this.writesAfterFIN++;
          this.controlEvents.push("write");
          if (this.blockNext) {
            this.blockNext = false;
            this.blockedWriteEntered.resolve();
            await this.blockedWriteRelease.promise;
          }
        }
        return await stream.write(data, options);
      },
      closeWrite: async () => {
        if (this.tracking) {
          this.fin = true;
          this.controlEvents.push("fin");
        }
        await stream.closeWrite();
      },
      stopSending: async () => await stream.stopSending(),
      reset: async () => await stream.reset(),
      abort: (error) => stream.abort(error),
    };
  }
}

function idReason(id: bigint, reason: number): Uint8Array {
  const output = new Uint8Array(10);
  const view = new DataView(output.buffer);
  view.setBigUint64(0, id);
  view.setUint16(8, reason);
  return output;
}

function sessionRekeyPayload(): Uint8Array {
  const output = new Uint8Array(20);
  const view = new DataView(output.buffer);
  view.setBigUint64(0, 1n);
  view.setUint32(8, 1);
  view.setBigUint64(12, 0n);
  return output;
}

function deferred<T = void>(): Readonly<{
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
}> {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}
