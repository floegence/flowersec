import { describe, expect, test } from "vitest";

import { createMemoryCarrierPairV2, type CarrierSessionV2, type CarrierStreamV2 } from "./carrier.js";
import type { OperationOptionsV2 } from "./contract.js";
import { CipherSuiteV2, InnerTypeV2 } from "./protocol.js";
import { establishSessionV2, type SessionConfigV2, type SessionV2 } from "./session.js";
import { nodeSessionRuntimeV2 } from "../node/sessionRuntime.js";

function config(role: "client" | "server"): SessionConfigV2 {
  return {
    role,
    path: "direct",
    channelID: "session-v2-control-terminal",
    sessionContractHash: new Uint8Array(32).fill(0x31),
    suite: CipherSuiteV2.ChaCha20Poly1305,
    psk: new Uint8Array(32).fill(0x32),
    maxInboundStreams: 1,
    localAdmissionBinding: new Uint8Array(32).fill(0x33),
    peerAdmissionBinding: new Uint8Array(32).fill(0x33),
    localEndpointInstanceID: "",
    expectedPeerEndpointInstanceID: "",
    runtime: nodeSessionRuntimeV2,
    idleTimeoutMs: 0,
    closeTimeoutMs: 500,
  };
}

describe("SessionV2 control terminal serialization", () => {
  test("seals queued responses and appends GOAWAY, SESSION_CLOSE, and FIN after owned cleanup", async () => {
    const [rawClient, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const clientCarrier = new TerminalOrderingCarrier(rawClient);
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    await client.openStream("terminal-reset");
    await server.acceptStream();
    const internals = sessionInternals(client);

    clientCarrier.blockNextControlWrite();
    const active = internals.sendControl(InnerTypeV2.Ping, new Uint8Array(8));
    await clientCarrier.blockedWriteEntered.promise;
    const cleanup = internals.sendControlCleanup(InnerTypeV2.StreamReset, idReason(1n, 6));
    const pong = internals.sendControlResponse(InnerTypeV2.Pong, new Uint8Array(8));
    const rekeyACK = internals.sendControlResponse(InnerTypeV2.SessionKeyUpdateACK, new Uint8Array(20));
    const closing = client.close();

    await expect(internals.sendControl(InnerTypeV2.Ping, new Uint8Array(8))).rejects.toThrow(/sealed|closed/);
    await expect(internals.sendControlCleanup(InnerTypeV2.StreamReset, idReason(3n, 6))).resolves.toBe(false);
    await expect(internals.sendControlResponse(InnerTypeV2.Pong, new Uint8Array(8))).resolves.toBe(false);
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
    const [clientCarrier, serverCarrier] = createMemoryCarrierPairV2({
      kind: "webtransport",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
    });
    const [client, server] = await Promise.all([
      establishSessionV2(clientCarrier, config("client")),
      establishSessionV2(serverCarrier, config("server")),
    ]);
    const internals = sessionInternals(client);
    const sendControlResponse = internals.sendControlResponse.bind(client);
    internals.sendControlResponse = async (type) => {
      expect(type).toBe(InnerTypeV2.SessionKeyUpdateACK);
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
});

type SessionInternals = {
  sendControl(type: InnerTypeV2, payload: Uint8Array): Promise<void>;
  sendControlResponse(type: InnerTypeV2, payload: Uint8Array): Promise<boolean>;
  sendControlCleanup(type: InnerTypeV2, payload: Uint8Array): Promise<boolean>;
  receiveSessionRekeyBeforeDeadline(payload: Uint8Array, signal: AbortSignal): Promise<void>;
  receiveEpoch: number;
  receiveTransition: bigint;
  pendingReceiveEpoch: number | undefined;
  receiveRoots: Map<number, unknown>;
};

function sessionInternals(session: SessionV2): SessionInternals {
  return session as unknown as SessionInternals;
}

class TerminalOrderingCarrier implements CarrierSessionV2 {
  readonly kind: CarrierSessionV2["kind"];
  readonly path: CarrierSessionV2["path"];
  readonly inboundBidirectionalStreamCapacity: number;
  readonly unreliableDatagrams: CarrierSessionV2["unreliableDatagrams"];
  readonly blockedWriteEntered = deferred<void>();
  readonly controlEvents: string[] = [];
  writesAfterFIN = 0;
  aborts = 0;
  private opens = 0;
  private tracking = false;
  private blockNext = false;
  private fin = false;
  private readonly blockedWriteRelease = deferred<void>();

  constructor(private readonly inner: CarrierSessionV2) {
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

  async openStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    const stream = await this.inner.openStream(options);
    const control = this.opens++ === 0;
    return control ? this.wrapControl(stream) : stream;
  }

  async acceptStream(options: OperationOptionsV2 = {}): Promise<CarrierStreamV2> {
    return await this.inner.acceptStream(options);
  }

  async waitTermination(): Promise<void> { await this.inner.waitTermination(); }
  async close(error?: Readonly<{ code: number; reason: string }>): Promise<void> { await this.inner.close(error); }
  abort(error?: Readonly<{ code: number; reason: string }>): void { this.aborts++; this.inner.abort(error); }

  private wrapControl(stream: CarrierStreamV2): CarrierStreamV2 {
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
