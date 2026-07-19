import { describe, expect, test, vi } from "vitest";
import { x25519 } from "@noble/curves/ed25519";
import type { E2EE_Ack, E2EE_Init, E2EE_Resp } from "../gen/flowersec/e2ee/v1.gen.js";
import { base64urlEncode, base64urlDecode } from "../utils/base64url.js";
import { HANDSHAKE_TYPE_ACK, HANDSHAKE_TYPE_INIT, HANDSHAKE_TYPE_RESP, PROTOCOL_VERSION } from "./constants.js";
import { clientHandshake, serverHandshake, ServerHandshakeCache } from "./handshake.js";
import { computeAuthTag } from "./kdf.js";
import { transcriptHash } from "./transcript.js";
import { encodeHandshakeFrame, decodeHandshakeFrame } from "./framing.js";

const te = new TextEncoder();
const td = new TextDecoder();

type BinaryTransport = {
  readBinary(opts?: Readonly<{ signal?: AbortSignal; timeoutMs?: number }>): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

class ScriptedTransport implements BinaryTransport {
  private readonly reads: Uint8Array[];
  readonly writes: Uint8Array[] = [];
  readonly readOptions: Array<Readonly<{ signal?: AbortSignal; timeoutMs?: number }> | undefined> = [];
  onWrite?: (frame: Uint8Array) => void;

  constructor(reads: Uint8Array[]) {
    this.reads = [...reads];
  }

  async readBinary(opts?: Readonly<{ signal?: AbortSignal; timeoutMs?: number }>): Promise<Uint8Array> {
    this.readOptions.push(opts);
    const next = this.reads.shift();
    if (next == null) throw new Error("unexpected read");
    return next;
  }

  async writeBinary(frame: Uint8Array): Promise<void> {
    this.writes.push(frame);
    this.onWrite?.(frame);
  }

  close(): void {}

  pushRead(frame: Uint8Array): void {
    this.reads.push(frame);
  }
}

function makeInit(opts: { channelId: string; suite: 1 | 2; clientFeatures?: number }): {
  init: E2EE_Init;
  initFrame: Uint8Array;
  clientPriv: Uint8Array;
  clientPub: Uint8Array;
  nonceC: Uint8Array;
} {
  const clientPriv = x25519.utils.randomPrivateKey();
  const clientPub = x25519.getPublicKey(clientPriv);
  const nonceC = crypto.getRandomValues(new Uint8Array(32));
  const init: E2EE_Init = {
    channel_id: opts.channelId,
    role: 1,
    version: PROTOCOL_VERSION,
    suite: opts.suite,
    client_eph_pub_b64u: base64urlEncode(clientPub),
    nonce_c_b64u: base64urlEncode(nonceC),
    client_features: opts.clientFeatures ?? 0
  };
  const initFrame = encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode(JSON.stringify(init)));
  return { init, initFrame, clientPriv, clientPub, nonceC };
}

function buildAckFrame(args: {
  init: E2EE_Init;
  resp: E2EE_Resp;
  psk: Uint8Array;
  timestamp: number;
}): Uint8Array {
  const clientPub = base64urlDecode(args.init.client_eph_pub_b64u);
  const nonceC = base64urlDecode(args.init.nonce_c_b64u);
  const serverPub = base64urlDecode(args.resp.server_eph_pub_b64u);
  const nonceS = base64urlDecode(args.resp.nonce_s_b64u);
  const th = transcriptHash({
    version: PROTOCOL_VERSION,
    suite: args.init.suite as 1 | 2,
    role: 1,
    clientFeatures: args.init.client_features,
    serverFeatures: args.resp.server_features >>> 0,
    channelId: args.init.channel_id,
    nonceC,
    nonceS,
    clientEphPub: clientPub,
    serverEphPub: serverPub
  });
  const tag = computeAuthTag(args.psk, th, BigInt(args.timestamp));
  const ack: E2EE_Ack = {
    handshake_id: args.resp.handshake_id,
    timestamp_unix_s: args.timestamp,
    auth_tag_b64u: base64urlEncode(tag)
  };
  return encodeHandshakeFrame(HANDSHAKE_TYPE_ACK, te.encode(JSON.stringify(ack)));
}

describe("clientHandshake", () => {
  test("rejects negative timeoutMs", async () => {
    const transport = new ScriptedTransport([]);
    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20,
      timeoutMs: -1
    })).rejects.toThrow(/timeoutMs must be >= 0/);
  });

  test("treats timeoutMs zero as no handshake deadline", async () => {
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode("{}")),
    ]);

    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20,
      timeoutMs: 0,
    })).rejects.toThrow(/unexpected handshake type/);

    expect(transport.readOptions).toEqual([{}]);
  });

  test("rejects missing handshake_id", async () => {
    const serverPub = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const nonceS = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, te.encode(JSON.stringify({ server_eph_pub_b64u: serverPub, nonce_s_b64u: nonceS, server_features: 0 })))
    ]);

    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/missing handshake_id/);
  });

  test("rejects bad nonce_s length", async () => {
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, te.encode(JSON.stringify({
        handshake_id: "hs_1",
        server_eph_pub_b64u: base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),
        nonce_s_b64u: base64urlEncode(crypto.getRandomValues(new Uint8Array(31))),
        server_features: 0
      })))
    ]);

    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/bad nonce_s length/);
  });

  test("rejects bad server eph pub length", async () => {
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, te.encode(JSON.stringify({
        handshake_id: "hs_1",
        server_eph_pub_b64u: base64urlEncode(crypto.getRandomValues(new Uint8Array(31))),
        nonce_s_b64u: base64urlEncode(crypto.getRandomValues(new Uint8Array(32))),
        server_features: 0
      })))
    ]);

    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/bad server eph pub length/);
  });

  test("rejects unexpected response type", async () => {
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode("{}"))
    ]);
    transport.onWrite = () => {};

    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/unexpected handshake type/);

    expect(transport.writes.length).toBe(1);
    const decoded = decodeHandshakeFrame(transport.writes[0]!, 8 * 1024);
    expect(decoded.handshakeType).toBe(HANDSHAKE_TYPE_INIT);
  });

  test("rejects oversized handshake payloads", async () => {
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, new Uint8Array(10))
    ]);

    await expect(clientHandshake(transport, {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      clientFeatures: 0,
      maxHandshakePayload: 4,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/handshake payload too large/);
  });
});

describe("serverHandshake", () => {
  test("rejects bad version", async () => {
    const { init } = makeInit({ channelId: "ch_1", suite: 1 });
    const badInit = { ...init, version: PROTOCOL_VERSION + 1 };
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode(JSON.stringify(badInit)))
    ]);

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      serverFeatures: 0,
      initExpireAtUnixS: 100,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/bad version/);
  });

  test("rejects invalid clock skew before reading transport", async () => {
    const transport = new ScriptedTransport([]);
    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      serverFeatures: 0,
      initExpireAtUnixS: 100,
      clockSkewSeconds: -1,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/invalid clock_skew/);

    expect(transport.writes.length).toBe(0);
  });

  test("rejects bad role", async () => {
    const { init } = makeInit({ channelId: "ch_1", suite: 1 });
    const badInit = { ...init, role: 2 };
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode(JSON.stringify(badInit)))
    ]);

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      serverFeatures: 0,
      initExpireAtUnixS: 100,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/bad role/);
  });

  test("rejects channel_id mismatch", async () => {
    const { init } = makeInit({ channelId: "ch_1", suite: 1 });
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode(JSON.stringify(init)))
    ]);

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_other",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      serverFeatures: 0,
      initExpireAtUnixS: 100,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/bad channel_id/);
  });

  test("rejects suite mismatch", async () => {
    const { init } = makeInit({ channelId: "ch_1", suite: 2 });
    const transport = new ScriptedTransport([
      encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode(JSON.stringify(init)))
    ]);

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk: crypto.getRandomValues(new Uint8Array(32)),
      serverFeatures: 0,
      initExpireAtUnixS: 100,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toMatchObject({ name: "E2EEHandshakeError", code: "invalid_suite" });
  });

  test("rejects timestamp skew", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(0));

    const psk = crypto.getRandomValues(new Uint8Array(32));
    const { init, initFrame } = makeInit({ channelId: "ch_1", suite: 1 });
    const transport = new ScriptedTransport([initFrame]);

    transport.onWrite = (frame) => {
      const decoded = decodeHandshakeFrame(frame, 8 * 1024);
      const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
      const ackFrame = buildAckFrame({ init, resp, psk, timestamp: 999 });
      transport.pushRead(ackFrame);
    };

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: 1000,
      clockSkewSeconds: 10,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/timestamp skew/);

    vi.useRealTimers();
  });

  test("treats zero clock skew as strict", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(100 * 1000));

    const psk = crypto.getRandomValues(new Uint8Array(32));
    const { init, initFrame } = makeInit({ channelId: "ch_1", suite: 1 });
    const transport = new ScriptedTransport([initFrame]);

    transport.onWrite = (frame) => {
      const decoded = decodeHandshakeFrame(frame, 8 * 1024);
      const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
      const ackFrame = buildAckFrame({ init, resp, psk, timestamp: 101 });
      transport.pushRead(ackFrame);
    };

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: 120,
      clockSkewSeconds: 0,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/timestamp skew/);

    vi.useRealTimers();
  });

  test("rejects timestamp after init_exp", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(100 * 1000));

    const psk = crypto.getRandomValues(new Uint8Array(32));
    const { init, initFrame } = makeInit({ channelId: "ch_1", suite: 1 });
    const transport = new ScriptedTransport([initFrame]);

    transport.onWrite = (frame) => {
      const decoded = decodeHandshakeFrame(frame, 8 * 1024);
      const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
      const ackFrame = buildAckFrame({ init, resp, psk, timestamp: 90 });
      transport.pushRead(ackFrame);
    };

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: 50,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/timestamp after init_exp/);

    vi.useRealTimers();
  });

  test("rejects auth tag mismatch", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(100 * 1000));

    const psk = crypto.getRandomValues(new Uint8Array(32));
    const { init, initFrame } = makeInit({ channelId: "ch_1", suite: 1 });
    const transport = new ScriptedTransport([initFrame]);
    const cache = new ServerHandshakeCache();
    let firstHandshakeId = "";

    transport.onWrite = (frame) => {
      const decoded = decodeHandshakeFrame(frame, 8 * 1024);
      const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
      firstHandshakeId = resp.handshake_id;
      const ack: E2EE_Ack = {
        handshake_id: resp.handshake_id,
        timestamp_unix_s: 100,
        auth_tag_b64u: base64urlEncode(new Uint8Array(32))
      };
      transport.pushRead(encodeHandshakeFrame(HANDSHAKE_TYPE_ACK, te.encode(JSON.stringify(ack))));
    };

    await expect(serverHandshake(transport, cache, {
      channelId: "ch_1",
      suite: 1,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: 200,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/auth tag mismatch/);

    const retryTransport = new ScriptedTransport([initFrame]);
    let replacementHandshakeId = "";
    retryTransport.onWrite = (frame) => {
      if (td.decode(frame.subarray(0, 4)) !== "FSEH") return;
      const decoded = decodeHandshakeFrame(frame, 8 * 1024);
      const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
      replacementHandshakeId = resp.handshake_id;
      retryTransport.pushRead(buildAckFrame({ init, resp, psk, timestamp: 100 }));
    };
    const replacement = await serverHandshake(retryTransport, cache, {
      channelId: "ch_1",
      suite: 1,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: 200,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    });
    replacement.close();
    expect(replacementHandshakeId).not.toBe(firstHandshakeId);

    vi.useRealTimers();
  });

  test("allows only one concurrent ACK to consume shared state", async () => {
    const psk = crypto.getRandomValues(new Uint8Array(32));
    const { init, initFrame } = makeInit({ channelId: "ch_1", suite: 1 });
    const cache = new ServerHandshakeCache();
    let responseCount = 0;
    let releaseResponses!: () => void;
    const responsesReady = new Promise<void>((resolve) => {
      releaseResponses = resolve;
    });

    const createTransport = (): BinaryTransport => {
      let readCount = 0;
      let ackFrame: Uint8Array | undefined;
      return {
        async readBinary() {
          readCount++;
          if (readCount === 1) return initFrame;
          if (readCount !== 2) throw new Error("unexpected read");
          await responsesReady;
          if (ackFrame == null) throw new Error("missing ACK");
          return ackFrame;
        },
        async writeBinary(frame) {
          if (td.decode(frame.subarray(0, 4)) !== "FSEH") return;
          const decoded = decodeHandshakeFrame(frame, 8 * 1024);
          const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
          ackFrame = buildAckFrame({ init, resp, psk, timestamp: Math.floor(Date.now() / 1000) });
          responseCount++;
          if (responseCount === 2) releaseResponses();
        },
        close() {}
      };
    };

    const opts = {
      channelId: "ch_1",
      suite: 1 as const,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: Math.floor(Date.now() / 1000) + 120,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    };
    const results = await Promise.allSettled([
      serverHandshake(createTransport(), cache, opts),
      serverHandshake(createTransport(), cache, opts)
    ]);
    const fulfilled = results.filter((result): result is PromiseFulfilledResult<Awaited<ReturnType<typeof serverHandshake>>> => result.status === "fulfilled");
    const rejected = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    for (const result of fulfilled) result.value.close();

    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.reason).toMatchObject({ message: "handshake state unavailable" });
  });

  test("rejects unexpected init retry parameters", async () => {
    const psk = crypto.getRandomValues(new Uint8Array(32));
    const { init, initFrame } = makeInit({ channelId: "ch_1", suite: 1 });
    const retry = { ...init, channel_id: "ch_other" };
    const retryFrame = encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, te.encode(JSON.stringify(retry)));
    const transport = new ScriptedTransport([initFrame, retryFrame]);

    await expect(serverHandshake(transport, new ServerHandshakeCache(), {
      channelId: "ch_1",
      suite: 1,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: Math.floor(Date.now() / 1000) + 120,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    })).rejects.toThrow(/unexpected init retry parameters/);
  });
});

describe("ServerHandshakeCache", () => {
  test("expires entries based on ttl", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(0));

    const cache = new ServerHandshakeCache({ ttlMs: 5, maxEntries: 10 });
    const { init } = makeInit({ channelId: "ch_1", suite: 1 });
    const first = cache.getOrCreate(init, 1, 0);

    vi.setSystemTime(new Date(10));
    const second = cache.getOrCreate(init, 1, 0);
    expect(second.handshakeId).not.toBe(first.handshakeId);

    vi.useRealTimers();
  });

  test("enforces max entries", () => {
    const cache = new ServerHandshakeCache({ ttlMs: 1000, maxEntries: 1 });
    const { init: initA } = makeInit({ channelId: "ch_1", suite: 1 });
    const { init: initB } = makeInit({ channelId: "ch_2", suite: 1 });
    cache.getOrCreate(initA, 1, 0);
    expect(() => cache.getOrCreate(initB, 1, 0)).toThrow(/too many pending handshakes/);
  });

  test("rejects negative or non-integer limits", () => {
    expect(() => new ServerHandshakeCache({ ttlMs: -1 })).toThrow(/ttlMs must be >= 0/);
    expect(() => new ServerHandshakeCache({ maxEntries: -1 })).toThrow(/maxEntries must be an integer >= 0/);
    expect(() => new ServerHandshakeCache({ maxEntries: 1.5 })).toThrow(/maxEntries must be an integer >= 0/);
  });
});
