import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import { adaptNativeCarrierSessionV3 } from "../v3/carrier.js";
import {
  createNativeRawQuicDriver,
  createNativeWebTransportDriver,
  loadNativeTransportAddon,
  tryLoadNativeTransportAddon,
  type NativeTransportAddonBinding,
} from "./nativeTransportAddon.js";

test("browser isolation rejects CommonJS and native loader syntax", () => {
  expect(() => assertBrowserGraphIsolation(
    'const fs = require("fs"); const load = createRequire(import.meta.url); load("./addon.node");',
    [],
  )).toThrowError(/Node native loader/u);
});

describe("native transport addon v5 ABI", () => {
  test("requires both WebTransport entries and aborts a late native dial result", async () => {
    const addon = completeAddon();
    expect(createNativeWebTransportDriver(addon)).toBeUndefined();
    expect(createNativeWebTransportDriver({ ...addon, bindWebTransport: addon.bindRawQuic })).toBeUndefined();
    const stop = new AbortController();
    let finish!: () => void, aborted = 0, canceled = 0;
    const native = { kind: "webtransport", wireVersion: 5, path: "direct", abort: () => { aborted++; } };
    const binding = { ...addon, bindWebTransport: addon.bindRawQuic, connectWebTransport: () => ({
      cancel: () => { canceled++; }, result: () => new Promise(resolve => { finish = () => resolve(native); }),
    }) } as unknown as NativeTransportAddonBinding;
    expect(createNativeWebTransportDriver(binding, "native_h3")).toBeUndefined();
    expect(createNativeWebTransportDriver({ ...binding, supportsNativeH3: () => true }, "native_h3")).toBeDefined();
    const connecting = createNativeWebTransportDriver(binding)!.connect({ ...rawQuicConnectOptions(), url: "https://localhost/flowersec/webtransport/v5/direct", origin: "https://app.example" }, stop.signal);
    stop.abort();
    await expect(connecting).rejects.toMatchObject({ code: "aborted" });
    finish(); await Promise.resolve();
    expect([canceled, aborted]).toEqual([1, 1]);
  });

  test("loads only the unversioned contractVersion 5 surface", () => {
    const requested: string[] = [];
    const addon = completeAddon();
    expect(loadNativeTransportAddon((specifier) => {
      requested.push(specifier);
      return addon;
    })).toBe(addon);
    expect(requested).toEqual(["@floegence/flowersec-node-native"]);
    expect(Object.keys(addon).sort()).toEqual([
      "bindRawQuic",
      "connectRawQuic",
      "contractVersion",
    ]);
    expect("connectRawQuicV3" in addon).toBe(false);
    expect("bindRawQuicV3" in addon).toBe(false);
  });

  test("rejects missing, incomplete, and old contracts", () => {
    expect(tryLoadNativeTransportAddon(() => {
      throw new Error("platform loader detail");
    })).toBeUndefined();
    for (const previousVersion of [2, 3, 4]) {
      expect(tryLoadNativeTransportAddon(() => ({
        ...completeAddon(),
        contractVersion: () => previousVersion,
      }))).toBeUndefined();
    }
    expect(tryLoadNativeTransportAddon(() => ({
      ...completeAddon(),
      connectRawQuic: undefined,
    }))).toBeUndefined();
  });

  test.each([2, 3, 4] as const)("rejects a wireVersion %i session without fallback", async (previousVersion) => {
    let abortCalls = 0;
    const session = {
      ...nativeSessionBinding({}, previousVersion),
      abort: () => { abortCalls += 1; },
    };
    const addon = {
      ...completeAddon(),
      connectRawQuic: () => operation(session),
    } as unknown as NativeTransportAddonBinding;
    await expect(createNativeRawQuicDriver(addon).connectRawQuic(rawQuicConnectOptions()))
      .rejects.toMatchObject({ code: "native_transport_unavailable" });
    expect(abortCalls).toBe(1);
  });

  test("cancels pending connect and stream I/O", async () => {
    let connectCanceled = 0;
    const addon = {
      ...completeAddon(),
      connectRawQuic: () => ({
        result: async () => await new Promise<never>(() => undefined),
        cancel: () => { connectCanceled += 1; },
      }),
    } as unknown as NativeTransportAddonBinding;
    const controller = new AbortController();
    const pending = createNativeRawQuicDriver(addon).connectRawQuic(
      rawQuicConnectOptions(),
      { signal: controller.signal },
    );
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    expect(connectCanceled).toBe(1);

    let cancelPendingCalls = 0;
    const stream = {
      read: async () => null,
      write: async () => await new Promise<number>(() => undefined),
      closeWrite: async () => undefined,
      stopSending: async () => undefined,
      reset: async () => undefined,
      cancelPending: () => { cancelPendingCalls += 1; },
      abort: () => undefined,
    };
    const streamAddon = {
      ...completeAddon(),
      connectRawQuic: () => operation(nativeSessionBinding(stream, 5)),
    } as unknown as NativeTransportAddonBinding;
    const native = await createNativeRawQuicDriver(streamAddon)
      .connectRawQuic(rawQuicConnectOptions());
    const carrier = adaptNativeCarrierSessionV3(native);
    const wrapped = await carrier.openStream();
    const writeAbort = new AbortController();
    const writing = wrapped.write(new Uint8Array([1]), { signal: writeAbort.signal });
    writeAbort.abort();
    await expect(writing).rejects.toMatchObject({ code: "aborted" });
    expect(cancelPendingCalls).toBe(1);
  });

  test("projects native stream reasons and close details", async () => {
    const closes: Array<readonly [number | undefined, string | undefined]> = [];
    const stream = {
      read: async () => { throw new Error("reset"); },
      write: async () => { throw new Error("stream_failed"); },
      closeWrite: async () => undefined,
      stopSending: async () => undefined,
      reset: async () => undefined,
      abort: () => undefined,
    };
    const session = {
      ...nativeSessionBinding(stream, 5),
      close: async (code?: number, reason?: string) => { closes.push([code, reason]); },
    };
    const addon = {
      ...completeAddon(),
      connectRawQuic: () => operation(session),
    } as unknown as NativeTransportAddonBinding;
    const connected = await createNativeRawQuicDriver(addon)
      .connectRawQuic(rawQuicConnectOptions());
    const wrapped = await connected.openStream();
    await expect(wrapped.read()).rejects.toMatchObject({ code: "reset" });
    await expect(wrapped.write(new Uint8Array([1]))).rejects.toMatchObject({ code: "closed" });
    await connected.close({ code: 7, reason: "session closed" });
    expect(closes).toEqual([[7, "session closed"]]);
  });

  test("published declarations expose addresses but no versioned ABI methods", () => {
    const declaration = readFileSync(resolve(
      fileURLToPath(new URL("../../..", import.meta.url)),
      "flowersec-node-native/index.d.ts",
    ), "utf8");
    expect(declaration).toMatch(/localAddress\(\): Readonly/u);
    expect(declaration).toMatch(/peerAddress\(\): Readonly/u);
    expect(declaration).not.toContain("connectRawQuicV3");
    expect(declaration).not.toContain("bindRawQuicV3");
  });

  test("browser entry graph cannot reach the Node addon loader", () => {
    const sourceRoot = fileURLToPath(new URL("..", import.meta.url));
    const pending = [resolve(sourceRoot, "browser/index.ts")];
    const visited = new Set<string>();
    const source = new Map<string, string>();
    const externalSpecifiers: string[] = [];
    while (pending.length > 0) {
      const file = pending.pop()!;
      if (visited.has(file)) continue;
      visited.add(file);
      const text = readFileSync(file, "utf8");
      source.set(file, text);
      for (const match of text.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s*)["']([^"']+)["']/gu)) {
        const specifier = match[1]!;
        if (!specifier.startsWith(".")) {
          externalSpecifiers.push(specifier);
          continue;
        }
        pending.push(resolve(file, "..", specifier.replace(/\.js$/u, ".ts")));
      }
    }
    assertBrowserGraphIsolation([...source.values()].join("\n"), externalSpecifiers);
  });
});

function completeAddon(): NativeTransportAddonBinding {
  return Object.freeze({
    contractVersion: () => 5,
    connectRawQuic: () => { throw new Error("unused"); },
    bindRawQuic: () => { throw new Error("unused"); },
  });
}

function rawQuicConnectOptions() {
  return {
    host: "127.0.0.1",
    port: 443,
    serverName: "localhost",
    path: "direct" as const,
    tlsMode: "pin" as const,
    activeLeafDerSha256: [new Uint8Array(32)],
    inboundBidirectionalStreamCapacity: 3,
    handshakeTimeoutMs: 1_000,
  };
}

function nativeSessionBinding(stream: object, wireVersion: 2 | 3 | 4 | 5) {
  return {
    kind: "raw_quic" as const,
    path: "direct" as const,
    wireVersion,
    inboundBidirectionalStreamCapacity: 3,
    localAddress: () => ({ host: "127.0.0.1", port: 1 }),
    peerAddress: () => ({ host: "127.0.0.1", port: 2 }),
    openStream: () => operation(stream),
    acceptStream: () => operation(stream),
    sendDatagram: () => "unavailable" as const,
    receiveDatagram: () => { throw new Error("unused"); },
    waitTermination: async () => undefined,
    close: async () => undefined,
    abort: () => undefined,
  };
}

function operation<T>(value: T) {
  return { result: async () => value, cancel: () => undefined };
}

function assertBrowserGraphIsolation(graph: string, externalSpecifiers: readonly string[]): void {
  expect(graph).not.toContain("nativeTransportAddon");
  expect(graph).not.toContain("flowersec-node-native");
  if (/\b(?:require|createRequire)\s*\(/u.test(graph)) {
    throw new Error("Node native loader syntax reached Browser graph");
  }
  expect(graph).not.toMatch(/(?:node:module|\.node["'])/u);
  expect(externalSpecifiers.some((specifier) =>
    specifier.startsWith("node:") || specifier.endsWith(".node"),
  )).toBe(false);
}
