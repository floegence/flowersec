import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, test } from "vitest";

import {
  createNativeRawQuicDriver,
  loadNativeTransportAddon,
  tryLoadNativeTransportAddon,
  type NativeTransportAddonBinding,
} from "./nativeTransportAddon.js";

test("browser isolation rejects CommonJS and native loader syntax", () => {
  expect(() => assertBrowserGraphIsolation(
    'const fs = require("fs"); const load = createRequire(import.meta.url); load("./addon.node");',
    [],
  )).toThrowError(/Node native loader/);
});

describe("native transport addon loader", () => {
  test("published raw QUIC session declarations expose the native address contract", () => {
    const declaration = readFileSync(resolve(
      fileURLToPath(new URL("../../..", import.meta.url)),
      "flowersec-node-native/index.d.ts",
    ), "utf8");
    expect(declaration).toMatch(/localAddress\(\): Readonly<\{ host: string; port: number \}>;/u);
    expect(declaration).toMatch(/peerAddress\(\): Readonly<\{ host: string; port: number \}>;/u);
  });

  test("loads only the Flowersec-owned package and reports a stable missing-addon error", () => {
    const requested: string[] = [];
    const addon = Object.freeze({
      contractVersion: () => 1,
      connectRawQuic: () => { throw new Error("unused"); },
      bindRawQuic: () => { throw new Error("unused"); },
    }) as unknown as NativeTransportAddonBinding;
    expect(loadNativeTransportAddon((specifier) => {
      requested.push(specifier);
      return addon;
    })).toBe(addon);
    expect(requested).toEqual(["@floegence/flowersec-node-native"]);

    expect(() => loadNativeTransportAddon(() => {
      throw new Error("platform loader detail");
    })).toThrowError(expect.objectContaining({
      name: "NativeTransportUnavailableError",
      code: "native_transport_unavailable",
      message: "Flowersec native transport is unavailable on this platform",
    }));
  });

  test("reports optional addon availability without leaking loader errors", () => {
    expect(tryLoadNativeTransportAddon(() => {
      throw new Error("platform loader detail");
    })).toBeUndefined();
  });

  test("cancels a pending native connect without a fallback", async () => {
    let canceled = 0;
    const operation = {
      result: async () => await new Promise<never>(() => undefined),
      cancel: () => { canceled += 1; },
    };
    const addon = {
      contractVersion: () => 1,
      connectRawQuic: () => operation,
      bindRawQuic: () => { throw new Error("unused"); },
    } as unknown as NativeTransportAddonBinding;
    const driver = createNativeRawQuicDriver(addon);
    const controller = new AbortController();
    const pending = driver.connectRawQuic({
      host: "127.0.0.1",
      port: 443,
      serverName: "localhost",
      path: "direct",
      trustRootsDer: [new Uint8Array([1])],
      inboundBidirectionalStreamCapacity: 66,
      handshakeTimeoutMs: 1_000,
    }, { signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: "aborted" });
    expect(canceled).toBe(1);
  });

  test("forwards bounded application close details through the native driver", async () => {
    const closes: Array<readonly [number | undefined, string | undefined]> = [];
    const session = {
      kind: "raw_quic",
      path: "direct",
      inboundBidirectionalStreamCapacity: 3,
      localAddress: () => ({ host: "127.0.0.1", port: 1 }),
      peerAddress: () => ({ host: "127.0.0.1", port: 2 }),
      openStream: () => { throw new Error("unused"); },
      acceptStream: () => { throw new Error("unused"); },
      sendDatagram: () => "unavailable",
      receiveDatagram: () => { throw new Error("unused"); },
      waitTermination: async () => undefined,
      close: async (code?: number, reason?: string) => { closes.push([code, reason]); },
      abort: () => undefined,
    };
    const addon = {
      contractVersion: () => 1,
      connectRawQuic: () => ({ result: async () => session, cancel: () => undefined }),
      bindRawQuic: () => { throw new Error("unused"); },
    } as unknown as NativeTransportAddonBinding;
    const driver = createNativeRawQuicDriver(addon);
    const connected = await driver.connectRawQuic({
      host: "127.0.0.1",
      port: 443,
      serverName: "localhost",
      path: "direct",
      trustRootsDer: [new Uint8Array([1])],
      inboundBidirectionalStreamCapacity: 3,
      handshakeTimeoutMs: 1_000,
    });

    await connected.close({ code: 7, reason: "session closed" });
    expect(closes).toEqual([[7, "session closed"]]);
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
        const resolved = resolve(file, "..", specifier.replace(/\.js$/u, ".ts"));
        pending.push(resolved);
      }
    }
    assertBrowserGraphIsolation([...source.values()].join("\n"), externalSpecifiers);
  });
});

function assertBrowserGraphIsolation(graph: string, externalSpecifiers: readonly string[]): void {
  expect(graph).not.toContain("nativeTransportAddon");
  expect(graph).not.toContain("flowersec-node-native");
  if (/\b(?:require|createRequire)\s*\(/u.test(graph)) {
    throw new Error("Node native loader syntax reached Browser graph");
  }
  expect(graph).not.toMatch(/(?:node:module|\.node["'])/u);
  expect(externalSpecifiers).not.toContain("fs");
  expect(externalSpecifiers).not.toContain("net");
  expect(externalSpecifiers).not.toContain("@floegence/flowersec-node-native");
  expect(externalSpecifiers.some((specifier) =>
    specifier.startsWith("node:") || specifier.endsWith(".node"),
  )).toBe(false);
}
