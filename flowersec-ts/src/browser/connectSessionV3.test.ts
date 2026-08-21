import { readFileSync } from "node:fs";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  connect,
  createArtifactLease,
  createConnectionController,
  parseArtifact,
} from "./index.js";
import type { ConnectError } from "./index.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ positive: readonly Readonly<{ id: string; artifact_json: string }>[] }>;
const directFixture = fixture.positive.find(({ id }) => id === "direct-mixed-security")!.artifact_json;

describe("browser production v3 connector", () => {
  afterEach(() => vi.unstubAllGlobals());

  test("fails closed before lease spend when certificate hashes are unsupported", async () => {
    class UnsupportedWebTransport {
      constructor() {
        throw new DOMException("certificate hashes are unavailable", "NotSupportedError");
      }
    }
    installBrowserFeatures(UnsupportedWebTransport);
    let spends = 0;

    await expect(connect(createArtifactLease(
      parseArtifact(singleWebTransportArtifact("pin")),
      async () => { spends += 1; },
    ))).rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({
      code: "transport_security_unsupported",
      disposition: { kind: "terminal" },
    }));
    expect(spends).toBe(0);
  });

  test("delegates CA trust without synthesizing certificate hashes", async () => {
    const calls: unknown[][] = [];
    class CATrustWebTransport {
      readonly ready = Promise.reject(new Error("test endpoint intentionally unavailable"));
      constructor(...args: unknown[]) { calls.push(args); }
      close() {}
    }
    installBrowserFeatures(CATrustWebTransport);
    let spends = 0;

    await expect(connect(createArtifactLease(
      parseArtifact(singleWebTransportArtifact("ca")),
      async () => { spends += 1; },
    ))).rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({
      code: "connection_failed",
    }));
    expect(spends).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toHaveLength(1);
  });

  test("validates the public browser connection timeout override", async () => {
    installBrowserFeatures(class {});
    const lease = createArtifactLease(parseArtifact(directFixture), async () => undefined);
    await expect(connect(lease, { connectTimeoutMs: 0 })).rejects.toEqual(
      expect.objectContaining<Partial<ConnectError>>({ code: "artifact_invalid" }),
    );
    await expect(createConnectionController({
      acquire: async () => ({ kind: "failure", code: "artifact_invalid", disposition: { kind: "terminal" } }),
    }, { connectTimeoutMs: 0 })).rejects.toEqual(
      expect.objectContaining<Partial<ConnectError>>({ code: "artifact_invalid" }),
    );
  });
});

function singleWebTransportArtifact(mode: "ca" | "pin"): string {
  const artifact = JSON.parse(directFixture) as {
    path: { candidates: Array<{ carrier: string; tls: unknown }> };
  };
  const candidate = artifact.path.candidates.find(({ carrier }) => carrier === "webtransport");
  if (candidate === undefined) throw new Error("WebTransport v3 fixture is missing");
  if (mode === "ca") candidate.tls = { mode: "ca" };
  artifact.path.candidates = [candidate];
  return JSON.stringify(artifact);
}

function installBrowserFeatures(WebTransport: new (...args: never[]) => unknown): void {
  vi.stubGlobal("WebSocket", undefined);
  const prototype = (WebTransport as unknown as { prototype?: Record<string, unknown> }).prototype;
  if (prototype !== undefined) {
    if (typeof prototype.createBidirectionalStream !== "function") {
      prototype.createBidirectionalStream = async () => await new Promise(() => undefined);
    }
    if (typeof prototype.close !== "function") prototype.close = () => undefined;
    for (const property of ["ready", "closed", "incomingBidirectionalStreams", "datagrams"]) {
      if (!(property in prototype)) Object.defineProperty(prototype, property, { configurable: true, get: () => undefined });
    }
  }
  vi.stubGlobal("WebTransport", WebTransport);
  vi.stubGlobal("navigator", {
    userAgentData: {
      getHighEntropyValues: async () => ({
        fullVersionList: [{ brand: "Chromium", version: "151.0.7922.34" }],
      }),
    },
  });
}
