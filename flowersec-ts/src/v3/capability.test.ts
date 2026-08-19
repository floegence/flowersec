import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import {
  decodeRuntimeCapabilityDescriptorV3,
  encodeRuntimeCapabilityDescriptorV3,
  runtimeCapabilityDigestHexV3,
} from "./capability.js";
import {
  BrowserRuntimeCapabilityRegistryV3,
  createBrowserWebTransportCarrierV3,
  createBrowserWebTransportV3,
} from "./browserRuntime.js";
import { detectNodeRuntimeCapabilityV3 } from "./nodeRuntime.js";
import { TransportFailureV3 } from "./security.js";
import type { CanonicalArtifactCandidateV3 } from "./artifact.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/capability_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  vectors: readonly Readonly<{ name: string; canonical_json: string; digest_hex: string }>[];
  invalid: readonly Readonly<{ id: string; value: string; error_code: "invalid_capability" }>[];
}>;
const urlFixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/idna_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{
  url_normalization: Readonly<{
    positive: readonly Readonly<{
      carrier: "raw_quic" | "websocket" | "webtransport";
      path_kind: "direct" | "tunnel";
      normalized: string;
      whatwg_roundtrip: boolean;
    }>[];
  }>;
}>;

const vector = (name: string) => fixture.vectors.find((item) => item.name === name)!;
const pinCandidate: CanonicalArtifactCandidateV3 = {
  carrier: "webtransport",
  id: "webtransport-pin",
  normalized_url: "https://example.com/flowersec/webtransport/v3/direct",
  tls: {
    mode: "pin",
    pins: [{
      algorithm: "sha-256",
      not_after_unix_s: 2_000_000_000,
      value_b64u: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    }],
  },
  wire_profile: "flowersec-direct/3",
};
const caCandidate: CanonicalArtifactCandidateV3 = { ...pinCandidate, id: "webtransport-ca", tls: { mode: "ca" } };

describe("runtime capability v3", () => {
  test("decodes and hashes all cross-language shared vectors", () => {
    for (const expected of fixture.vectors) {
      const descriptor = decodeRuntimeCapabilityDescriptorV3(expected.canonical_json);
      expect(encodeRuntimeCapabilityDescriptorV3(descriptor)).toBe(expected.canonical_json);
      expect(runtimeCapabilityDigestHexV3(descriptor)).toBe(expected.digest_hex);
    }
  });

  test("rejects every shared invalid capability descriptor", () => {
    expect(fixture.invalid.length).toBeGreaterThanOrEqual(20);
    for (const vector of fixture.invalid) {
      expect(
        () => decodeRuntimeCapabilityDescriptorV3(vector.value),
        vector.id,
      ).toThrowError(TypeError);
    }
  });

  test("rejects a nested duplicate tuple field during lexical preflight", () => {
    const raw = vector("go-native").canonical_json.replace(
      '"carrier":"raw_quic"',
      '"carrier":"raw_quic","carrier":"raw_quic"',
    );
    expect(() => decodeRuntimeCapabilityDescriptorV3(raw)).toThrowError(TypeError);
  });

  test("reports the stable native-unavailable reason when raw QUIC cannot be loaded", () => {
    const capability = detectNodeRuntimeCapabilityV3();
    expect(capability.tuples.every(({ carrier }) => carrier === "websocket")).toBe(true);
    expect(capability.unsupported).toContainEqual({
      carrier: "raw_quic",
      reason: "node_native_transport_unavailable",
    });
  });

  test("advertises the exact raw QUIC v3 tuples only when the addon is available", () => {
    const capability = detectNodeRuntimeCapabilityV3(true);
    const raw = capability.tuples.filter(({ carrier }) => carrier === "raw_quic");
    expect(raw).toHaveLength(4);
    expect(raw.map(({ networkMode, path, sessionRole }) => [networkMode, path, sessionRole])).toEqual([
      ["dial", "direct", "client"],
      ["dial", "tunnel", "client"],
      ["dial", "tunnel", "server"],
      ["listen", "direct", "server"],
    ]);
    expect(raw.every(({ securityModes, datagrams, migration }) =>
      datagrams && !migration && (securityModes.length === 0 ||
        securityModes.join(",") === "ca,pin"))).toBe(true);
    expect(capability.unsupported).toEqual([
      { carrier: "webtransport", reason: "node_webtransport_driver_unavailable" },
    ]);
  });

  test("keeps the registered Node capability independent of WebSocket origin wiring", () => {
    const withOrigin = detectNodeRuntimeCapabilityV3(true, true);
    const withoutOrigin = detectNodeRuntimeCapabilityV3(true, false);
    expect(withoutOrigin).toEqual(withOrigin);
    expect(withoutOrigin.tuples.some(({ carrier }) => carrier === "websocket")).toBe(true);
  });

  test("requires the exact Chromium full version before advertising browser pin", async () => {
    const constructor = class { ready = Promise.resolve(); close() {} };
    const matching = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(constructor, "151.0.7922.34"));
    expect(encodeRuntimeCapabilityDescriptorV3(matching.snapshot()))
      .toBe(vector("typescript-browser-chromium-151.0.7922.34").canonical_json);

    for (const version of ["151.0.7922.35", "151", "0151.0.7922.34"]) {
      const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(constructor, version));
      expect(encodeRuntimeCapabilityDescriptorV3(registry.snapshot()))
        .toBe(vector("typescript-browser-ca-only").canonical_json);
    }
  });

  test("passes only active hashes through the production WebTransport constructor", async () => {
    const calls: unknown[][] = [];
    const Constructor = class {
      ready = Promise.resolve();
      constructor(...args: unknown[]) { calls.push(args); }
      close() {}
    };
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    await createBrowserWebTransportV3(pinCandidate, 1_999_999_999, registry.snapshot(), registry);
    expect(calls).toHaveLength(1);
    const options = calls[0]![1] as { serverCertificateHashes: Array<{ algorithm: string; value: ArrayBuffer }> };
    expect(options.serverCertificateHashes).toHaveLength(1);
    expect(options.serverCertificateHashes[0]!.algorithm).toBe("sha-256");
    expect(options.serverCertificateHashes[0]!.value.byteLength).toBe(32);
  });

  test("passes both active hashes during overlap and drops the expired predecessor", async () => {
    const calls: unknown[][] = [];
    const Constructor = class {
      ready = Promise.resolve();
      constructor(...args: unknown[]) { calls.push(args); }
      close() {}
    };
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    const rotating = {
      ...pinCandidate,
      tls: {
        mode: "pin" as const,
        pins: [
          { ...pinCandidate.tls.mode === "pin" ? pinCandidate.tls.pins[0]! : never(), not_after_unix_s: 2_000_000_000 },
          {
            algorithm: "sha-256" as const,
            not_after_unix_s: 2_100_000_000,
            value_b64u: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
          },
        ],
      },
    };
    await createBrowserWebTransportV3(rotating, 1_999_999_999, registry.snapshot(), registry);
    let options = calls.at(-1)![1] as { serverCertificateHashes: Array<{ value: ArrayBuffer }> };
    expect(options.serverCertificateHashes).toHaveLength(2);

    await createBrowserWebTransportV3(rotating, 2_000_000_000, registry.snapshot(), registry);
    options = calls.at(-1)![1] as { serverCertificateHashes: Array<{ value: ArrayBuffer }> };
    expect(options.serverCertificateHashes).toHaveLength(1);
    expect(Buffer.from(options.serverCertificateHashes[0]!.value).toString("base64url"))
      .toBe(rotating.tls.pins[1]!.value_b64u);
  });

  test("rejects an all-expired pin set before constructing WebTransport", async () => {
    const Constructor = vi.fn(class { ready = Promise.resolve(); close() {} });
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    await expect(createBrowserWebTransportV3(pinCandidate, 2_000_000_000, registry.snapshot(), registry))
      .rejects.toMatchObject({ code: "tls_policy_expired" });
    expect(Constructor).not.toHaveBeenCalled();
  });

  test("omits serverCertificateHashes entirely in CA mode", async () => {
    const calls: unknown[][] = [];
    const Constructor = class {
      ready = Promise.resolve();
      constructor(...args: unknown[]) { calls.push(args); }
      close() {}
    };
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    await createBrowserWebTransportV3(caCandidate, 1_999_999_999, registry.snapshot(), registry);
    expect(calls).toEqual([[caCandidate.normalized_url]]);
  });

  test("passes the shared WHATWG-roundtrip URL through the production WebTransport adapter", async () => {
    const vector = urlFixture.url_normalization.positive.find(({ carrier }) => carrier === "webtransport");
    if (vector === undefined) throw new Error("shared WebTransport URL normalization vector is missing");
    expect(vector.whatwg_roundtrip).toBe(true);
    expect(new URL(vector.normalized).href).toBe(vector.normalized);
    const calls: unknown[][] = [];
    const Constructor = class {
      ready = Promise.resolve();
      constructor(...args: unknown[]) { calls.push(args); }
      close() {}
    };
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    const candidate: CanonicalArtifactCandidateV3 = {
      ...caCandidate,
      normalized_url: vector.normalized,
      wire_profile: vector.path_kind === "direct" ? "flowersec-direct/3" : "flowersec-tunnel/3",
    };
    await createBrowserWebTransportV3(candidate, 1_999_999_999, registry.snapshot(), registry);
    expect(calls).toEqual([[vector.normalized]]);
  });

  test("rejects a WebTransport URL with a non-contract v3 path before construction", async () => {
    const Constructor = vi.fn(class { ready = Promise.resolve(); close() {} });
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    await expect(createBrowserWebTransportV3(
      { ...caCandidate, normalized_url: `${caCandidate.normalized_url}/extra` },
      1_999_999_999,
      registry.snapshot(),
      registry,
    )).rejects.toMatchObject({ code: "invalid_artifact" });
    expect(Constructor).not.toHaveBeenCalled();
  });

  test("keeps pin ready rejection opaque and closes the failed transport", async () => {
    const close = vi.fn();
    const Constructor = class {
      ready = Promise.reject(new Error("opaque browser failure"));
      close = close;
    };
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    await expect(createBrowserWebTransportV3(pinCandidate, 1_999_999_999, registry.snapshot(), registry))
      .rejects.toMatchObject({ code: "connection_failed", detail: "browser_pin_opaque" });
    expect(close).toHaveBeenCalledOnce();
    expect(registry.pinEnabled()).toBe(true);
  });

  test("fails exact-provider detection closed and rebuilds registry state independently", async () => {
    const Constructor = class { ready = Promise.resolve(); close() {} };
    const duplicate = browserFeatures(Constructor, "151.0.7922.34");
    duplicate.navigator.userAgentData.getHighEntropyValues = async () => ({
      fullVersionList: [
        { brand: "Chromium", version: "151.0.7922.34" },
        { brand: "Chromium", version: "151.0.7922.34" },
      ],
    });
    expect((await BrowserRuntimeCapabilityRegistryV3.create(duplicate)).pinEnabled()).toBe(false);
    const denied = browserFeatures(Constructor, "151.0.7922.34");
    denied.navigator.userAgentData.getHighEntropyValues = async () => { throw new Error("denied"); };
    expect((await BrowserRuntimeCapabilityRegistryV3.create(denied)).pinEnabled()).toBe(false);
    expect((await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"))).pinEnabled())
      .toBe(true);
  });

  test("adapts the same hash-verified production WebTransport into a v3 carrier", async () => {
    const close = vi.fn();
    const Constructor = class {
      readonly ready = Promise.resolve();
      readonly closed = new Promise(() => undefined);
      readonly incomingBidirectionalStreams = new ReadableStream({ start() {} });
      readonly datagrams = {
        readable: new ReadableStream<Uint8Array>({ start() {} }),
        writable: new WritableStream<Uint8Array>({ write() {} }),
        maxDatagramSize: 1_200,
      };
      readonly close = close;
      async createBidirectionalStream(): Promise<never> { return await new Promise(() => undefined); }
    };
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    const carrier = await createBrowserWebTransportCarrierV3(
      pinCandidate,
      1_999_999_999,
      registry.snapshot(),
      registry,
      3,
    );
    expect(carrier.kind).toBe("webtransport");
    expect(carrier.path).toBe("direct");
    carrier.abort({ code: 6, reason: "test complete" });
    expect(close).toHaveBeenCalledOnce();
  });

  test("linearizes synchronous NotSupportedError and live-gates an old snapshot", async () => {
    const Constructor = vi.fn(function () {
      throw new DOMException("unsupported", "NotSupportedError");
    });
    const registry = await BrowserRuntimeCapabilityRegistryV3.create(browserFeatures(Constructor, "151.0.7922.34"));
    const oldSnapshot = registry.snapshot();
    await expect(createBrowserWebTransportV3(pinCandidate, 1_999_999_999, oldSnapshot, registry))
      .rejects.toMatchObject({ code: "tls_unsupported" });
    expect(registry.pinEnabled()).toBe(false);
    await expect(createBrowserWebTransportV3(pinCandidate, 1_999_999_999, oldSnapshot, registry))
      .rejects.toBeInstanceOf(TransportFailureV3);
    expect(Constructor).toHaveBeenCalledTimes(1);
  });
});

function browserFeatures(Constructor: unknown, version: string) {
  return {
    WebSocket: class {},
    WebTransport: Constructor,
    navigator: {
      userAgentData: {
        async getHighEntropyValues() {
          return { fullVersionList: [{ brand: "Chromium", version }] };
        },
      },
    },
  };
}

function never(): never {
  throw new Error("unreachable");
}
