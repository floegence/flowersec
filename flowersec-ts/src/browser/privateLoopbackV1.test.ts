import { readFileSync } from "node:fs";

import { afterEach, describe, expect, test, vi } from "vitest";

import {
  connect,
  connectPrivateLoopbackV1,
  createPrivateLoopbackArtifactLeaseV1,
  createPrivateLoopbackConnectionControllerV1,
  parseArtifact,
  parsePrivateLoopbackArtifactV1,
  type ConnectError,
} from "./index.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { canonicalizeJCSV3, type JCSValue } from "../v3/jcs.js";
import { decodeArtifactV3JSON, encodeArtifactV3JSON } from "../v3/artifact.js";
import type { ArtifactLeaseV3 } from "../v3/artifactLease.js";

type PrivateLoopbackVectors = Readonly<{
  version: 1;
  profile: "flowersec-private-loopback/1";
  nested_profile: "flowersec/3";
  positive: readonly Readonly<{ id: string; endpoint: string; artifact_json: string }>[];
  negative_endpoint_values: readonly string[];
}>;

const vectors = JSON.parse(readFileSync(
  new URL("../../../testdata/private_loopback_v1/profile_vectors.json", import.meta.url),
  "utf8",
)) as PrivateLoopbackVectors;
const positive = vectors.positive[0]!;

describe("private loopback transport profile v1", () => {
  afterEach(() => vi.unstubAllGlobals());

  test("parses every shared IPv4 and IPv6 positive vector", () => {
    for (const vector of vectors.positive) {
      expect(parsePrivateLoopbackArtifactV1(vector.artifact_json)).toBeDefined();
      expect(() => parseArtifact(vector.artifact_json)).toThrow(expect.objectContaining({ code: "invalid_artifact" }));
    }
  });

  test("keeps the profile isolated from the ordinary flowersec/3 parser and connector", async () => {
    expect(() => parseArtifact(positive.artifact_json)).toThrow(expect.objectContaining({ code: "invalid_artifact" }));
    const privateArtifact = parsePrivateLoopbackArtifactV1(positive.artifact_json);
    const privateLease = createPrivateLoopbackArtifactLeaseV1(privateArtifact, async () => undefined);
    await expect(connect(privateLease as unknown as ArtifactLeaseV3)).rejects.toEqual(
      expect.objectContaining<Partial<ConnectError>>({ code: "artifact_invalid" }),
    );
    await expect(connectPrivateLoopbackV1(
      {} as ReturnType<typeof createPrivateLoopbackArtifactLeaseV1>,
      { origin: "http://127.0.0.1:23998" },
    )).rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({ code: "artifact_invalid" }));
  });

  test("rejects non-loopback, TLS, tunnel, and noncanonical endpoint mutations", () => {
    const envelope = JSON.parse(positive.artifact_json) as Record<string, unknown>;
    for (const endpoint of vectors.negative_endpoint_values) {
      const mutated = canonicalizeJCSV3({ ...envelope, endpoint } as JCSValue);
      expect(() => parsePrivateLoopbackArtifactV1(mutated)).toThrow(expect.objectContaining({ code: "invalid_artifact" }));
    }
    expect(() => parsePrivateLoopbackArtifactV1(canonicalizeJCSV3({
      ...envelope,
      profile: "flowersec/3",
    } as JCSValue))).toThrow(expect.objectContaining({ code: "invalid_artifact" }));
  });

  test("requires an exact canonical outer envelope", () => {
    const envelope = JSON.parse(positive.artifact_json) as Record<string, unknown>;
    for (const mutated of [
      JSON.stringify(envelope, null, 2),
      canonicalizeJCSV3({ ...envelope, extra: true } as JCSValue),
      canonicalizeJCSV3({ ...envelope, v: 2 } as JCSValue),
      canonicalizeJCSV3({ ...envelope, artifact_b64u: "not_base64!" } as JCSValue),
      positive.artifact_json.replace("\"v\":1", "\"v\":1,\"v\":1"),
    ]) {
      expect(() => parsePrivateLoopbackArtifactV1(mutated)).toThrow(
        expect.objectContaining({ code: "invalid_artifact" }),
      );
    }
    expect(() => parsePrivateLoopbackArtifactV1("x".repeat(100_001))).toThrow(
      expect.objectContaining({ code: "invalid_artifact" }),
    );
  });

  test("binds the private endpoint to the exact nested v3 authority", () => {
    const envelope = JSON.parse(positive.artifact_json) as Record<string, unknown> & { artifact_b64u: string };
    const inner = decodeArtifactV3JSON(base64urlDecode(envelope.artifact_b64u));
    const candidate = inner.path.candidates[0]!;
    const mismatchedURL = "wss://127.0.0.1:23999/flowersec/v3/direct";
    const mismatched = encodeArtifactV3JSON({
      ...inner,
      path: {
        ...inner.path,
        candidates: [{
          ...candidate,
          url: mismatchedURL,
          normalized_url: mismatchedURL,
        }],
      },
    });
    const mutated = canonicalizeJCSV3({
      ...envelope,
      artifact_b64u: base64urlEncode(mismatched),
    } as JCSValue);
    expect(() => parsePrivateLoopbackArtifactV1(mutated)).toThrow(expect.objectContaining({ code: "invalid_artifact" }));
  });

  test("rejects nested v3 values outside the one direct CA WebSocket contract", () => {
    const envelope = JSON.parse(positive.artifact_json) as Record<string, unknown> & { artifact_b64u: string };
    const inner = decodeArtifactV3JSON(base64urlDecode(envelope.artifact_b64u));
    const candidate = inner.path.candidates[0]!;
    for (const mutatedCandidate of [
      { ...candidate, id: "other" },
      { ...candidate, wire_profile: "flowersec-tunnel/3" },
      { ...candidate, carrier: "webtransport" },
      { ...candidate, normalized_url: "wss://127.0.0.1:23999/flowersec/v3/direct" },
    ]) {
      let encoded: Uint8Array;
      try {
        encoded = encodeArtifactV3JSON({
          ...inner,
          path: { ...inner.path, candidates: [mutatedCandidate] },
        } as typeof inner);
      } catch {
        continue;
      }
      const mutated = canonicalizeJCSV3({
        ...envelope,
        artifact_b64u: base64urlEncode(encoded),
      } as JCSValue);
      expect(() => parsePrivateLoopbackArtifactV1(mutated)).toThrow(
        expect.objectContaining({ code: "invalid_artifact" }),
      );
    }
    const innerWire = JSON.parse(new TextDecoder().decode(base64urlDecode(envelope.artifact_b64u))) as {
      path: { candidates: Array<Record<string, unknown>> };
    } & Record<string, unknown>;
    const duplicated = new TextEncoder().encode(canonicalizeJCSV3({
      ...innerWire,
      path: {
        ...innerWire.path,
        candidates: [innerWire.path.candidates[0]!, { ...innerWire.path.candidates[0]!, id: "other" }],
      },
    } as JCSValue));
    expect(() => parsePrivateLoopbackArtifactV1(canonicalizeJCSV3({
      ...envelope,
      artifact_b64u: base64urlEncode(duplicated),
    } as JCSValue))).toThrow(expect.objectContaining({ code: "invalid_artifact" }));
  });

  test("requires the exact HTTP origin and dials only the mapped loopback WebSocket", async () => {
    const calls: string[] = [];
    class PrivateWebSocket {
      constructor(url: string) {
        calls.push(url);
        throw new Error("test endpoint intentionally unavailable");
      }
    }
    vi.stubGlobal("WebSocket", PrivateWebSocket);
    vi.stubGlobal("WebTransport", undefined);

    const lease = () => createPrivateLoopbackArtifactLeaseV1(
      parsePrivateLoopbackArtifactV1(positive.artifact_json),
      async () => undefined,
    );
    await expect(connectPrivateLoopbackV1(lease(), { origin: "http://127.0.0.1:23999" }))
      .rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({ code: "artifact_invalid" }));
    expect(calls).toHaveLength(0);

    await expect(connectPrivateLoopbackV1(lease(), { origin: "http://127.0.0.1:23998" }))
      .rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({ code: "connection_failed" }));
    expect(calls).toEqual([positive.endpoint]);
  });

  test("rejects noncanonical, privileged-port, and non-loopback origins as public terminal errors", async () => {
    const calls: string[] = [];
    class PrivateWebSocket {
      constructor(url: string) { calls.push(url); }
    }
    vi.stubGlobal("WebSocket", PrivateWebSocket);
    for (const origin of [
      "https://127.0.0.1:23998",
      "http://localhost:23998",
      "http://2130706433:23998",
      "http://127.1:23998",
      "http://127.0.0.1.:23998",
      "http://[0:0:0:0:0:0:0:1]:23998",
      "http://127.0.0.1:80",
      "http://127.0.0.1:443",
      "http://127.0.0.1:1023",
      "http://127.0.0.1:23998/",
    ]) {
      const lease = createPrivateLoopbackArtifactLeaseV1(
        parsePrivateLoopbackArtifactV1(positive.artifact_json),
        async () => undefined,
      );
      await expect(connectPrivateLoopbackV1(lease, { origin })).rejects.toEqual(
        expect.objectContaining<Partial<ConnectError>>({ code: "artifact_invalid" }),
      );
    }
    expect(calls).toHaveLength(0);
  });

  test("preserves cancellation and bounded timeout without spending the lease", async () => {
    const sockets: PendingPrivateWebSocket[] = [];
    class PendingPrivateWebSocket {
      binaryType = "";
      readyState = 0;
      protocol = "";
      bufferedAmount = 0;
      readonly close = vi.fn();
      readonly #listeners = new Map<string, Set<(event: unknown) => void>>();

      constructor(readonly url: string) { sockets.push(this); }
      send() {}
      addEventListener(type: string, listener: (event: unknown) => void) {
        const listeners = this.#listeners.get(type) ?? new Set();
        listeners.add(listener);
        this.#listeners.set(type, listeners);
      }
      removeEventListener(type: string, listener: (event: unknown) => void) {
        this.#listeners.get(type)?.delete(listener);
      }
    }
    vi.stubGlobal("WebSocket", PendingPrivateWebSocket);
    vi.stubGlobal("WebTransport", undefined);

    let spends = 0;
    const lease = () => createPrivateLoopbackArtifactLeaseV1(
      parsePrivateLoopbackArtifactV1(positive.artifact_json),
      async () => { spends += 1; },
    );
    const canceled = new AbortController();
    canceled.abort(new Error("caller canceled"));
    await expect(connectPrivateLoopbackV1(lease(), {
      origin: "http://127.0.0.1:23998",
      signal: canceled.signal,
    })).rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({ code: "connection_failed" }));
    expect(sockets).toHaveLength(0);

    await expect(connectPrivateLoopbackV1(lease(), {
      origin: "http://127.0.0.1:23998",
      connectTimeoutMs: 1,
    })).rejects.toEqual(expect.objectContaining<Partial<ConnectError>>({ code: "connection_failed" }));
    expect(sockets).toHaveLength(1);
    expect(sockets[0]!.close).toHaveBeenCalledOnce();
    expect(spends).toBe(0);
  });

  test("keeps controller retries inside the dedicated private profile", async () => {
    const calls: string[] = [];
    class PrivateWebSocket {
      constructor(url: string) {
        calls.push(url);
        throw new Error("test endpoint intentionally unavailable");
      }
    }
    vi.stubGlobal("WebSocket", PrivateWebSocket);
    vi.stubGlobal("WebTransport", undefined);

    const controller = await createPrivateLoopbackConnectionControllerV1({
      acquire: async () => ({
        kind: "lease",
        lease: createPrivateLoopbackArtifactLeaseV1(
          parsePrivateLoopbackArtifactV1(positive.artifact_json),
          async () => undefined,
        ),
      }),
    }, {
      origin: "http://127.0.0.1:23998",
      maximumAttempts: 1,
    });
    controller.start();

    await expect(controller.waitForSession()).rejects.toEqual(
      expect.objectContaining({ code: "failed" }),
    );
    expect(calls).toEqual([positive.endpoint]);
  });

  test("retires exactly one recognizable private lease from malformed source results", async () => {
    const calls: string[] = [];
    class PrivateWebSocket {
      constructor(url: string) { calls.push(url); }
    }
    vi.stubGlobal("WebSocket", PrivateWebSocket);

    for (const malformed of [
      (lease: ReturnType<typeof createPrivateLoopbackArtifactLeaseV1>) => ({ kind: "lease", lease, extra: true }),
      (lease: ReturnType<typeof createPrivateLoopbackArtifactLeaseV1>) => ({ kind: "unknown", lease }),
    ]) {
      let retirements = 0;
      const lease = createPrivateLoopbackArtifactLeaseV1(
        parsePrivateLoopbackArtifactV1(positive.artifact_json),
        async () => undefined,
        async () => { retirements += 1; },
      );
      const controller = await createPrivateLoopbackConnectionControllerV1({
        acquire: async () => malformed(lease) as never,
      }, { origin: "http://127.0.0.1:23998", maximumAttempts: 1 });
      controller.start();
      await expect(controller.waitForSession()).rejects.toEqual(expect.objectContaining({ code: "failed" }));
      expect(retirements).toBe(1);
      await controller.close();
    }
    expect(calls).toHaveLength(0);
  });

  test("retires a late private lease when controller cancellation wins acquisition", async () => {
    let deliver!: (value: unknown) => void;
    let retirements = 0;
    const controller = await createPrivateLoopbackConnectionControllerV1({
      acquire: async () => await new Promise((resolve) => { deliver = resolve; }) as never,
    }, { origin: "http://127.0.0.1:23998" });
    controller.start();
    const closed = controller.close();
    deliver({
      kind: "lease",
      lease: createPrivateLoopbackArtifactLeaseV1(
        parsePrivateLoopbackArtifactV1(positive.artifact_json),
        async () => undefined,
        async () => { retirements += 1; },
      ),
    });
    await closed;
    expect(retirements).toBe(1);
  });
});
