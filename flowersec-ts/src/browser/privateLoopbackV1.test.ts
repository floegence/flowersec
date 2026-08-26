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
});
