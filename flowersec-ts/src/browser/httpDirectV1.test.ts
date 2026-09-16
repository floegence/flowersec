import { readFileSync } from "node:fs";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  parseArtifact, parsePrivateLoopbackArtifactV1, parseHTTPDirectArtifactV1,
  createHTTPDirectArtifactLeaseV1, connectHTTPDirectV1, connect,
} from "./index.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { canonicalizeJCSV3, type JCSValue } from "../v3/jcs.js";
import { decodeArtifactV3JSON, encodeArtifactV3JSON } from "../v3/artifact.js";
import type { ArtifactLeaseV3 } from "../v3/artifactLease.js";

const fixture = JSON.parse(readFileSync(new URL("../../../testdata/private_loopback_v1/profile_vectors.json", import.meta.url), "utf8")) as {positive: {artifact_json: string}[]};

export function httpArtifact(endpoint = "ws://192.168.1.20:23998/flowersec/v3/direct"): string {
  const envelope = JSON.parse(fixture.positive[0]!.artifact_json) as {artifact_b64u: string};
  const inner = decodeArtifactV3JSON(base64urlDecode(envelope.artifact_b64u));
  const url = new URL(endpoint);
  const port = url.port || "80";
  url.protocol = "wss:";
  url.port = port;
  const candidate = {...inner.path.candidates[0]!, id: "http-direct", url: url.href, normalized_url: url.href};
  const bytes = encodeArtifactV3JSON({...inner, path: {...inner.path, candidates: [candidate]}});
  return canonicalizeJCSV3({v: 1, profile: "flowersec-http-direct/1", endpoint, artifact_b64u: base64urlEncode(bytes)} as JCSValue);
}

describe("explicit HTTP direct profile", () => {
  afterEach(() => vi.unstubAllGlobals());
  test("supports network and local HTTP while keeping TLS and private artifacts separate", () => {
    for (const endpoint of ["ws://192.168.1.20:23998/flowersec/v3/direct", "ws://localhost:23998/flowersec/v3/direct", "ws://[2001:db8::1]:23998/flowersec/v3/direct", "ws://localhost/flowersec/v3/direct"]) {
      const wire = httpArtifact(endpoint);
      expect(parseHTTPDirectArtifactV1(wire)).toBeDefined();
      expect(() => parseArtifact(wire)).toThrow();
      expect(() => parsePrivateLoopbackArtifactV1(wire)).toThrow();
    }
    expect(() => parseHTTPDirectArtifactV1(fixture.positive[0]!.artifact_json)).toThrow();
  });
  test("requires the exact same origin and never spends a cross-origin lease", async () => {
    let spent = 0;
    const lease = createHTTPDirectArtifactLeaseV1(parseHTTPDirectArtifactV1(httpArtifact()), async () => { spent++; });
    await expect(connectHTTPDirectV1(lease, {origin: "http://192.168.1.21:23998"})).rejects.toMatchObject({code: "artifact_invalid"});
    expect(spent).toBe(0);
    await expect(connect(lease as unknown as ArtifactLeaseV3)).rejects.toMatchObject({code: "artifact_invalid"});
  });
  test("preserves the HTTP port when the nested TLS binding uses a default port", async () => {
    const calls: string[] = [];
    vi.stubGlobal("WebSocket", class {
      constructor(url: string) { calls.push(url); throw new Error("test endpoint unavailable"); }
    });
    vi.stubGlobal("WebTransport", undefined);
    const endpoints = [
      "ws://localhost/flowersec/v3/direct",
      "ws://localhost:443/flowersec/v3/direct",
      "ws://[2001:db8::1]:443/flowersec/v3/direct",
      "ws://192.168.1.20:23998/flowersec/v3/direct",
    ];
    for (const endpoint of endpoints) {
      const lease = createHTTPDirectArtifactLeaseV1(parseHTTPDirectArtifactV1(httpArtifact(endpoint)), async () => undefined);
      await expect(connectHTTPDirectV1(lease, {origin: new URL(endpoint).origin.replace(/^ws:/, "http:")}))
        .rejects.toMatchObject({code: "connection_failed"});
    }
    expect(calls).toEqual(endpoints);
  });
  test("rejects authority and profile mutations", () => {
    const envelope = JSON.parse(httpArtifact()) as Record<string, JCSValue>;
    for (const endpoint of ["ws://0.0.0.0:23998/flowersec/v3/direct", "ws://192.168.1.21:23998/flowersec/v3/direct", "ws://192.168.1.20:23998/flowersec/v3/tunnel", "wss://192.168.1.20:23998/flowersec/v3/direct"]) {
      expect(() => parseHTTPDirectArtifactV1(canonicalizeJCSV3({...envelope, endpoint}))).toThrow();
    }
  });
});
