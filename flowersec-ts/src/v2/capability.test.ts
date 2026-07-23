import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  BROWSER_RUNTIME_CAPABILITY_V2,
  NODE_RUNTIME_CAPABILITY_V2,
  decodeRuntimeCapabilityDescriptorV2,
  detectBrowserRuntimeCapabilityV2,
  encodeRuntimeCapabilityDescriptorV2,
  runtimeCapabilityDigestHexV2,
} from "./capability.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/capability_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ vectors: readonly Readonly<{ name: string; canonical_json: string; digest_hex: string }>[] }>;

function vector(name: string) {
  const match = vectors.vectors.find((candidate) => candidate.name === name);
  if (match === undefined) throw new Error(`missing capability vector ${name}`);
  return match;
}

describe("runtime capability v2", () => {
  test("declares browser WebSocket and WebTransport dial tuples without inventing listen support", () => {
    expect(BROWSER_RUNTIME_CAPABILITY_V2).toEqual({
      language: "typescript",
      runtime: "browser",
      schemaVersion: 2,
      tuples: [
        { carrier: "websocket", networkMode: "dial", path: "direct", sessionRole: "client" },
        { carrier: "websocket", networkMode: "dial", path: "tunnel", sessionRole: "client" },
        { carrier: "websocket", networkMode: "dial", path: "tunnel", sessionRole: "server" },
        { carrier: "webtransport", networkMode: "dial", path: "direct", sessionRole: "client" },
        { carrier: "webtransport", networkMode: "dial", path: "tunnel", sessionRole: "client" },
        { carrier: "webtransport", networkMode: "dial", path: "tunnel", sessionRole: "server" },
      ],
      unsupported: [{ carrier: "raw_quic", reason: "browser_no_raw_udp" }],
    });
  });

  test("advertises the production Node WebSocket dial connector", () => {
    expect(NODE_RUNTIME_CAPABILITY_V2).toEqual({
      language: "typescript",
      runtime: "node",
      schemaVersion: 2,
      tuples: [
        { carrier: "websocket", networkMode: "dial", path: "direct", sessionRole: "client" },
        { carrier: "websocket", networkMode: "dial", path: "tunnel", sessionRole: "client" },
        { carrier: "websocket", networkMode: "dial", path: "tunnel", sessionRole: "server" },
      ],
      unsupported: [
        { carrier: "raw_quic", reason: "no_production_grade_node_quic_runtime" },
        { carrier: "webtransport", reason: "no_production_grade_node_quic_runtime" },
      ],
    });
  });

  test("removes WebTransport when the browser runtime API is unavailable", () => {
    const descriptor = detectBrowserRuntimeCapabilityV2({
      WebSocket: function WebSocket() {},
      WebTransport: undefined,
    });
    expect([...new Set(descriptor.tuples.map(({ carrier }) => carrier))]).toEqual(["websocket"]);
    expect(descriptor.unsupported).toContainEqual({
      carrier: "webtransport",
      reason: "browser_webtransport_api_unavailable",
    });
  });

  test("matches the shared strict codec and digest vectors", () => {
    for (const [descriptor, name] of [
      [BROWSER_RUNTIME_CAPABILITY_V2, "typescript-browser"],
      [NODE_RUNTIME_CAPABILITY_V2, "typescript-node"],
    ] as const) {
      const expected = vector(name);
      const encoded = encodeRuntimeCapabilityDescriptorV2(descriptor);
      expect(encoded).toBe(expected.canonical_json);
      expect(runtimeCapabilityDigestHexV2(descriptor)).toBe(expected.digest_hex);
      expect(decodeRuntimeCapabilityDescriptorV2(encoded)).toEqual(descriptor);
      expect(() => decodeRuntimeCapabilityDescriptorV2(` ${encoded}`)).toThrow(/canonical/i);
      expect(() => decodeRuntimeCapabilityDescriptorV2(`${encoded.slice(0, -1)},\"extra\":true}`)).toThrow();
    }
  });

  test("freezes the descriptors and flat tuples", () => {
    expect(Object.isFrozen(BROWSER_RUNTIME_CAPABILITY_V2)).toBe(true);
    expect(Object.isFrozen(BROWSER_RUNTIME_CAPABILITY_V2.tuples)).toBe(true);
    expect(Object.isFrozen(BROWSER_RUNTIME_CAPABILITY_V2.tuples[0])).toBe(true);
    expect(Object.isFrozen(NODE_RUNTIME_CAPABILITY_V2.unsupported)).toBe(true);
  });
});
