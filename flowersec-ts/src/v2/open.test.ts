import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeOpenPayload, encodeOpenPayload } from "./protocol.js";

type Vector = Readonly<{
  id: string;
  kind?: string;
  kind_utf8_hex?: string;
  metadata_json?: string;
  metadata_hex?: string;
}>;

const fixture = JSON.parse(
  readFileSync(
    new URL(
      "../../../testdata/transport_v2/open_unicode_vectors.json",
      import.meta.url,
    ),
    "utf8",
  ),
) as { unicode_version: string; positive: Vector[]; negative: Vector[] };

const bytes = (value: string): Uint8Array => new TextEncoder().encode(value);
const fromHex = (value: string): Uint8Array =>
  Uint8Array.from(Buffer.from(value, "hex"));

describe("OPEN Unicode 15.1 and canonical metadata", () => {
  it("accepts the shared positive vectors", () => {
    expect(fixture.unicode_version).toBe("15.1.0");
    for (const vector of fixture.positive) {
      const encoded = encodeOpenPayload({
        logicalStreamID: 1n,
        fss2Hash: new Uint8Array(32),
        kind: vector.kind!,
        metadata: bytes(vector.metadata_json!),
      });
      const decoded = decodeOpenPayload(encoded);
      expect(decoded.kind, vector.id).toBe(vector.kind);
      expect(new TextDecoder().decode(decoded.metadata), vector.id).toBe(
        vector.metadata_json,
      );
    }
  });

  it("rejects the shared negative vectors", () => {
    for (const vector of fixture.negative) {
      const metadata =
        vector.metadata_hex === undefined
          ? bytes(vector.metadata_json!)
          : fromHex(vector.metadata_hex);
      if (vector.kind_utf8_hex !== undefined) {
        const kind = fromHex(vector.kind_utf8_hex);
        const raw = new Uint8Array(46 + kind.length + metadata.length);
        new DataView(raw.buffer).setBigUint64(0, 1n, false);
        new DataView(raw.buffer).setUint16(40, kind.length, false);
        new DataView(raw.buffer).setUint32(42, metadata.length, false);
        raw.set(kind, 46);
        raw.set(metadata, 46 + kind.length);
        expect(() => decodeOpenPayload(raw), vector.id).toThrow();
        continue;
      }
      expect(
        () =>
          encodeOpenPayload({
            logicalStreamID: 1n,
            fss2Hash: new Uint8Array(32),
            kind: vector.kind!,
            metadata,
          }),
        vector.id,
      ).toThrow();
    }
  });

  it("enforces every existing OPEN metadata limit at the boundary", () => {
    const array = (count: number): string =>
      `[${Array.from({ length: count }, () => "0").join(",")}]`;
    const keys = (count: number): string =>
      `{${Array.from({ length: count }, (_, index) => `"k${index.toString().padStart(2, "0")}":0`).join(",")}}`;
    const metadata4096 = `{"a":"${"a".repeat(512)}","b":"${"b".repeat(512)}","c":"${"c".repeat(
      512,
    )}","d":"${"d".repeat(512)}","e":"${"e".repeat(512)}","f":"${"f".repeat(512)}","g":"${"g".repeat(
      512,
    )}","h":"${"h".repeat(455)}"}`;
    expect(bytes(metadata4096).length).toBe(4_096);

    const encode = (kind: string, metadata: string | Uint8Array): Uint8Array =>
      encodeOpenPayload({
        logicalStreamID: 1n,
        fss2Hash: new Uint8Array(32),
        kind,
        metadata: typeof metadata === "string" ? bytes(metadata) : metadata,
      });

    for (const [kind, metadata] of [
      ["k".repeat(128), "{}"],
      ["rpc", `{"${"k".repeat(64)}":"${"s".repeat(512)}"}`],
      ["rpc", `{"a":${array(32)}}`],
      ["rpc", '{"a":{"b":{"c":0}}}'],
      ["rpc", `{"a":${array(32)},"b":${array(30)}}`],
      ["rpc", keys(64)],
      ["rpc", metadata4096],
    ] as const) {
      expect(() => encode(kind, metadata)).not.toThrow();
    }

    for (const [kind, metadata] of [
      ["k".repeat(129), "{}"],
      ["rpc", `{"${"k".repeat(65)}":0}`],
      ["rpc", `{"a":"${"s".repeat(513)}"}`],
      ["rpc", `{"a":${array(33)}}`],
      ["rpc", '{"a":{"b":{"c":{"d":0}}}}'],
      ["rpc", `{"a":${array(32)},"b":${array(32)}}`],
      ["rpc", keys(65)],
      ["rpc", `{"a":"${"s".repeat(4_090)}"}`],
    ] as const) {
      expect(() => encode(kind, metadata)).toThrow();
    }

    const empty = decodeOpenPayload(encode("rpc", new Uint8Array()));
    expect(new TextDecoder().decode(empty.metadata)).toBe("{}");
  });
});
