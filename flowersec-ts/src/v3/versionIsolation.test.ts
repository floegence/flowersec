import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import { assertRpcEnvelope } from "../rpc/validate.js";
import {
  canonicalizeCandidatesV3,
  decodeFSA3ResponseV3,
  decodeFSB3RequestV3,
} from "./artifact.js";
import {
  decodeClientInitV3,
  decodeHandshakeFrameV3,
  parseControlPrefaceV3,
} from "./handshake.js";
import {
  decodeOpenPayload,
  encodeOpenPayload,
  decodeRecordHeader,
  decodeSetupPrefaceV3,
} from "./protocol.js";
import {
  createInternalUnreliableMessageChannelV3,
  sealUnreliableMessageDatagramV3,
} from "./unreliableMessage.js";
import type { DirectionV3, CipherSuiteV3 } from "./protocol.js";

type IsolationFixture = Readonly<{
  version: number;
  frames: readonly Readonly<{ id: string; v3_hex: string; v2_magic_hex: string; v2_version_hex: string }>[];
  profile_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
  path_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
  alpn_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
  crypto_label_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
  inherited_codecs: Readonly<{
    fsh3: Readonly<{ frame_id: string }>;
    open: Readonly<{ vector_id: string }>;
    rpc: Readonly<{ envelope_json: string }>;
  }>;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/version_isolation_vectors.json", import.meta.url),
  "utf8",
)) as IsolationFixture;
const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));

describe("transport v3 version isolation", () => {
  test("profile and path mutations fail at the production candidate boundary", () => {
    const candidate = (url: string, wireProfile: string, carrier: "websocket" | "webtransport" = "websocket") => ({
      carrier,
      id: "isolation",
      url,
      normalized_url: url,
      tls: { mode: "ca" as const },
      wire_profile: wireProfile,
    });
    for (const mutation of fixture.profile_mutations) {
      expect(mutation.error_code).toBe("version_isolation");
      const kind = mutation.id === "tunnel" ? "tunnel" : "direct";
      expect(() => canonicalizeCandidatesV3(kind, [candidate(
        `wss://example.com/flowersec/v3/${kind}`,
        mutation.v2,
      )])).toThrow();
    }
    for (const mutation of fixture.path_mutations) {
      expect(mutation.error_code).toBe("version_isolation");
      if (mutation.id.endsWith("-subprotocol")) continue;
      const kind = mutation.id.endsWith("-tunnel") ? "tunnel" : "direct";
      const carrier = mutation.id.startsWith("webtransport") ? "webtransport" : "websocket";
      const validURL = carrier === "webtransport"
        ? `https://example.com/flowersec/webtransport/v3/${kind}`
        : `wss://example.com/flowersec/v3/${kind}`;
      const invalidURL = validURL.replace("/v3/", "/v2/");
      expect(() => canonicalizeCandidatesV3(kind, [candidate(
        invalidURL,
        `flowersec-${kind}/3`,
        carrier,
      )])).toThrow();
    }
    for (const mutation of [...fixture.alpn_mutations, ...fixture.crypto_label_mutations]) {
      expect(mutation.error_code).toBe("version_isolation");
      expect(mutation.v3).not.toBe(mutation.v2);
    }
  });

  test("all v2 magic and version mutations fail closed in production decoders", async () => {
    expect(fixture.version).toBe(3);
    for (const frame of fixture.frames) {
      const valid = fromHex(frame.v3_hex);
      const magic = fromHex(frame.v2_magic_hex);
      const version = fromHex(frame.v2_version_hex);
      switch (frame.id) {
        case "fsb3":
          expect(decodeFSB3RequestV3(valid).request.profile).toBe("flowersec/3");
          expect(() => decodeFSB3RequestV3(magic)).toThrow();
          expect(() => decodeFSB3RequestV3(version)).toThrow();
          break;
        case "fsa3":
          expect(decodeFSA3ResponseV3(valid).reason).toBe("invalid_token");
          expect(() => decodeFSA3ResponseV3(magic)).toThrow();
          expect(() => decodeFSA3ResponseV3(version)).toThrow();
          break;
        case "fsc3":
          expect(() => parseControlPrefaceV3(valid)).not.toThrow();
          expect(() => parseControlPrefaceV3(magic)).toThrow();
          expect(() => parseControlPrefaceV3(version)).toThrow();
          break;
        case "fsh3":
          expect(decodeHandshakeFrameV3(valid).type).toBe(1);
          expect(() => decodeHandshakeFrameV3(magic)).toThrow();
          expect(() => decodeHandshakeFrameV3(version)).toThrow();
          break;
        case "fss3":
          expect(decodeSetupPrefaceV3(valid).logicalStreamID).toBe(1n);
          expect(() => decodeSetupPrefaceV3(magic)).toThrow();
          expect(() => decodeSetupPrefaceV3(version)).toThrow();
          break;
        case "fsr3":
          expect(decodeRecordHeader(valid).epoch).toBe(0);
          expect(() => decodeRecordHeader(magic)).toThrow();
          expect(() => decodeRecordHeader(version)).toThrow();
          break;
        case "fsd3": {
          const vector = JSON.parse(readFileSync(
            new URL("../../../testdata/transport_v3/datagram_vectors.json", import.meta.url), "utf8"),
          ).vectors[0];
          const sealed = sealUnreliableMessageDatagramV3({
            suite: vector.suite as CipherSuiteV3,
            epochSecret: base64urlDecode(vector.epoch_secret_b64u),
            h3: base64urlDecode(vector.h3_b64u),
            direction: vector.direction as DirectionV3,
            epoch: vector.epoch,
            sequence: BigInt(vector.sequence),
            expiresAtUnixMs: BigInt(vector.expires_at_unix_ms),
            plaintext: base64urlDecode(vector.plaintext_b64u),
          });
          expect(Buffer.from(sealed.header).toString("hex")).toBe(frame.v3_hex);
          const queue = [magic, version, sealed.wire];
          const transport = {
            maxDatagramSize: 1024,
            send: async () => "accepted" as const,
            receive: async () => queue.shift()!,
          };
          const channel = createInternalUnreliableMessageChannelV3({
            transport,
            suite: vector.suite as CipherSuiteV3,
            h3: base64urlDecode(vector.h3_b64u),
            sendDirection: vector.direction as DirectionV3,
            receiveDirection: vector.direction as DirectionV3,
            currentSendEpoch: () => ({ epoch: vector.epoch, epochSecret: base64urlDecode(vector.epoch_secret_b64u) }),
            receiveEpochSecret: (epoch) => epoch === vector.epoch ? base64urlDecode(vector.epoch_secret_b64u) : undefined,
            now: () => 0,
          });
          expect(await channel.receive()).toEqual(base64urlDecode(vector.plaintext_b64u));
          break;
        }
      }
    }
  });

  test("inherited FSH3, OPEN, and RPC codecs remain production session codecs", () => {
    const handshake = fixture.frames.find((frame) => frame.id === "fsh3")!;
    const clientInit = decodeClientInitV3(fromHex(handshake.v3_hex));
    expect(clientInit.profile).toBe("flowersec/3");

    const openFixture = JSON.parse(readFileSync(
      new URL("../../../testdata/transport_v3/open_unicode_vectors.json", import.meta.url), "utf8"),
    );
    const open = openFixture.positive.find((vector: { id: string }) =>
      vector.id === fixture.inherited_codecs.open.vector_id);
    expect(open).toBeDefined();
    const encoded = encodeOpenPayload({
      logicalStreamID: 1n,
      fss3Hash: new Uint8Array(32),
      kind: open.kind,
      metadata: new TextEncoder().encode(open.metadata_json),
    });
    expect(new TextDecoder().decode(decodeOpenPayload(encoded).metadata)).toBe(open.metadata_json);

    const rpc = assertRpcEnvelope(JSON.parse(fixture.inherited_codecs.rpc.envelope_json));
    expect((rpc.payload as { ratio: number }).ratio).toBe(1.5);
  });
});
