import { readFileSync } from "node:fs";
import { describe, expect, test, vi } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import { assertRpcEnvelope } from "../rpc/validate.js";
import {
  canonicalizeCandidatesV3,
  decodeArtifactV3JSON,
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
import { readyWebSocketAdmissionV3, type WebSocketLikeV3 } from "./runtimeAdapters.js";
import { createNodeRawQuicClientV3 } from "../node/rawQuicAdapterV3.js";
import type { NativeRawQuicConnectOptionsV3, NativeRawQuicDriverV3 } from "../node/nativeTransportAddon.js";
import type { ArtifactV3 } from "./artifact.js";
import type { NativeCarrierSessionV3 } from "./carrier.js";
import {
  FLOWERSEC_V3_ALPN,
  FLOWERSEC_V3_CRYPTO_LABELS,
  FLOWERSEC_V3_PATHS,
  FLOWERSEC_V3_PROFILE,
  FLOWERSEC_V3_WIRE_PROFILES,
  FLOWERSEC_V3_WEBSOCKET_SUBPROTOCOLS,
  alpnForPathV3,
} from "./transportConstants.js";

type IsolationFixture = Readonly<{
  version: number;
  frames: readonly Readonly<{ id: string; v3_hex: string; v2_magic_hex: string; v2_version_hex: string }>[];
  profile_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
  path_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
  subprotocol_mutations: readonly Readonly<{ id: string; v3: string; v2: string; error_code: string }>[];
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
      if (mutation.id === "session") {
        expect(mutation.v3).toBe(FLOWERSEC_V3_PROFILE);
        const artifactVector = JSON.parse(readFileSync(
          new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
          "utf8",
        )).positive[0] as { artifact_json: string };
        const artifactWire = JSON.parse(artifactVector.artifact_json);
        artifactWire.profile = mutation.v2;
        expect(() => decodeArtifactV3JSON(JSON.stringify(artifactWire))).toThrow();
        continue;
      } else {
        expect(mutation.v3).toBe(kind === "direct" ? FLOWERSEC_V3_WIRE_PROFILES.direct : FLOWERSEC_V3_WIRE_PROFILES.tunnel);
      }
      expect(() => canonicalizeCandidatesV3(kind, [candidate(
        `wss://example.com/flowersec/v3/${kind}`,
        mutation.v2,
      )])).toThrow();
    }
    for (const mutation of fixture.path_mutations) {
      expect(mutation.error_code).toBe("version_isolation");
      const kind = mutation.id.includes("-tunnel") ? "tunnel" : "direct";
      const carrier = mutation.id.startsWith("webtransport") ? "webtransport" : "websocket";
      const validURL = carrier === "webtransport"
        ? FLOWERSEC_V3_PATHS.webtransport[kind]
        : FLOWERSEC_V3_PATHS.websocket[kind];
      const invalidURL = mutation.v2;
      expect(mutation.v3).toBe(validURL);
      expect(() => canonicalizeCandidatesV3(kind, [candidate(
        `${carrier === "webtransport" ? "https://" : "wss://"}example.com${invalidURL}`,
        `flowersec-${kind}/3`,
        carrier,
      )])).toThrow();
    }
    for (const mutation of fixture.alpn_mutations) {
      expect(mutation.error_code).toBe("version_isolation");
      const kind = mutation.id === "tunnel" ? "tunnel" : "direct";
      expect(mutation.v3).toBe(alpnForPathV3(kind));
      expect(mutation.v3).toBe(FLOWERSEC_V3_ALPN[kind]);
      expect(mutation.v3).not.toBe(mutation.v2);
    }
    const cryptoLabels: Readonly<Record<string, string>> = {
      ...FLOWERSEC_V3_CRYPTO_LABELS,
    };
    expect(Object.keys(cryptoLabels).sort()).toEqual(
      fixture.crypto_label_mutations.map(({ id }) => id).sort(),
    );
    for (const mutation of fixture.crypto_label_mutations) {
      expect(mutation.error_code).toBe("version_isolation");
      expect(cryptoLabels[mutation.id]).toBe(mutation.v3);
      expect(mutation.v3).not.toBe(mutation.v2);
    }
  });

  test("v2 WebSocket admission subprotocols are rejected by the production adapter", async () => {
    for (const mutation of fixture.subprotocol_mutations) {
      const kind = mutation.id === "websocket-tunnel" ? "tunnel" : "direct";
      expect(["websocket-direct", "websocket-tunnel"]).toContain(mutation.id);
      expect(mutation.error_code).toBe("version_isolation");
      const artifactVector = JSON.parse(readFileSync(
        new URL("../../../testdata/transport_v3/artifact_vectors.json", import.meta.url),
        "utf8",
      )).positive.find((vector: { artifact_json: string }) =>
        JSON.parse(vector.artifact_json).path.kind === kind);
      const artifact = decodeArtifactV3JSON(artifactVector.artifact_json);
      const candidate = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates
        .find(({ carrier }) => carrier === "websocket")!;
      const socket = fakeSocket(1, mutation.v2);
      await expect(readyWebSocketAdmissionV3(
        candidate,
        artifact,
        socket,
        new AbortController().signal,
      )).rejects.toMatchObject({ code: "connection_failed" });
      expect(socket.close).toHaveBeenCalledOnce();
      expect(FLOWERSEC_V3_WEBSOCKET_SUBPROTOCOLS[kind]).toBe(mutation.v3);
    }
  });

  test("raw QUIC adapter binds the candidate to the v3 ALPN profile", async () => {
    const calls: NativeRawQuicConnectOptionsV3[] = [];
    const driver: NativeRawQuicDriverV3 = {
      connectRawQuic: async (options) => { calls.push(options); return {} as NativeCarrierSessionV3; },
      bindRawQuic: async () => { throw new Error("unused"); },
    };
    const base = {
      carrier: "raw_quic" as const,
      id: "raw",
      normalized_url: "quic://example.com:443",
      tls: {
        mode: "pin" as const,
        pins: [{
          algorithm: "sha-256" as const,
          not_after_unix_s: 1_900_000_100,
          value_b64u: Buffer.alloc(32, 7).toString("base64url"),
        }],
      },
    };
    for (const mutation of fixture.alpn_mutations) {
      const kind = mutation.id === "tunnel" ? "tunnel" : "direct";
      const artifact = {
        path: { kind },
        session: { max_inbound_streams: 1 },
      } as unknown as ArtifactV3;
      await createNodeRawQuicClientV3(driver, {
        ...base,
        wire_profile: FLOWERSEC_V3_ALPN[kind],
      }, artifact, 1_900_000_000);
      const accepted = calls.length;
      await expect(createNodeRawQuicClientV3(driver, {
        ...base,
        wire_profile: mutation.v2,
      }, artifact, 1_900_000_000)).rejects.toMatchObject({
        code: "invalid_artifact",
      });
      expect(calls).toHaveLength(accepted);
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
          expect(decodeFSB3RequestV3(valid).request.profile).toBe(FLOWERSEC_V3_PROFILE);
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
          const transport = {
            maxDatagramSize: 1024,
            send: async () => "accepted" as const,
            receive: async () => sealed.wire,
          };
          const channel = createInternalUnreliableMessageChannelV3({
            transport,
            suite: vector.suite as CipherSuiteV3,
            h3: base64urlDecode(vector.h3_b64u),
            sendDirection: vector.direction as DirectionV3,
            receiveDirection: vector.direction as DirectionV3,
            currentSendEpoch: () => ({ epoch: vector.epoch, epochSecret: base64urlDecode(vector.epoch_secret_b64u) }),
            receiveEpochSecret: (epoch) => epoch === vector.epoch ? base64urlDecode(vector.epoch_secret_b64u) : undefined,
            onProtocolFailure: () => undefined,
            now: () => 0,
          });
          expect(await channel.receive()).toEqual(base64urlDecode(vector.plaintext_b64u));
          for (const mutation of [magic, version]) {
            const onProtocolFailure = vi.fn();
            const invalidChannel = createInternalUnreliableMessageChannelV3({
              transport: {
                ...transport,
                receive: async () => mutation,
              },
              suite: vector.suite as CipherSuiteV3,
              h3: base64urlDecode(vector.h3_b64u),
              sendDirection: vector.direction as DirectionV3,
              receiveDirection: vector.direction as DirectionV3,
              currentSendEpoch: () => ({ epoch: vector.epoch, epochSecret: base64urlDecode(vector.epoch_secret_b64u) }),
              receiveEpochSecret: (epoch) => epoch === vector.epoch ? base64urlDecode(vector.epoch_secret_b64u) : undefined,
              onProtocolFailure,
              now: () => 0,
            });
            await expect(invalidChannel.receive()).rejects.toMatchObject({ code: "closed" });
            expect(onProtocolFailure).toHaveBeenCalledOnce();
          }
          break;
        }
      }
    }
  });

  test("inherited FSH3, OPEN, and RPC codecs remain production session codecs", () => {
    const handshake = fixture.frames.find((frame) => frame.id === "fsh3")!;
    const clientInit = decodeClientInitV3(fromHex(handshake.v3_hex));
    expect(clientInit.profile).toBe(FLOWERSEC_V3_PROFILE);

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

function fakeSocket(readyState: number, protocol: string): WebSocketLikeV3 & Readonly<{ close: ReturnType<typeof vi.fn> }> {
  const socket = {
    binaryType: "",
    readyState,
    protocol,
    bufferedAmount: 0,
    send: vi.fn(),
    close: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  } as unknown as WebSocketLikeV3 & Readonly<{ close: ReturnType<typeof vi.fn> }>;
  return socket;
}
