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
import { createInternalUnreliableMessageChannelV3 } from "./unreliableMessage.js";
import type { DirectionV3, CipherSuiteV3 } from "./protocol.js";
import { readyWebSocketAdmissionV3, type WebSocketLikeV3 } from "./runtimeAdapters.js";
import { createNodeRawQuicClientV3 } from "../node/rawQuicAdapterV3.js";
import type { NativeRawQuicConnectOptions, NativeRawQuicDriver } from "../node/nativeTransportAddon.js";
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

const previousVersions = [2, 3, 4] as const;
type PreviousVersion = (typeof previousVersions)[number];
type IsolationFrame = Readonly<{ id: string; v5_hex: string } & Record<
  `v${PreviousVersion}_${"magic" | "version"}_hex`, string
>>;
type Identifier = Readonly<{ id: string; v5: string; v2: string; error_code: string }>;
type DatagramVector = Readonly<{
  suite: CipherSuiteV3;
  direction: DirectionV3;
  epoch: number;
  h3_b64u: string;
  epoch_secret_b64u: string;
  plaintext_b64u: string;
  header_hex: string;
  wire_b64u: string;
}>;
type IsolationFixture = Readonly<{
  version: number;
  frames: readonly IsolationFrame[];
  profile_mutations: readonly Identifier[];
  path_mutations: readonly Identifier[];
  subprotocol_mutations: readonly Identifier[];
  alpn_mutations: readonly Identifier[];
  crypto_label_mutations: readonly Identifier[];
  application_codecs: Readonly<{
    fsh5: Readonly<{ frame_id: string }>;
    open: Readonly<{ vector_id: string }>;
    rpc: Readonly<{ envelope_json: string }>;
  }>;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v5/version_isolation_vectors.json", import.meta.url),
  "utf8",
)) as IsolationFixture;
const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));

const artifacts = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v5/artifact_vectors.json", import.meta.url), "utf8",
)) as { positive: { path_kind: "direct" | "tunnel"; artifact_json: string }[] };

function previousIdentifiers(identifier: Identifier): string[] {
  expect(identifier.error_code).toBe("version_isolation");
  const previous = previousVersions.map((version) => identifier.v5.replace("5", String(version)));
  expect(previous[0]).toBe(identifier.v2);
  return previous;
}

describe("transport v5 version isolation", () => {
  test("profile and path mutations fail at the production candidate boundary", () => {
    const candidate = (url: string, wireProfile: string, carrier: "websocket" | "webtransport" = "websocket") => ({
      carrier,
      id: "isolation",
      url,
      tls: { mode: "ca" as const },
      wire_profile: wireProfile,
    });
    for (const mutation of fixture.profile_mutations) {
      const kind = mutation.id === "tunnel" ? "tunnel" : "direct";
      if (mutation.id === "session") {
        expect(mutation.v5).toBe(FLOWERSEC_V3_PROFILE);
        const artifact = JSON.parse(artifacts.positive[0]!.artifact_json);
        expect(decodeArtifactV3JSON(JSON.stringify(artifact)).profile).toBe(mutation.v5);
        for (const profile of previousIdentifiers(mutation)) {
          expect(() => decodeArtifactV3JSON(JSON.stringify({ ...artifact, profile }))).toThrow(/version or profile/);
        }
      } else {
        expect(mutation.v5).toBe(FLOWERSEC_V3_WIRE_PROFILES[kind]);
        const url = `wss://example.com${FLOWERSEC_V3_PATHS.websocket[kind]}`;
        expect(canonicalizeCandidatesV3(kind, [candidate(url, mutation.v5)]).candidates[0]?.wire_profile)
          .toBe(mutation.v5);
        for (const profile of previousIdentifiers(mutation)) {
          expect(() => canonicalizeCandidatesV3(kind, [candidate(url, profile)])).toThrow(/wire profile/);
        }
      }
    }
    for (const mutation of fixture.path_mutations) {
      const kind = mutation.id.includes("-tunnel") ? "tunnel" : "direct";
      const carrier = mutation.id.startsWith("webtransport") ? "webtransport" : "websocket";
      const origin = `${carrier === "webtransport" ? "https" : "wss"}://example.com`;
      const withPath = (path: string) => candidate(`${origin}${path}`, FLOWERSEC_V3_WIRE_PROFILES[kind], carrier);
      expect(mutation.v5).toBe(FLOWERSEC_V3_PATHS[carrier][kind]);
      expect(canonicalizeCandidatesV3(kind, [withPath(mutation.v5)]).candidates[0]?.normalized_url)
        .toBe(`${origin}${mutation.v5}`);
      for (const path of previousIdentifiers(mutation)) {
        expect(() => canonicalizeCandidatesV3(kind, [withPath(path)])).toThrow(/carrier URL path/);
      }
    }
    for (const mutation of fixture.alpn_mutations) {
      const kind = mutation.id === "tunnel" ? "tunnel" : "direct";
      expect(mutation.v5).toBe(alpnForPathV3(kind));
      expect(mutation.v5).toBe(FLOWERSEC_V3_ALPN[kind]);
      expect(previousIdentifiers(mutation)).not.toContain(mutation.v5);
    }
    const cryptoLabels: Readonly<Record<string, string>> = {
      ...FLOWERSEC_V3_CRYPTO_LABELS,
    };
    expect(Object.keys(cryptoLabels).sort()).toEqual(
      fixture.crypto_label_mutations.map(({ id }) => id).sort(),
    );
    for (const mutation of fixture.crypto_label_mutations) {
      expect(cryptoLabels[mutation.id]).toBe(mutation.v5);
      expect(previousIdentifiers(mutation)).not.toContain(mutation.v5);
    }
  });

  test("WebSocket admission accepts v5 and rejects previous subprotocols", async () => {
    for (const mutation of fixture.subprotocol_mutations) {
      const kind = mutation.id === "websocket-tunnel" ? "tunnel" : "direct";
      expect(["websocket-direct", "websocket-tunnel"]).toContain(mutation.id);
      const vector = artifacts.positive.find(({ path_kind }) => path_kind === kind)!;
      const artifact = decodeArtifactV3JSON(vector.artifact_json);
      const candidate = canonicalizeCandidatesV3(artifact.path.kind, artifact.path.candidates).candidates
        .find(({ carrier }) => carrier === "websocket")!;
      const signal = new AbortController().signal;
      expect(FLOWERSEC_V3_WEBSOCKET_SUBPROTOCOLS[kind]).toBe(mutation.v5);
      const accepted = fakeSocket(1, mutation.v5);
      const ready = await readyWebSocketAdmissionV3(candidate, artifact, accepted, signal);
      expect(ready.candidate).toBe(candidate);
      await ready.close();
      expect(accepted.close).toHaveBeenCalledOnce();
      expect(accepted.readyState).toBe(3);
      for (const protocol of previousIdentifiers(mutation)) {
        const socket = fakeSocket(1, protocol);
        await expect(readyWebSocketAdmissionV3(candidate, artifact, socket, signal))
          .rejects.toMatchObject({ code: "connection_failed" });
        expect(socket.close).toHaveBeenCalledOnce();
      }
    }
  });

  test("raw QUIC adapter binds the candidate to the v5 ALPN profile", async () => {
    const calls: NativeRawQuicConnectOptions[] = [];
    const driver: NativeRawQuicDriver = {
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
      const before = calls.length;
      await createNodeRawQuicClientV3(driver, {
        ...base,
        wire_profile: mutation.v5,
      }, artifact, 1_900_000_000);
      expect(calls).toHaveLength(before + 1);
      for (const profile of previousIdentifiers(mutation)) {
        await expect(createNodeRawQuicClientV3(driver, {
          ...base,
          wire_profile: profile,
        }, artifact, 1_900_000_000)).rejects.toMatchObject({ code: "invalid_artifact" });
        expect(calls).toHaveLength(before + 1);
      }
    }
  });

  test("the v5 isolation corpus covers every frame family", () => {
    expect(fixture.version).toBe(5);
    expect(fixture.frames.map(({ id }) => id).sort())
      .toEqual(["fsa5", "fsb5", "fsc5", "fsd5", "fsh5", "fsr5", "fss5"]);
  });

  test.each(fixture.frames)("$id accepts v5 and rejects each previous marker independently", async (frame) => {
    const valid = fromHex(frame.v5_hex);
    const mutations = previousVersions.flatMap((version) => (["magic", "version"] as const).map((field) => {
      const mutated = fromHex(frame[`v${version}_${field}_hex`]);
      const expected = valid.slice();
      expected[field === "magic" ? 3 : 4] = field === "magic" ? 0x30 + version : version;
      expect(mutated).toEqual(expected);
      return mutated;
    }));
    if (frame.id === "fsd5") {
      const datagrams = JSON.parse(readFileSync(
        new URL("../../../testdata/transport_v5/datagram_vectors.json", import.meta.url), "utf8",
      )) as { vectors: DatagramVector[] };
      for (const vector of datagrams.vectors) {
        const wire = base64urlDecode(vector.wire_b64u);
        const epochSecret = base64urlDecode(vector.epoch_secret_b64u);
        expect(vector.header_hex).toBe(frame.v5_hex);
        expect(wire.subarray(0, valid.length)).toEqual(valid);
        const receiveHeader = (header: Uint8Array, onProtocolFailure: () => void) => {
          const datagram = wire.slice();
          datagram.set(header);
          const receive = vi.fn<() => Promise<Uint8Array>>().mockRejectedValue(new Error("no more datagrams"))
            .mockResolvedValueOnce(datagram);
          return createInternalUnreliableMessageChannelV3({
            transport: { maxDatagramSize: 1024, send: async () => "accepted", receive },
            suite: vector.suite,
            h3: base64urlDecode(vector.h3_b64u),
            sendDirection: vector.direction,
            receiveDirection: vector.direction,
            currentSendEpoch: () => ({ epoch: vector.epoch, epochSecret }),
            receiveEpochSecret: (epoch) => epoch === vector.epoch ? epochSecret : undefined,
            onProtocolFailure,
            now: () => 0,
          }).receive();
        };
        const onProtocolFailure = vi.fn();
        await expect(receiveHeader(valid, onProtocolFailure)).resolves.toEqual(base64urlDecode(vector.plaintext_b64u));
        expect(onProtocolFailure).not.toHaveBeenCalled();
        for (const mutated of mutations) {
          onProtocolFailure.mockClear();
          await expect(receiveHeader(mutated, onProtocolFailure)).rejects.toMatchObject({ code: "closed" });
          expect(onProtocolFailure).toHaveBeenCalledOnce();
        }
      }
      return;
    }
    function checkFrame<Decoded>(decode: (bytes: Uint8Array) => Decoded, checkValid: (value: Decoded) => void) {
      checkValid(decode(valid));
      for (const mutated of mutations) expect(() => decode(mutated)).toThrow();
    }
    switch (frame.id) {
      case "fsb5": return checkFrame(decodeFSB3RequestV3, ({ request }) => expect(request.profile).toBe(FLOWERSEC_V3_PROFILE));
      case "fsa5": return checkFrame(decodeFSA3ResponseV3, ({ reason }) => expect(reason).toBe("invalid_token"));
      case "fsc5": return checkFrame(parseControlPrefaceV3, (result) => expect(result).toBeUndefined());
      case "fsh5": return checkFrame(decodeHandshakeFrameV3, ({ type }) => expect(type).toBe(1));
      case "fss5": return checkFrame(decodeSetupPrefaceV3, ({ logicalStreamID }) => expect(logicalStreamID).toBe(1n));
      case "fsr5": return checkFrame(decodeRecordHeader, ({ epoch }) => expect(epoch).toBe(0));
      default: throw new Error(`unknown frame family: ${frame.id}`);
    }
  });

  test("FSH5, OPEN, and RPC codecs accept their shared application vectors", () => {
    const handshake = fixture.frames.find((frame) => frame.id === "fsh5")!;
    const handshakes = JSON.parse(readFileSync(
      new URL("../../../testdata/transport_v5/handshake_vectors.json", import.meta.url), "utf8",
    )) as { vectors: { id: string; client_init_hex: string }[] };
    const vector = handshakes.vectors.find(({ id }) => id === fixture.application_codecs.fsh5.frame_id)!;
    expect(handshake.v5_hex).toBe(vector.client_init_hex);
    const clientInit = decodeClientInitV3(fromHex(handshake.v5_hex));
    expect(clientInit.profile).toBe(FLOWERSEC_V3_PROFILE);

    const openFixture = JSON.parse(readFileSync(
      new URL("../../../testdata/transport_v5/open_unicode_vectors.json", import.meta.url), "utf8"),
    );
    const open = openFixture.positive.find((vector: { id: string }) =>
      vector.id === fixture.application_codecs.open.vector_id);
    expect(open).toBeDefined();
    const encoded = encodeOpenPayload({
      logicalStreamID: 1n,
      fss3Hash: new Uint8Array(32),
      kind: open.kind,
      metadata: new TextEncoder().encode(open.metadata_json),
    });
    const decoded = decodeOpenPayload(encoded);
    expect(decoded.kind).toBe(open.kind);
    expect(new TextDecoder().decode(decoded.metadata)).toBe(open.metadata_json);

    const rpc = assertRpcEnvelope(JSON.parse(fixture.application_codecs.rpc.envelope_json));
    expect((rpc.payload as { ratio: number }).ratio).toBe(1.5);
  });
});

function fakeSocket(readyState: number, protocol: string) {
  const events = new EventTarget();
  const socket = {
    binaryType: "",
    readyState,
    protocol,
    bufferedAmount: 0,
    send: vi.fn(),
    close: vi.fn(() => {
      socket.readyState = 2;
      queueMicrotask(() => {
        socket.readyState = 3;
        events.dispatchEvent(new Event("close"));
      });
    }),
    addEventListener: events.addEventListener.bind(events),
    removeEventListener: events.removeEventListener.bind(events),
  } satisfies WebSocketLikeV3;
  return socket;
}
