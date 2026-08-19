import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import {
  computeClientConfirmV3,
  computeHandshakeH0V3,
  computeHandshakeH1V3,
  computeHandshakeH2V3,
  computeHandshakeH3V3,
  computeServerConfirmV3,
  computeSharedSecretV3,
  decodeClientFinishedV3,
  decodeClientInitV3,
  decodeServerFinishedV3,
  deriveHandshakePRKV3,
  deriveSessionPRKV3,
  encodeClientFinishedCoreV3,
  encodeControlPrefaceV3,
  encodeServerFinishedCoreV3,
  ephemeralPublicKeyV3,
  parseControlPrefaceV3,
} from "./handshake.js";
import { ProtocolV3Error, type CipherSuiteV3 } from "./protocol.js";

type HandshakeVector = Readonly<{
  suite: 1 | 2;
  client_private_hex: string;
  server_private_hex: string;
  client_public_b64u: string;
  server_public_b64u: string;
  psk_hex: string;
  shared_secret_hex: string;
  fsc3_hex: string;
  client_init_hex: string;
  server_core_hex: string;
  server_finished_hex: string;
  client_core_hex: string;
  client_finished_hex: string;
  h0_hex: string;
  h1_hex: string;
  h2_hex: string;
  h3_hex: string;
  handshake_prk_hex: string;
  session_prk_hex: string;
  server_confirm_hex: string;
  client_confirm_hex: string;
}>;

const fixture = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v3/handshake_vectors.json", import.meta.url),
  "utf8",
)) as Readonly<{ profile: string; vectors: readonly HandshakeVector[] }>;
const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("transport v3 FSC3 and FSH3 handshake", () => {
  test("matches both shared suite transcripts and session keys", () => {
    expect(fixture.profile).toBe("flowersec/3");
    expect(fixture.vectors.map(({ suite }) => suite)).toEqual([1, 2]);
    for (const vector of fixture.vectors) {
      const suite = vector.suite as CipherSuiteV3;
      const fsc3 = encodeControlPrefaceV3();
      expect(hex(fsc3)).toBe(vector.fsc3_hex);
      parseControlPrefaceV3(fsc3);
      const clientPrivate = fromHex(vector.client_private_hex);
      const serverPrivate = fromHex(vector.server_private_hex);
      const clientPublic = base64urlDecode(vector.client_public_b64u);
      const serverPublic = base64urlDecode(vector.server_public_b64u);
      expect(ephemeralPublicKeyV3(suite, clientPrivate)).toEqual(clientPublic);
      expect(ephemeralPublicKeyV3(suite, serverPrivate)).toEqual(serverPublic);
      const shared = computeSharedSecretV3(suite, clientPrivate, serverPublic);
      expect(hex(shared)).toBe(vector.shared_secret_hex);
      expect(computeSharedSecretV3(suite, serverPrivate, clientPublic)).toEqual(shared);

      const clientInitRaw = fromHex(vector.client_init_hex);
      const serverFinishedRaw = fromHex(vector.server_finished_hex);
      const clientFinishedRaw = fromHex(vector.client_finished_hex);
      const clientInit = decodeClientInitV3(clientInitRaw);
      const serverFinished = decodeServerFinishedV3(serverFinishedRaw, suite);
      const clientFinished = decodeClientFinishedV3(clientFinishedRaw);
      expect(clientInit.profile).toBe("flowersec/3");
      expect(hex(encodeServerFinishedCoreV3(serverFinished.core, suite))).toBe(vector.server_core_hex);
      expect(hex(encodeClientFinishedCoreV3(clientFinished.handshakeID))).toBe(vector.client_core_hex);

      const handshakePRK = deriveHandshakePRKV3(fromHex(vector.psk_hex), shared);
      const h0 = computeHandshakeH0V3(fsc3, clientInitRaw);
      const h1 = computeHandshakeH1V3(h0, fromHex(vector.server_core_hex));
      const h2 = computeHandshakeH2V3(h1, serverFinishedRaw, fromHex(vector.client_core_hex));
      const h3 = computeHandshakeH3V3(h2, clientFinishedRaw);
      expect(hex(handshakePRK)).toBe(vector.handshake_prk_hex);
      expect(hex(h0)).toBe(vector.h0_hex);
      expect(hex(h1)).toBe(vector.h1_hex);
      expect(hex(h2)).toBe(vector.h2_hex);
      expect(hex(h3)).toBe(vector.h3_hex);
      expect(hex(computeServerConfirmV3(handshakePRK, h1))).toBe(vector.server_confirm_hex);
      expect(hex(computeClientConfirmV3(handshakePRK, h2))).toBe(vector.client_confirm_hex);
      expect(hex(deriveSessionPRKV3(h3, handshakePRK))).toBe(vector.session_prk_hex);
    }
  });

  test("rejects v2 control and handshake frame families", () => {
    const control = encodeControlPrefaceV3();
    control[3] = 0x32;
    control[4] = 2;
    expect(() => parseControlPrefaceV3(control)).toThrowError(ProtocolV3Error);
    const frame = fromHex(fixture.vectors[0]!.client_init_hex);
    frame[3] = 0x32;
    frame[4] = 2;
    expect(() => decodeClientInitV3(frame)).toThrowError(ProtocolV3Error);
  });
});
