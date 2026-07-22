import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import { base64urlDecode } from "../utils/base64url.js";
import {
  computeClientConfirmV2,
  computeHandshakeH0V2,
  computeHandshakeH1V2,
  computeHandshakeH2V2,
  computeHandshakeH3V2,
  computeServerConfirmV2,
  computeSharedSecretV2,
  decodeClientFinishedV2,
  decodeClientInitV2,
  decodeServerFinishedV2,
  deriveHandshakePRKV2,
  deriveSessionPRKV2,
  encodeClientFinishedCoreV2,
  encodeControlPrefaceV2,
  encodeServerFinishedCoreV2,
  ephemeralPublicKeyV2,
  parseControlPrefaceV2,
} from "./handshake.js";
import type { CipherSuiteV2 } from "./protocol.js";

type HandshakeVector = Readonly<{
  id: string;
  suite: 1 | 2;
  client_private_hex: string;
  server_private_hex: string;
  client_public_b64u: string;
  server_public_b64u: string;
  psk_hex: string;
  shared_secret_hex: string;
  fsc2_hex: string;
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

const fixture = JSON.parse(
  readFileSync(new URL("../../../testdata/transport_v2/handshake_vectors.json", import.meta.url), "utf8"),
) as Readonly<{ version: number; profile: string; vectors: readonly HandshakeVector[] }>;

const fromHex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));
const hex = (value: Uint8Array): string => Buffer.from(value).toString("hex");

describe("transport v2 FSC2/FSH2 shared handshake vectors", () => {
  test("matches Go wire, transcript, confirms, and session keys for both suites", () => {
    expect(fixture.version).toBe(1);
    expect(fixture.profile).toBe("flowersec/2");
    expect(fixture.vectors.map((vector) => vector.suite)).toEqual([1, 2]);

    for (const vector of fixture.vectors) {
      const suite = vector.suite as CipherSuiteV2;
      const fsc2 = encodeControlPrefaceV2();
      expect(hex(fsc2)).toBe(vector.fsc2_hex);
      expect(() => parseControlPrefaceV2(fsc2)).not.toThrow();

      const clientPrivate = fromHex(vector.client_private_hex);
      const serverPrivate = fromHex(vector.server_private_hex);
      const clientPublic = base64urlDecode(vector.client_public_b64u);
      const serverPublic = base64urlDecode(vector.server_public_b64u);
      expect(hex(ephemeralPublicKeyV2(suite, clientPrivate))).toBe(hex(clientPublic));
      expect(hex(ephemeralPublicKeyV2(suite, serverPrivate))).toBe(hex(serverPublic));
      const clientShared = computeSharedSecretV2(suite, clientPrivate, serverPublic);
      const serverShared = computeSharedSecretV2(suite, serverPrivate, clientPublic);
      expect(hex(clientShared)).toBe(vector.shared_secret_hex);
      expect(serverShared).toEqual(clientShared);

      const clientInitRaw = fromHex(vector.client_init_hex);
      const serverFinishedRaw = fromHex(vector.server_finished_hex);
      const clientFinishedRaw = fromHex(vector.client_finished_hex);
      const clientInit = decodeClientInitV2(clientInitRaw);
      const serverFinished = decodeServerFinishedV2(serverFinishedRaw, suite);
      const clientFinished = decodeClientFinishedV2(clientFinishedRaw);
      expect(hex(encodeServerFinishedCoreV2(serverFinished.core, suite))).toBe(vector.server_core_hex);
      expect(hex(encodeClientFinishedCoreV2(clientFinished.handshakeID))).toBe(vector.client_core_hex);
      expect(clientInit.suite).toBe(suite);

      const handshakePRK = deriveHandshakePRKV2(fromHex(vector.psk_hex), clientShared);
      expect(hex(handshakePRK)).toBe(vector.handshake_prk_hex);
      const h0 = computeHandshakeH0V2(fsc2, clientInitRaw);
      const h1 = computeHandshakeH1V2(h0, fromHex(vector.server_core_hex));
      expect(hex(h0)).toBe(vector.h0_hex);
      expect(hex(h1)).toBe(vector.h1_hex);
      expect(hex(computeServerConfirmV2(handshakePRK, h1))).toBe(vector.server_confirm_hex);
      expect(serverFinished.serverConfirm).toEqual(computeServerConfirmV2(handshakePRK, h1));

      const h2 = computeHandshakeH2V2(h1, serverFinishedRaw, fromHex(vector.client_core_hex));
      expect(hex(h2)).toBe(vector.h2_hex);
      expect(hex(computeClientConfirmV2(handshakePRK, h2))).toBe(vector.client_confirm_hex);
      expect(clientFinished.clientConfirm).toEqual(computeClientConfirmV2(handshakePRK, h2));

      const h3 = computeHandshakeH3V2(h2, clientFinishedRaw);
      expect(hex(h3)).toBe(vector.h3_hex);
      expect(hex(deriveSessionPRKV2(h3, handshakePRK))).toBe(vector.session_prk_hex);
    }
  });

  test("rejects malformed control and non-canonical handshake frames", () => {
    const control = encodeControlPrefaceV2();
    for (const offset of [0, 4, 5, 15]) {
      const changed = control.slice();
      changed[offset] ^= 1;
      expect(() => parseControlPrefaceV2(changed)).toThrow();
    }

    const vector = fixture.vectors[0]!;
    const raw = fromHex(vector.client_init_hex);
    const text = new TextDecoder().decode(raw.subarray(12));
    const nonCanonicalPayload = new TextEncoder().encode(` ${text}`);
    const changed = new Uint8Array(12 + nonCanonicalPayload.length);
    changed.set(raw.subarray(0, 8));
    new DataView(changed.buffer).setUint32(8, nonCanonicalPayload.length, false);
    changed.set(nonCanonicalPayload, 12);
    expect(() => decodeClientInitV2(changed)).toThrow();
  });
});
