import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { p256 } from "@noble/curves/p256";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { deriveSessionKeys } from "./kdf.js";
import { encryptRecord } from "./record.js";
import { transcriptHash } from "./transcript.js";

type Vectors = {
  transcript_hash: Array<{
    case_id: string;
    inputs: {
      version: number;
      suite: number;
      role: number;
      client_features: number;
      server_features: number;
      channel_id: string;
      nonce_c_b64u: string;
      nonce_s_b64u: string;
      client_eph_pub_b64u: string;
      server_eph_pub_b64u: string;
    };
    expected: { transcript_hash_b64u: string };
  }>;
  record_frame: Array<{
    case_id: string;
    inputs: {
      key_b64u: string;
      nonce_prefix_b64u: string;
      flags: number;
      seq: number;
      plaintext_utf8: string;
      max_record_bytes: number;
    };
    expected: { frame_b64u: string };
  }>;
  handshake_p256: Array<{
    case_id: string;
    inputs: {
      version: number;
      suite: number;
      role: number;
      client_features: number;
      server_features: number;
      channel_id: string;
      nonce_c_b64u: string;
      nonce_s_b64u: string;
      client_eph_priv_b64u: string;
      server_eph_priv_b64u: string;
      client_eph_pub_b64u: string;
      server_eph_pub_b64u: string;
      psk_b64u: string;
    };
    expected: {
      shared_secret_b64u: string;
      transcript_hash_b64u: string;
      c2s_key_b64u: string;
      s2c_key_b64u: string;
      c2s_nonce_prefix_b64u: string;
      s2c_nonce_prefix_b64u: string;
      rekey_base_b64u: string;
    };
  }>;
};

async function loadVectors(): Promise<Vectors> {
  const p = path.join(process.cwd(), "..", "idl", "flowersec", "testdata", "v1", "e2ee_vectors.json");
  const b = await readFile(p, "utf8");
  return JSON.parse(b) as Vectors;
}

describe("e2ee test vectors", () => {
  test("transcript_hash", async () => {
    const v = await loadVectors();
    for (const tc of v.transcript_hash) {
      const nonceC = base64urlDecode(tc.inputs.nonce_c_b64u);
      const nonceS = base64urlDecode(tc.inputs.nonce_s_b64u);
      const clientPub = base64urlDecode(tc.inputs.client_eph_pub_b64u);
      const serverPub = base64urlDecode(tc.inputs.server_eph_pub_b64u);
      const h = transcriptHash({
        version: tc.inputs.version,
        suite: tc.inputs.suite,
        role: tc.inputs.role,
        clientFeatures: tc.inputs.client_features,
        serverFeatures: tc.inputs.server_features,
        channelId: tc.inputs.channel_id,
        nonceC,
        nonceS,
        clientEphPub: clientPub,
        serverEphPub: serverPub
      });
      expect(base64urlEncode(h)).toBe(tc.expected.transcript_hash_b64u);
    }
  });

  test("record_frame", async () => {
    const v = await loadVectors();
    for (const tc of v.record_frame) {
      const key = base64urlDecode(tc.inputs.key_b64u);
      const noncePrefix = base64urlDecode(tc.inputs.nonce_prefix_b64u);
      const frame = encryptRecord(
        key,
        noncePrefix,
        tc.inputs.flags as 0 | 1 | 2,
        BigInt(tc.inputs.seq),
        new TextEncoder().encode(tc.inputs.plaintext_utf8),
        tc.inputs.max_record_bytes
      );
      expect(base64urlEncode(frame)).toBe(tc.expected.frame_b64u);
    }
  });

  test("handshake_p256", async () => {
    const v = await loadVectors();
    for (const tc of v.handshake_p256) {
      const nonceC = base64urlDecode(tc.inputs.nonce_c_b64u);
      const nonceS = base64urlDecode(tc.inputs.nonce_s_b64u);
      const clientPriv = base64urlDecode(tc.inputs.client_eph_priv_b64u);
      const serverPriv = base64urlDecode(tc.inputs.server_eph_priv_b64u);
      const clientPub = base64urlDecode(tc.inputs.client_eph_pub_b64u);
      const serverPub = base64urlDecode(tc.inputs.server_eph_pub_b64u);
      const psk = base64urlDecode(tc.inputs.psk_b64u);

      expect(base64urlEncode(p256.getPublicKey(clientPriv, false))).toBe(tc.inputs.client_eph_pub_b64u);
      expect(base64urlEncode(p256.getPublicKey(serverPriv, false))).toBe(tc.inputs.server_eph_pub_b64u);

      // P-256 shared secret uses the x-coordinate to align with crypto/ecdh.
      const shared = p256.getSharedSecret(clientPriv, serverPub, false);
      if (shared.length !== 65 || shared[0] !== 4) throw new Error("invalid P-256 shared secret encoding");
      const sharedX = shared.slice(1, 33);
      expect(base64urlEncode(sharedX)).toBe(tc.expected.shared_secret_b64u);

      const th = transcriptHash({
        version: tc.inputs.version,
        suite: tc.inputs.suite,
        role: tc.inputs.role,
        clientFeatures: tc.inputs.client_features,
        serverFeatures: tc.inputs.server_features,
        channelId: tc.inputs.channel_id,
        nonceC,
        nonceS,
        clientEphPub: clientPub,
        serverEphPub: serverPub
      });
      expect(base64urlEncode(th)).toBe(tc.expected.transcript_hash_b64u);

      const keys = deriveSessionKeys(psk, sharedX, th);
      expect(base64urlEncode(keys.c2sKey)).toBe(tc.expected.c2s_key_b64u);
      expect(base64urlEncode(keys.s2cKey)).toBe(tc.expected.s2c_key_b64u);
      expect(base64urlEncode(keys.c2sNoncePrefix)).toBe(tc.expected.c2s_nonce_prefix_b64u);
      expect(base64urlEncode(keys.s2cNoncePrefix)).toBe(tc.expected.s2c_nonce_prefix_b64u);
      expect(base64urlEncode(keys.rekeyBase)).toBe(tc.expected.rekey_base_b64u);
    }
  });
});
