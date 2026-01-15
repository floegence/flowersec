import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, test } from "vitest";

import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
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
});

