import { describe, expect, test } from "vitest";
import { x25519 } from "@noble/curves/ed25519";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { HANDSHAKE_TYPE_ACK, HANDSHAKE_TYPE_INIT, HANDSHAKE_TYPE_RESP, PROTOCOL_VERSION } from "./constants.js";
import { decodeHandshakeFrame, encodeHandshakeFrame } from "./framing.js";
import { computeAuthTag } from "./kdf.js";
import { transcriptHash } from "./transcript.js";
import { ServerHandshakeCache, serverHandshake, type HandshakeServerOptions } from "./handshake.js";

function u8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

type BinaryTransport = {
  readBinary(): Promise<Uint8Array>;
  writeBinary(frame: Uint8Array): Promise<void>;
  close(): void;
};

describe("e2ee serverHandshake", () => {
  test("replies to init retry using cached response", async () => {
    const channelId = "ch_1";
    const suite = 1 as const;
    const psk = crypto.getRandomValues(new Uint8Array(32));

    const clientPriv = x25519.utils.randomPrivateKey();
    const clientPub = x25519.getPublicKey(clientPriv);
    const nonceC = crypto.getRandomValues(new Uint8Array(32));
    const clientFeatures = 123;

    const init = {
      channel_id: channelId,
      role: 1,
      version: PROTOCOL_VERSION,
      suite,
      client_eph_pub_b64u: base64urlEncode(clientPub),
      nonce_c_b64u: base64urlEncode(nonceC),
      client_features: clientFeatures >>> 0
    } as const;
    const initFrame = encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, u8(JSON.stringify(init)));

    // Same semantic init, but with a different JSON key order to ensure canonical fingerprinting.
    const initRetryJson = JSON.stringify({
      role: init.role,
      version: init.version,
      channel_id: init.channel_id,
      suite: init.suite,
      client_features: init.client_features,
      nonce_c_b64u: init.nonce_c_b64u,
      client_eph_pub_b64u: init.client_eph_pub_b64u
    });
    const initRetryFrame = encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, u8(initRetryJson));

    let state = 0;
    let respCount = 0;
    let ackFrame: Uint8Array | null = null;
    let lastResp: any = null;

    const transport: BinaryTransport = {
      async readBinary() {
        if (state === 0) {
          state++;
          return initFrame;
        }
        if (state === 1) {
          state++;
          return initRetryFrame;
        }
        if (state === 2) {
          if (ackFrame == null) throw new Error("missing ack frame");
          state++;
          return ackFrame;
        }
        throw new Error("unexpected read");
      },
      async writeBinary(frame: Uint8Array) {
        const decoded = decodeHandshakeFrame(frame, 8 * 1024);
        if (decoded.handshakeType !== HANDSHAKE_TYPE_RESP) return;
        respCount++;
        if (lastResp == null) {
          lastResp = JSON.parse(new TextDecoder().decode(decoded.payloadJsonUtf8));
          const serverPubBytes = base64urlDecode(lastResp.server_eph_pub_b64u);
          const nonceSBytes = base64urlDecode(lastResp.nonce_s_b64u);
          const th = transcriptHash({
            version: PROTOCOL_VERSION,
            suite,
            role: 1,
            clientFeatures,
            serverFeatures: lastResp.server_features >>> 0,
            channelId,
            nonceC,
            nonceS: nonceSBytes,
            clientEphPub: clientPub,
            serverEphPub: serverPubBytes
          });
          const ts = Math.floor(Date.now() / 1000);
          const tag = computeAuthTag(psk, th, BigInt(ts));
          const ack = {
            handshake_id: lastResp.handshake_id,
            timestamp_unix_s: ts,
            auth_tag_b64u: base64urlEncode(tag)
          };
          ackFrame = encodeHandshakeFrame(HANDSHAKE_TYPE_ACK, u8(JSON.stringify(ack)));
        }
      },
      close() {}
    };

    const cache = new ServerHandshakeCache();
    const opts: HandshakeServerOptions = {
      channelId,
      suite,
      psk,
      serverFeatures: 0,
      initExpireAtUnixS: Math.floor(Date.now() / 1000) + 120,
      clockSkewSeconds: 30,
      maxHandshakePayload: 8 * 1024,
      maxRecordBytes: 1 << 20
    };

    await serverHandshake(transport, cache, opts);
    expect(respCount).toBe(2);
  });
});
