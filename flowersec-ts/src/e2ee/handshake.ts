import { x25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import type { E2EE_Ack, E2EE_Init, E2EE_Resp } from "../gen/flowersec/e2ee/v1.gen.js";
import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { HANDSHAKE_TYPE_ACK, HANDSHAKE_TYPE_INIT, HANDSHAKE_TYPE_RESP, PROTOCOL_VERSION, RECORD_FLAG_PING } from "./constants.js";
import { encodeHandshakeFrame, decodeHandshakeFrame } from "./framing.js";
import { computeAuthTag, deriveSessionKeys } from "./kdf.js";
import { transcriptHash } from "./transcript.js";
import { decryptRecord, encryptRecord } from "./record.js";
import { SecureChannel, type BinaryTransport } from "./secureChannel.js";
import { E2EEHandshakeError } from "./errors.js";
import { TimeoutError, throwIfAborted } from "../utils/errors.js";

// Suite identifies the ECDH+AEAD combination.
export type Suite = 1 | 2;

// HandshakeClientOptions configures the client handshake path.
export type HandshakeClientOptions = Readonly<{
  /** Channel identifier shared with the server. */
  channelId: string;
  /** Cipher suite selection (see Suite). */
  suite: Suite;
  /** 32-byte pre-shared key for authenticating the handshake. */
  psk: Uint8Array; // 32
  /** Client feature bitset advertised during handshake. */
  clientFeatures: number;
  /** Maximum allowed bytes for a handshake JSON payload. */
  maxHandshakePayload: number;
  /** Maximum record size for encrypted frames after handshake. */
  maxRecordBytes: number;
  /** Maximum buffered plaintext bytes for the secure channel. */
  maxBufferedBytes?: number;
  /** Optional AbortSignal to cancel the handshake. */
  signal?: AbortSignal;
  /** Optional total handshake timeout in milliseconds (0 disables). */
  timeoutMs?: number;
}>;

// HandshakeServerOptions configures the server handshake path.
export type HandshakeServerOptions = Readonly<{
  /** Channel identifier expected from the client. */
  channelId: string;
  /** Cipher suite selection (see Suite). */
  suite: Suite;
  /** 32-byte pre-shared key for authenticating the handshake. */
  psk: Uint8Array; // 32
  /** Server feature bitset advertised during handshake. */
  serverFeatures: number;
  /** Absolute expiry (Unix seconds) for the init message. */
  initExpireAtUnixS: number;
  /** Allowed clock skew (seconds) for timestamp validation. */
  clockSkewSeconds: number;
  /** Maximum allowed bytes for a handshake JSON payload. */
  maxHandshakePayload: number;
  /** Maximum record size for encrypted frames after handshake. */
  maxRecordBytes: number;
  /** Maximum buffered plaintext bytes for the secure channel. */
  maxBufferedBytes?: number;
  /** Optional AbortSignal to cancel the handshake. */
  signal?: AbortSignal;
  /** Optional total handshake timeout in milliseconds (0 disables). */
  timeoutMs?: number;
}>;

const te = new TextEncoder();
const td = new TextDecoder();

function handshakeDeadlineMs(timeoutMs: number | undefined): number | null {
  const ms = Math.max(0, timeoutMs ?? 10_000);
  if (ms <= 0) return null;
  return Date.now() + ms;
}

function ioReadOpts(signal: AbortSignal | undefined, deadlineMs: number | null): { signal?: AbortSignal; timeoutMs?: number } {
  throwIfAborted(signal, "handshake aborted");
  if (deadlineMs == null) return signal != null ? { signal } : {};
  const remaining = deadlineMs - Date.now();
  if (remaining <= 0) throw new TimeoutError("handshake timeout");
  return signal != null ? { signal, timeoutMs: remaining } : { timeoutMs: remaining };
}

function ioWriteOpts(signal: AbortSignal | undefined): { signal?: AbortSignal } {
  throwIfAborted(signal, "handshake aborted");
  return signal != null ? { signal } : {};
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

// suiteKeypair generates a per-handshake ECDH keypair.
function suiteKeypair(suite: Suite): { priv: Uint8Array; pub: Uint8Array } {
  if (suite === 1) {
    const priv = x25519.utils.randomPrivateKey();
    const pub = x25519.getPublicKey(priv);
    return { priv, pub };
  }
  if (suite === 2) {
    const priv = p256.utils.randomPrivateKey();
    const pub = p256.getPublicKey(priv, false);
    return { priv, pub };
  }
  throw new Error(`unsupported suite ${suite}`);
}

// suiteSharedSecret computes the ECDH shared secret for the suite.
function suiteSharedSecret(suite: Suite, priv: Uint8Array, peerPub: Uint8Array): Uint8Array {
  if (suite === 1) return x25519.getSharedSecret(priv, peerPub);
  if (suite === 2) {
    // P-256 uses the x-coordinate (32 bytes) to align with Go's crypto/ecdh output.
    const shared = p256.getSharedSecret(priv, peerPub, false);
    if (shared.length !== 65 || shared[0] !== 4) throw new Error("invalid P-256 shared secret encoding");
    return shared.slice(1, 33);
  }
  throw new Error(`unsupported suite ${suite}`);
}

function fingerprintInit(init: E2EE_Init): string {
  // Canonicalize to avoid JSON key-order affecting the cache key.
  const canonical = {
    channel_id: init.channel_id,
    role: init.role,
    version: init.version,
    suite: init.suite,
    client_eph_pub_b64u: init.client_eph_pub_b64u,
    nonce_c_b64u: init.nonce_c_b64u,
    client_features: init.client_features
  } satisfies E2EE_Init;
  const b = te.encode(JSON.stringify(canonical));
  const sum = sha256(b);
  // Full 32-byte fingerprint (aligns with Go's sha256-based fingerprinting).
  return base64urlEncode(sum);
}

// clientHandshake performs the client side of the E2EE handshake.
export async function clientHandshake(transport: BinaryTransport, opts: HandshakeClientOptions): Promise<SecureChannel> {
  if (opts.psk.length !== 32) throw new Error("psk must be 32 bytes");
  if (opts.channelId === "") throw new Error("missing channel_id");
  const deadlineMs = handshakeDeadlineMs(opts.timeoutMs);
  const kp = suiteKeypair(opts.suite);
  const nonceC = randomBytes(32);
  const init: E2EE_Init = {
    channel_id: opts.channelId,
    role: 1,
    version: PROTOCOL_VERSION,
    suite: opts.suite,
    client_eph_pub_b64u: base64urlEncode(kp.pub),
    nonce_c_b64u: base64urlEncode(nonceC),
    client_features: opts.clientFeatures >>> 0
  };
  const initJson = te.encode(JSON.stringify(init));
  await transport.writeBinary(encodeHandshakeFrame(HANDSHAKE_TYPE_INIT, initJson), ioWriteOpts(opts.signal));

  // Read server response with ephemeral key and nonce.
  const respFrame = await transport.readBinary(ioReadOpts(opts.signal, deadlineMs));
  const decoded = decodeHandshakeFrame(respFrame, opts.maxHandshakePayload);
  if (decoded.handshakeType !== HANDSHAKE_TYPE_RESP) throw new Error("unexpected handshake type");
  const resp = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Resp;
  if (resp.handshake_id == null || resp.handshake_id === "") throw new Error("missing handshake_id");
  if (resp.server_eph_pub_b64u == null || resp.server_eph_pub_b64u === "") throw new Error("missing server_eph_pub_b64u");
  if (resp.nonce_s_b64u == null || resp.nonce_s_b64u === "") throw new Error("missing nonce_s_b64u");
  const serverPub = base64urlDecode(resp.server_eph_pub_b64u);
  const nonceS = base64urlDecode(resp.nonce_s_b64u);
  if (nonceS.length !== 32) throw new Error("bad nonce_s length");
  if (opts.suite === 1 && serverPub.length !== 32) throw new Error("bad server eph pub length");
  if (opts.suite === 2 && serverPub.length !== 65) throw new Error("bad server eph pub length");

  const th = transcriptHash({
    version: PROTOCOL_VERSION,
    suite: opts.suite,
    role: 1,
    clientFeatures: init.client_features,
    serverFeatures: resp.server_features >>> 0,
    channelId: opts.channelId,
    nonceC,
    nonceS,
    clientEphPub: kp.pub,
    serverEphPub: serverPub
  });
  const shared = suiteSharedSecret(opts.suite, kp.priv, serverPub);
  const keys = deriveSessionKeys(opts.psk, shared, th);

  const ts = BigInt(Math.floor(Date.now() / 1000));
  const tag = computeAuthTag(opts.psk, th, ts);
  const ack: E2EE_Ack = {
    handshake_id: resp.handshake_id,
    timestamp_unix_s: Number(ts),
    auth_tag_b64u: base64urlEncode(tag)
  };
  await transport.writeBinary(
    encodeHandshakeFrame(HANDSHAKE_TYPE_ACK, te.encode(JSON.stringify(ack))),
    ioWriteOpts(opts.signal)
  );

  // Server-finished confirmation: require an encrypted ping record (seq=1) before returning.
  const finishedFrame = await transport.readBinary(ioReadOpts(opts.signal, deadlineMs));
  const finished = decryptRecord(keys.s2cKey, keys.s2cNoncePrefix, finishedFrame, 1n, opts.maxRecordBytes);
  if (finished.flags !== RECORD_FLAG_PING || finished.plaintext.length !== 0) {
    throw new Error("expected server-finished ping");
  }

  // Client sends application data with the C2S keys.
  return new SecureChannel({
    transport,
    maxRecordBytes: opts.maxRecordBytes,
    ...(opts.maxBufferedBytes !== undefined ? { maxBufferedBytes: opts.maxBufferedBytes } : {}),
    sendKey: keys.c2sKey,
    recvKey: keys.s2cKey,
    sendNoncePrefix: keys.c2sNoncePrefix,
    recvNoncePrefix: keys.s2cNoncePrefix,
    rekeyBase: keys.rekeyBase,
    transcriptHash: th,
    sendDir: 1,
    recvDir: 2,
    recvSeq: 2n
  });
}

type ServerCacheEntry = {
  /** Stable fingerprint of the init message for retries. */
  initKey: string;
  /** Suite used for this cached handshake. */
  suite: Suite;
  /** Server ephemeral private key for ECDH. */
  serverPriv: Uint8Array;
  /** Server ephemeral public key bytes. */
  serverPub: Uint8Array;
  /** Server nonce (32 bytes). */
  nonceS: Uint8Array;
  /** Handshake identifier returned to the client. */
  handshakeId: string;
  /** Server feature bitset from this handshake. */
  serverFeatures: number;
  /** Cache insert time (ms since epoch) for TTL eviction. */
  createdAtMs: number;
};

// ServerHandshakeCache stores server-side handshake state for retries.
export class ServerHandshakeCache {
  // Cache keyed by init fingerprint.
  private readonly m = new Map<string, ServerCacheEntry>();
  // Time-to-live for cache entries in milliseconds.
  private readonly ttlMs: number;
  // Maximum number of cached entries.
  private readonly maxEntries: number;

  constructor(opts: Readonly<{ ttlMs?: number; maxEntries?: number }> = {}) {
    this.ttlMs = Math.max(0, opts.ttlMs ?? 60_000);
    this.maxEntries = Math.max(0, opts.maxEntries ?? 4096);
  }

  private cleanup(nowMs: number): void {
    if (this.ttlMs <= 0) return;
    for (const [k, v] of this.m) {
      if (nowMs - v.createdAtMs > this.ttlMs) this.m.delete(k);
    }
  }

  // getOrCreate returns a cached entry or creates a new handshake response.
  getOrCreate(init: E2EE_Init, suite: Suite, serverFeatures: number): ServerCacheEntry {
    const nowMs = Date.now();
    const initKey = fingerprintInit(init);
    this.cleanup(nowMs);
    const existing = this.m.get(initKey);
    if (existing != null) return existing;
    if (this.maxEntries > 0 && this.m.size >= this.maxEntries) {
      throw new Error("too many pending handshakes");
    }
    const kp = suiteKeypair(suite);
    const nonceS = randomBytes(32);
    const entry: ServerCacheEntry = {
      initKey,
      suite,
      serverPriv: kp.priv,
      serverPub: kp.pub,
      nonceS,
      handshakeId: base64urlEncode(randomBytes(24)),
      serverFeatures: serverFeatures >>> 0,
      createdAtMs: nowMs
    };
    this.m.set(initKey, entry);
    return entry;
  }

  // delete removes a cached handshake entry.
  delete(init: E2EE_Init): void {
    const initKey = fingerprintInit(init);
    this.m.delete(initKey);
  }
}

// serverHandshake performs the server side of the E2EE handshake.
export async function serverHandshake(
  transport: BinaryTransport,
  cache: ServerHandshakeCache,
  opts: HandshakeServerOptions
): Promise<SecureChannel> {
  if (opts.initExpireAtUnixS <= 0) throw new Error("missing init_exp");
  const deadlineMs = handshakeDeadlineMs(opts.timeoutMs);
  const initFrame = await transport.readBinary(ioReadOpts(opts.signal, deadlineMs));
  const decodedInit = decodeHandshakeFrame(initFrame, opts.maxHandshakePayload);
  if (decodedInit.handshakeType !== HANDSHAKE_TYPE_INIT) throw new Error("unexpected handshake type");
  const init = JSON.parse(td.decode(decodedInit.payloadJsonUtf8)) as E2EE_Init;
  if (init.version !== PROTOCOL_VERSION) throw new E2EEHandshakeError("invalid_version", "bad version");
  if (init.role !== 1) throw new Error("bad role");
  if (init.channel_id !== opts.channelId) throw new Error("bad channel_id");
  const suite = init.suite as Suite;
  if (suite !== opts.suite) throw new Error("bad suite");

  const clientPub = base64urlDecode(init.client_eph_pub_b64u);
  const nonceC = base64urlDecode(init.nonce_c_b64u);
  if (nonceC.length !== 32) throw new Error("bad nonce_c length");
  if (suite === 1 && clientPub.length !== 32) throw new Error("bad client eph pub length");
  if (suite === 2 && clientPub.length !== 65) throw new Error("bad client eph pub length");

  const entry = cache.getOrCreate(init, suite, opts.serverFeatures);
  const resp: E2EE_Resp = {
    handshake_id: entry.handshakeId,
    server_eph_pub_b64u: base64urlEncode(entry.serverPub),
    nonce_s_b64u: base64urlEncode(entry.nonceS),
    server_features: entry.serverFeatures
  };
  await transport.writeBinary(encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, te.encode(JSON.stringify(resp))), ioWriteOpts(opts.signal));

  let ack: E2EE_Ack;
  while (true) {
    const frame = await transport.readBinary(ioReadOpts(opts.signal, deadlineMs));
    const decoded = decodeHandshakeFrame(frame, opts.maxHandshakePayload);
    if (decoded.handshakeType === HANDSHAKE_TYPE_INIT) {
      // Client retry: re-send the cached response if parameters match.
      const retry = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Init;
      if (fingerprintInit(retry) !== entry.initKey) throw new Error("unexpected init retry parameters");
      await transport.writeBinary(
        encodeHandshakeFrame(HANDSHAKE_TYPE_RESP, te.encode(JSON.stringify(resp))),
        ioWriteOpts(opts.signal)
      );
      continue;
    }
    if (decoded.handshakeType !== HANDSHAKE_TYPE_ACK) throw new Error("unexpected handshake type");
    ack = JSON.parse(td.decode(decoded.payloadJsonUtf8)) as E2EE_Ack;
    break;
  }
  if (ack.handshake_id !== entry.handshakeId) throw new Error("handshake_id mismatch");

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ack.timestamp_unix_s) > opts.clockSkewSeconds) throw new E2EEHandshakeError("timestamp_out_of_skew", "timestamp skew");
  if (ack.timestamp_unix_s > opts.initExpireAtUnixS + opts.clockSkewSeconds) throw new E2EEHandshakeError("timestamp_after_init_exp", "timestamp after init_exp");

  const th = transcriptHash({
    version: PROTOCOL_VERSION,
    suite: suite,
    role: 1,
    clientFeatures: init.client_features >>> 0,
    serverFeatures: entry.serverFeatures,
    channelId: init.channel_id,
    nonceC,
    nonceS: entry.nonceS,
    clientEphPub: clientPub,
    serverEphPub: entry.serverPub
  });

  const expected = computeAuthTag(opts.psk, th, BigInt(ack.timestamp_unix_s));
  const got = base64urlDecode(ack.auth_tag_b64u);
  if (got.length !== expected.length || !equalBytes(got, expected)) throw new E2EEHandshakeError("auth_tag_mismatch", "auth tag mismatch");

  const shared = suiteSharedSecret(suite, entry.serverPriv, clientPub);
  const keys = deriveSessionKeys(opts.psk, shared, th);
  cache.delete(init);

  // Server-finished confirmation: send an encrypted ping record (seq=1) immediately after the handshake.
  const pingFrame = encryptRecord(keys.s2cKey, keys.s2cNoncePrefix, RECORD_FLAG_PING, 1n, new Uint8Array(), opts.maxRecordBytes);
  await transport.writeBinary(pingFrame, ioWriteOpts(opts.signal));

  // Server sends application data with the S2C keys.
  return new SecureChannel({
    transport,
    maxRecordBytes: opts.maxRecordBytes,
    ...(opts.maxBufferedBytes !== undefined ? { maxBufferedBytes: opts.maxBufferedBytes } : {}),
    sendKey: keys.s2cKey,
    recvKey: keys.c2sKey,
    sendNoncePrefix: keys.s2cNoncePrefix,
    recvNoncePrefix: keys.c2sNoncePrefix,
    rekeyBase: keys.rekeyBase,
    transcriptHash: th,
    sendDir: 2,
    recvDir: 1,
    sendSeq: 2n
  });
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let ok = 0;
  for (let i = 0; i < a.length; i++) ok |= a[i]! ^ b[i]!;
  return ok === 0;
}
