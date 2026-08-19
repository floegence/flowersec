import { x25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { expand, extract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64urlDecode, base64urlEncode } from "../utils/base64url.js";
import { concatBytes, readU32be, u32be } from "../utils/bin.js";
import { CipherSuiteV3, ProtocolV3Error } from "./protocol.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const CONTROL_PREFACE_BYTES = 16;
const HANDSHAKE_HEADER_BYTES = 12;
const MAX_HANDSHAKE_PAYLOAD_BYTES = 8_192;
const registryIDPattern = /^[A-Za-z0-9._~-]+$/;
const KNOWN_FEATURES_V3 = 0x00000001;

export enum HandshakeMessageTypeV3 {
  ClientInit = 1,
  ServerFinished = 2,
  ClientFinished = 3,
}

export type HandshakeFrameV3 = Readonly<{
  type: HandshakeMessageTypeV3;
  payload: Uint8Array;
  raw: Uint8Array;
}>;

export type ClientInitV3 = Readonly<{
  profile: "flowersec/3";
  channelID: string;
  sessionContractHash: Uint8Array;
  clientRole: 1;
  suite: CipherSuiteV3;
  clientEphemeralPublic: Uint8Array;
  nonceC: Uint8Array;
  selectedFeatures: number;
  maxInboundStreams: number;
  clientAdmissionBinding: Uint8Array;
  clientEndpointInstanceID: string;
}>;

export type ServerFinishedCoreV3 = Readonly<{
  suite: CipherSuiteV3;
  handshakeID: Uint8Array;
  serverEphemeralPublic: Uint8Array;
  nonceS: Uint8Array;
  sessionContractHash: Uint8Array;
  selectedFeatures: number;
  maxInboundStreams: number;
  serverAdmissionBinding: Uint8Array;
  serverEndpointInstanceID: string;
}>;

export type ServerFinishedV3 = Readonly<{
  core: ServerFinishedCoreV3;
  serverConfirm: Uint8Array;
}>;

export type ClientFinishedV3 = Readonly<{
  handshakeID: Uint8Array;
  clientConfirm: Uint8Array;
}>;

export type HandshakeExpectationsV3 = Readonly<{
  path: "direct" | "tunnel";
  channelID: string;
  sessionContractHash: Uint8Array;
  suite: CipherSuiteV3;
  maxInboundStreams: number;
  admissionBinding: Uint8Array;
  expectedEndpointInstanceID: string;
}>;

export function encodeControlPrefaceV3(): Uint8Array {
  const out = new Uint8Array(CONTROL_PREFACE_BYTES);
  out.set(encoder.encode("FSC3"));
  out[4] = 3;
  out[5] = 1;
  return out;
}

export function parseControlPrefaceV3(raw: Uint8Array): void {
  if (
    raw.length !== CONTROL_PREFACE_BYTES ||
    raw[0] !== 0x46 || raw[1] !== 0x53 || raw[2] !== 0x43 || raw[3] !== 0x33 ||
    raw[4] !== 3 || raw[5] !== 1 || raw.subarray(6).some((value) => value !== 0)
  ) {
    throw new ProtocolV3Error("invalid FSC3 control preface");
  }
}

export function encodeHandshakeFrameV3(type: HandshakeMessageTypeV3, payload: Uint8Array): Uint8Array {
  if (
    type < HandshakeMessageTypeV3.ClientInit ||
    type > HandshakeMessageTypeV3.ClientFinished ||
    payload.length < 1 ||
    payload.length > MAX_HANDSHAKE_PAYLOAD_BYTES
  ) {
    throw new ProtocolV3Error("invalid FSH3 handshake frame");
  }
  const out = new Uint8Array(HANDSHAKE_HEADER_BYTES + payload.length);
  out.set(encoder.encode("FSH3"));
  out[4] = 3;
  out[5] = type;
  out.set(u32be(payload.length), 8);
  out.set(payload, HANDSHAKE_HEADER_BYTES);
  return out;
}

export function decodeHandshakeFrameV3(raw: Uint8Array): HandshakeFrameV3 {
  if (
    raw.length < HANDSHAKE_HEADER_BYTES ||
    raw[0] !== 0x46 || raw[1] !== 0x53 || raw[2] !== 0x48 || raw[3] !== 0x33 ||
    raw[4] !== 3 || raw[6] !== 0 || raw[7] !== 0
  ) {
    throw new ProtocolV3Error("invalid FSH3 handshake frame");
  }
  const type = raw[5]! as HandshakeMessageTypeV3;
  const length = readU32be(raw, 8);
  if (
    type < HandshakeMessageTypeV3.ClientInit ||
    type > HandshakeMessageTypeV3.ClientFinished ||
    length < 1 || length > MAX_HANDSHAKE_PAYLOAD_BYTES ||
    raw.length !== HANDSHAKE_HEADER_BYTES + length
  ) {
    throw new ProtocolV3Error("invalid FSH3 handshake frame");
  }
  const payload = raw.slice(HANDSHAKE_HEADER_BYTES);
  try {
    decoder.decode(payload);
  } catch {
    throw new ProtocolV3Error("invalid FSH3 UTF-8 payload");
  }
  return { type, payload, raw: raw.slice() };
}

export function encodeClientInitV3(message: ClientInitV3): Uint8Array {
  validateClientInit(message);
  return encodeCanonicalHandshake(HandshakeMessageTypeV3.ClientInit, {
    channel_id: message.channelID,
    client_admission_binding_b64u: encode32(message.clientAdmissionBinding),
    client_endpoint_instance_id: message.clientEndpointInstanceID,
    client_eph_pub_b64u: base64urlEncode(message.clientEphemeralPublic),
    client_role: message.clientRole,
    max_inbound_streams: message.maxInboundStreams,
    nonce_c_b64u: encode32(message.nonceC),
    profile: message.profile,
    selected_features: message.selectedFeatures,
    session_contract_hash_b64u: encode32(message.sessionContractHash),
    suite: message.suite,
  });
}

export function decodeClientInitV3(raw: Uint8Array): ClientInitV3 {
  const value = decodeCanonicalObject(raw, HandshakeMessageTypeV3.ClientInit, [
    "channel_id", "client_admission_binding_b64u", "client_endpoint_instance_id", "client_eph_pub_b64u",
    "client_role", "max_inbound_streams", "nonce_c_b64u", "profile", "selected_features",
    "session_contract_hash_b64u", "suite",
  ]);
  const message: ClientInitV3 = {
    profile: requireString(value.profile) as "flowersec/3",
    channelID: requireString(value.channel_id),
    sessionContractHash: decode32(value.session_contract_hash_b64u),
    clientRole: requireInteger(value.client_role, 1) as 1,
    suite: requireSuite(value.suite),
    clientEphemeralPublic: decodeBase64(value.client_eph_pub_b64u),
    nonceC: decode32(value.nonce_c_b64u),
    selectedFeatures: requireInteger(value.selected_features, 0xffffffff),
    maxInboundStreams: requireInteger(value.max_inbound_streams, 0xffff),
    clientAdmissionBinding: decode32(value.client_admission_binding_b64u),
    clientEndpointInstanceID: requireString(value.client_endpoint_instance_id),
  };
  validateClientInit(message);
  requireCanonical(raw, encodeClientInitV3(message));
  return message;
}

export function encodeServerFinishedCoreV3(core: ServerFinishedCoreV3, suite: CipherSuiteV3): Uint8Array {
  const normalized = { ...core, suite };
  validateServerCore(normalized);
  return encodeCanonicalHandshake(HandshakeMessageTypeV3.ServerFinished, serverCoreWire(normalized));
}

export function encodeServerFinishedV3(message: ServerFinishedV3, suite: CipherSuiteV3): Uint8Array {
  const core = { ...message.core, suite };
  validateServerCore(core);
  assertBytes("server confirm", message.serverConfirm, 32);
  return encodeCanonicalHandshake(HandshakeMessageTypeV3.ServerFinished, {
    handshake_id: base64urlEncode(core.handshakeID),
    max_inbound_streams: core.maxInboundStreams,
    nonce_s_b64u: encode32(core.nonceS),
    selected_features: core.selectedFeatures,
    server_admission_binding_b64u: encode32(core.serverAdmissionBinding),
    server_confirm_b64u: encode32(message.serverConfirm),
    server_endpoint_instance_id: core.serverEndpointInstanceID,
    server_eph_pub_b64u: base64urlEncode(core.serverEphemeralPublic),
    session_contract_hash_b64u: encode32(core.sessionContractHash),
  });
}

export function decodeServerFinishedV3(raw: Uint8Array, suite: CipherSuiteV3): ServerFinishedV3 {
  const value = decodeCanonicalObject(raw, HandshakeMessageTypeV3.ServerFinished, [
    "handshake_id", "max_inbound_streams", "nonce_s_b64u", "selected_features",
    "server_admission_binding_b64u", "server_confirm_b64u", "server_endpoint_instance_id",
    "server_eph_pub_b64u", "session_contract_hash_b64u",
  ]);
  const core: ServerFinishedCoreV3 = {
    suite,
    handshakeID: decodeBase64(value.handshake_id),
    serverEphemeralPublic: decodeBase64(value.server_eph_pub_b64u),
    nonceS: decode32(value.nonce_s_b64u),
    sessionContractHash: decode32(value.session_contract_hash_b64u),
    selectedFeatures: requireInteger(value.selected_features, 0xffffffff),
    maxInboundStreams: requireInteger(value.max_inbound_streams, 0xffff),
    serverAdmissionBinding: decode32(value.server_admission_binding_b64u),
    serverEndpointInstanceID: requireString(value.server_endpoint_instance_id),
  };
  const message = { core, serverConfirm: decode32(value.server_confirm_b64u) };
  validateServerCore(core);
  requireCanonical(raw, encodeServerFinishedV3(message, suite));
  return message;
}

export function encodeClientFinishedCoreV3(handshakeID: Uint8Array): Uint8Array {
  validateHandshakeID(handshakeID);
  return encodeCanonicalHandshake(HandshakeMessageTypeV3.ClientFinished, {
    handshake_id: base64urlEncode(handshakeID),
  });
}

export function encodeClientFinishedV3(message: ClientFinishedV3): Uint8Array {
  validateHandshakeID(message.handshakeID);
  assertBytes("client confirm", message.clientConfirm, 32);
  return encodeCanonicalHandshake(HandshakeMessageTypeV3.ClientFinished, {
    client_confirm_b64u: encode32(message.clientConfirm),
    handshake_id: base64urlEncode(message.handshakeID),
  });
}

export function decodeClientFinishedV3(raw: Uint8Array): ClientFinishedV3 {
  const value = decodeCanonicalObject(raw, HandshakeMessageTypeV3.ClientFinished, [
    "client_confirm_b64u", "handshake_id",
  ]);
  const message = {
    handshakeID: decodeBase64(value.handshake_id),
    clientConfirm: decode32(value.client_confirm_b64u),
  };
  validateHandshakeID(message.handshakeID);
  requireCanonical(raw, encodeClientFinishedV3(message));
  return message;
}

export function generateEphemeralKeyV3(
  suite: CipherSuiteV3,
  entropy: (length: number) => Uint8Array,
): Readonly<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  let privateKey: Uint8Array;
  if (suite === CipherSuiteV3.ChaCha20Poly1305) {
    privateKey = requireEntropy(entropy, 32);
  } else if (suite === CipherSuiteV3.AES256GCM) {
    do privateKey = requireEntropy(entropy, 32);
    while (!p256.utils.isValidSecretKey(privateKey));
  } else {
    return invalidSuite();
  }
  return { privateKey, publicKey: ephemeralPublicKeyV3(suite, privateKey) };
}

function requireEntropy(entropy: (length: number) => Uint8Array, length: number): Uint8Array {
  const output = entropy(length);
  assertBytes("session entropy", output, length);
  return output.slice();
}

export function ephemeralPublicKeyV3(suite: CipherSuiteV3, privateKey: Uint8Array): Uint8Array {
  assertBytes("ephemeral private key", privateKey, 32);
  try {
    if (suite === CipherSuiteV3.ChaCha20Poly1305) return x25519.getPublicKey(privateKey);
    if (suite === CipherSuiteV3.AES256GCM) return p256.getPublicKey(privateKey, false);
  } catch {
    throw new ProtocolV3Error("invalid v3 ephemeral private key");
  }
  return invalidSuite();
}

export function computeSharedSecretV3(
  suite: CipherSuiteV3,
  privateKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  assertBytes("ephemeral private key", privateKey, 32);
  validateEphemeralPublic(suite, peerPublicKey);
  let shared: Uint8Array;
  try {
    if (suite === CipherSuiteV3.ChaCha20Poly1305) {
      shared = x25519.getSharedSecret(privateKey, peerPublicKey);
    } else if (suite === CipherSuiteV3.AES256GCM) {
      const point = p256.getSharedSecret(privateKey, peerPublicKey, false);
      if (point.length !== 65 || point[0] !== 4) throw new Error("invalid P-256 point");
      shared = point.slice(1, 33);
    } else {
      return invalidSuite();
    }
  } catch {
    throw new ProtocolV3Error("invalid v3 ECDH shared secret");
  }
  if (shared.length !== 32 || shared.every((value) => value === 0)) {
    throw new ProtocolV3Error("invalid v3 ECDH shared secret");
  }
  return shared;
}

export function deriveHandshakePRKV3(psk: Uint8Array, sharedSecret: Uint8Array): Uint8Array {
  assertBytes("handshake PSK", psk, 32);
  assertBytes("ECDH shared secret", sharedSecret, 32);
  if (sharedSecret.every((value) => value === 0)) throw new ProtocolV3Error("invalid v3 ECDH shared secret");
  return extract(sha256, sharedSecret, psk);
}

export function computeHandshakeH0V3(controlPrefaceRaw: Uint8Array, clientInitRaw: Uint8Array): Uint8Array {
  parseControlPrefaceV3(controlPrefaceRaw);
  decodeClientInitV3(clientInitRaw);
  return sha256(concatBytes([
    encoder.encode("flowersec-v3-handshake\0"),
    controlPrefaceRaw,
    lengthPrefixed(clientInitRaw),
  ]));
}

export function computeHandshakeH1V3(h0: Uint8Array, serverCoreRaw: Uint8Array): Uint8Array {
  assertBytes("H0", h0, 32);
  const frame = decodeHandshakeFrameV3(serverCoreRaw);
  if (frame.type !== HandshakeMessageTypeV3.ServerFinished) throw new ProtocolV3Error("invalid v3 transcript");
  return sha256(concatBytes([h0, lengthPrefixed(serverCoreRaw)]));
}

export function computeServerConfirmV3(handshakePRK: Uint8Array, h1: Uint8Array): Uint8Array {
  return computeConfirm(handshakePRK, h1, "flowersec v3 server finished");
}

export function computeHandshakeH2V3(
  h1: Uint8Array,
  serverFinishedRaw: Uint8Array,
  clientCoreRaw: Uint8Array,
): Uint8Array {
  assertBytes("H1", h1, 32);
  if (decodeHandshakeFrameV3(serverFinishedRaw).type !== HandshakeMessageTypeV3.ServerFinished ||
      decodeHandshakeFrameV3(clientCoreRaw).type !== HandshakeMessageTypeV3.ClientFinished) {
    throw new ProtocolV3Error("invalid v3 transcript");
  }
  return sha256(concatBytes([h1, lengthPrefixed(serverFinishedRaw), lengthPrefixed(clientCoreRaw)]));
}

export function computeClientConfirmV3(handshakePRK: Uint8Array, h2: Uint8Array): Uint8Array {
  return computeConfirm(handshakePRK, h2, "flowersec v3 client finished");
}

export function computeHandshakeH3V3(h2: Uint8Array, clientFinishedRaw: Uint8Array): Uint8Array {
  assertBytes("H2", h2, 32);
  decodeClientFinishedV3(clientFinishedRaw);
  return sha256(concatBytes([h2, lengthPrefixed(clientFinishedRaw)]));
}

export function deriveSessionPRKV3(h3: Uint8Array, handshakePRK: Uint8Array): Uint8Array {
  assertBytes("H3", h3, 32);
  assertBytes("handshake PRK", handshakePRK, 32);
  return extract(sha256, handshakePRK, h3);
}

export function validateClientInitV3(message: ClientInitV3, expected: HandshakeExpectationsV3): void {
  validateClientInit(message);
  if (
    message.channelID !== expected.channelID ||
    message.suite !== expected.suite ||
    message.maxInboundStreams !== expected.maxInboundStreams ||
    !bytesEqual(message.sessionContractHash, expected.sessionContractHash) ||
    !validAdmissionBinding(expected.path, message.clientAdmissionBinding, expected.admissionBinding) ||
    !validExpectedEndpoint(expected.path, message.clientEndpointInstanceID, expected.expectedEndpointInstanceID)
  ) {
    throw new ProtocolV3Error("v3 handshake binding mismatch");
  }
}

export function validateServerFinishedV3(message: ServerFinishedV3, expected: HandshakeExpectationsV3): void {
  validateServerCore(message.core);
  if (
    message.core.suite !== expected.suite ||
    message.core.maxInboundStreams !== expected.maxInboundStreams ||
    !bytesEqual(message.core.sessionContractHash, expected.sessionContractHash) ||
    !validAdmissionBinding(expected.path, message.core.serverAdmissionBinding, expected.admissionBinding) ||
    !validExpectedEndpoint(expected.path, message.core.serverEndpointInstanceID, expected.expectedEndpointInstanceID)
  ) {
    throw new ProtocolV3Error("v3 handshake binding mismatch");
  }
}

function serverCoreWire(core: ServerFinishedCoreV3): Record<string, unknown> {
  return {
    handshake_id: base64urlEncode(core.handshakeID),
    max_inbound_streams: core.maxInboundStreams,
    nonce_s_b64u: encode32(core.nonceS),
    selected_features: core.selectedFeatures,
    server_admission_binding_b64u: encode32(core.serverAdmissionBinding),
    server_endpoint_instance_id: core.serverEndpointInstanceID,
    server_eph_pub_b64u: base64urlEncode(core.serverEphemeralPublic),
    session_contract_hash_b64u: encode32(core.sessionContractHash),
  };
}

function validateClientInit(message: ClientInitV3): void {
  if (
    message.profile !== "flowersec/3" ||
    !validRegistryID(message.channelID, false) ||
    message.clientRole !== 1 ||
    (message.selectedFeatures & ~KNOWN_FEATURES_V3) !== 0 ||
    message.maxInboundStreams < 1 || message.maxInboundStreams > 128 ||
    !validRegistryID(message.clientEndpointInstanceID, true)
  ) {
    throw new ProtocolV3Error("invalid v3 client init");
  }
  assertBytes("session contract hash", message.sessionContractHash, 32);
  assertBytes("client nonce", message.nonceC, 32);
  assertBytes("client admission binding", message.clientAdmissionBinding, 32);
  validateEphemeralPublic(message.suite, message.clientEphemeralPublic);
}

function validateServerCore(core: ServerFinishedCoreV3): void {
  validateHandshakeID(core.handshakeID);
  if (
    (core.selectedFeatures & ~KNOWN_FEATURES_V3) !== 0 ||
    core.maxInboundStreams < 1 || core.maxInboundStreams > 128 ||
    !validRegistryID(core.serverEndpointInstanceID, true)
  ) {
    throw new ProtocolV3Error("invalid v3 server finished");
  }
  assertBytes("session contract hash", core.sessionContractHash, 32);
  assertBytes("server nonce", core.nonceS, 32);
  assertBytes("server admission binding", core.serverAdmissionBinding, 32);
  validateEphemeralPublic(core.suite, core.serverEphemeralPublic);
}

function validateEphemeralPublic(suite: CipherSuiteV3, value: Uint8Array): void {
  try {
    if (suite === CipherSuiteV3.ChaCha20Poly1305) {
      assertBytes("X25519 public key", value, 32);
      return;
    }
    if (suite === CipherSuiteV3.AES256GCM) {
      if (value.length !== 65 || value[0] !== 4) throw new Error("invalid P-256 public key");
      p256.Point.fromBytes(value);
      return;
    }
  } catch {
    throw new ProtocolV3Error("invalid v3 ephemeral public key");
  }
  invalidSuite();
}

function encodeCanonicalHandshake(type: HandshakeMessageTypeV3, value: Record<string, unknown>): Uint8Array {
  return encodeHandshakeFrameV3(type, encoder.encode(JSON.stringify(value)));
}

function decodeCanonicalObject(
  raw: Uint8Array,
  type: HandshakeMessageTypeV3,
  fields: readonly string[],
): Record<string, unknown> {
  const frame = decodeHandshakeFrameV3(raw);
  if (frame.type !== type) throw new ProtocolV3Error("unexpected FSH3 message type");
  let value: unknown;
  try {
    value = JSON.parse(decoder.decode(frame.payload)) as unknown;
  } catch {
    throw new ProtocolV3Error("invalid FSH3 JSON payload");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProtocolV3Error("invalid FSH3 JSON object");
  }
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object);
  if (keys.length !== fields.length || fields.some((field) => !Object.hasOwn(object, field))) {
    throw new ProtocolV3Error("invalid FSH3 JSON fields");
  }
  return object;
}

function requireCanonical(actual: Uint8Array, canonical: Uint8Array): void {
  if (!bytesEqual(actual, canonical)) throw new ProtocolV3Error("non-canonical FSH3 message");
}

function requireString(value: unknown): string {
  if (typeof value !== "string") throw new ProtocolV3Error("invalid FSH3 string");
  return value;
}

function requireInteger(value: unknown, max: number): number {
  if (!Number.isInteger(value) || (value as number) < 0 || (value as number) > max) {
    throw new ProtocolV3Error("invalid FSH3 integer");
  }
  return value as number;
}

function requireSuite(value: unknown): CipherSuiteV3 {
  if (value !== CipherSuiteV3.ChaCha20Poly1305 && value !== CipherSuiteV3.AES256GCM) return invalidSuite();
  return value;
}

function decodeBase64(value: unknown): Uint8Array {
  const text = requireString(value);
  try {
    return base64urlDecode(text);
  } catch {
    throw new ProtocolV3Error("invalid FSH3 base64url");
  }
}

function decode32(value: unknown): Uint8Array {
  const decoded = decodeBase64(value);
  assertBytes("FSH3 field", decoded, 32);
  return decoded;
}

function encode32(value: Uint8Array): string {
  assertBytes("FSH3 field", value, 32);
  return base64urlEncode(value);
}

function validateHandshakeID(value: Uint8Array): void {
  if (value.length < 16 || value.length > 32) throw new ProtocolV3Error("invalid v3 handshake ID");
}

function computeConfirm(handshakePRK: Uint8Array, transcript: Uint8Array, label: string): Uint8Array {
  assertBytes("handshake PRK", handshakePRK, 32);
  assertBytes("handshake transcript", transcript, 32);
  const key = expand(sha256, handshakePRK, concatBytes([encoder.encode(label), transcript]), 32);
  return hmac(sha256, key, transcript);
}

function lengthPrefixed(raw: Uint8Array): Uint8Array {
  return concatBytes([u32be(raw.length), raw]);
}

function validRegistryID(value: string, allowEmpty: boolean): boolean {
  return (allowEmpty && value === "") || (value.length >= 1 && value.length <= 128 && registryIDPattern.test(value));
}

function validAdmissionBinding(
  path: "direct" | "tunnel",
  actual: Uint8Array,
  expected: Uint8Array,
): boolean {
  assertBytes("actual admission binding", actual, 32);
  assertBytes("expected admission binding", expected, 32);
  if (path === "direct" || !expected.every((value) => value === 0)) return bytesEqual(actual, expected);
  return !actual.every((value) => value === 0);
}

function validExpectedEndpoint(path: "direct" | "tunnel", actual: string, expected: string): boolean {
  if (path === "direct") return actual === "" && expected === "";
  return validRegistryID(actual, false) && validRegistryID(expected, false) && actual === expected;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function assertBytes(name: string, value: Uint8Array, length: number): void {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new ProtocolV3Error(`${name} must be ${length} bytes`);
  }
}

function invalidSuite(): never {
  throw new ProtocolV3Error("invalid v3 cipher suite");
}
