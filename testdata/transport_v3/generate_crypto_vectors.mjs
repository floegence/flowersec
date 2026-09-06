#!/usr/bin/env node

import { createCipheriv, createHmac } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import { loadTransportRegistry, provenance } from "./registry_provenance.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const transport = loadTransportRegistry();
const domain = (name) => transport.labels[name];
const checkOnly = process.argv.length === 3 && process.argv[2] === "--check";
if (process.argv.length > (checkOnly ? 3 : 2)) {
  throw new Error("usage: generate_crypto_vectors.mjs [--check]");
}

function write(name, value) {
  const rendered = `${JSON.stringify(value, null, 2)}\n`;
  const output = join(root, name);
  if (checkOnly) {
    if (readFileSync(output, "utf8") !== rendered) {
      throw new Error(`${name} is not reproducible; regenerate crypto vectors`);
    }
    return;
  }
  writeFileSync(output, rendered);
}

function hmac(key, ...parts) {
  const value = createHmac("sha256", key);
  for (const part of parts) value.update(part);
  return value.digest();
}

function hkdfExpand(prk, info, length) {
  const blocks = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; Buffer.concat(blocks).length < length; counter++) {
    previous = hmac(prk, previous, info, Buffer.from([counter]));
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function label(name, ...parts) {
  return Buffer.concat([Buffer.from(name, "ascii"), Buffer.from([0]), ...parts]);
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

function seal(algorithm, key, nonce, aad, plaintext) {
  const cipher = createCipheriv(algorithm, key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function roots(epochSecret) {
  return {
    controlRoot: hkdfExpand(epochSecret, label(domain("control_root")), 32),
    streamRoot: hkdfExpand(epochSecret, label(domain("stream_root")), 32),
    setupRoot: hkdfExpand(epochSecret, label(domain("setup_root")), 32),
    rekeyRoot: hkdfExpand(epochSecret, label(domain("rekey_root")), 32),
  };
}

const sessionPRK = Buffer.from([...Array(32).keys()]);
const h3 = Buffer.from([...Array(32).keys()].map((value) => value + 32));
const direction = 1;
const epoch = 0;
const logicalStreamID = 1;
const sequence = 0;
const epochSecret = hkdfExpand(sessionPRK, label(domain("epoch_zero"), Buffer.from([direction])), 32);
const epochRoots = roots(epochSecret);
const streamSecret = hkdfExpand(
  epochRoots.streamRoot,
  label(domain("stream"), h3, u64(logicalStreamID), Buffer.from([direction]), u32(epoch)),
  32,
);
const recordKey = hkdfExpand(streamSecret, label(domain("record_key")), 32);
const noncePrefix = hkdfExpand(streamSecret, label(domain("nonce")), 4);
const setupPrefix = Buffer.alloc(24);
setupPrefix.write(transport.registry.frame_family.setup, 0, "ascii");
setupPrefix[4] = transport.registry.frame_family.version_byte;
setupPrefix[5] = 1;
setupPrefix.writeBigUInt64BE(BigInt(logicalStreamID), 8);
setupPrefix.writeUInt32BE(epoch, 16);
const setupMAC = hmac(epochRoots.setupRoot, label(domain("setup_mac").replace(/\0$/, ""), h3, setupPrefix));
const setup = Buffer.concat([setupPrefix, setupMAC]);
const inner = Buffer.concat([Buffer.from([4, 0, 0, 0]), u32(3), Buffer.from("abc")]);
const recordHeader = Buffer.alloc(24);
recordHeader.write(transport.registry.frame_family.record, 0, "ascii");
recordHeader[4] = transport.registry.frame_family.version_byte;
recordHeader[5] = 24;
recordHeader.writeUInt32BE(epoch, 8);
recordHeader.writeBigUInt64BE(BigInt(sequence), 12);
recordHeader.writeUInt32BE(inner.length + 16, 20);
const recordAAD = label(
  domain("record_aad").replace(/\0$/, ""),
  h3,
  u64(logicalStreamID),
  Buffer.from([direction]),
  recordHeader,
);
const recordNonce = Buffer.concat([noncePrefix, u64(sequence)]);

const cryptoVectors = provenance({
  version: 3,
  profile: transport.registry.profiles.session,
  source: "testdata/transport_v3/generate_crypto_vectors.mjs using Node.js crypto",
  vectors: [
    {
      id: "epoch0-c2s-stream1-data-abc",
      direction,
      epoch,
      logical_stream_id: logicalStreamID,
      sequence,
      session_prk_hex: sessionPRK.toString("hex"),
      h3_hex: h3.toString("hex"),
      epoch_secret_hex: epochSecret.toString("hex"),
      control_root_hex: epochRoots.controlRoot.toString("hex"),
      stream_root_hex: epochRoots.streamRoot.toString("hex"),
      setup_root_hex: epochRoots.setupRoot.toString("hex"),
      rekey_root_hex: epochRoots.rekeyRoot.toString("hex"),
      stream_secret_hex: streamSecret.toString("hex"),
      record_key_hex: recordKey.toString("hex"),
      nonce_prefix_hex: noncePrefix.toString("hex"),
      fss3_hex: setup.toString("hex"),
      fsr3_header_hex: recordHeader.toString("hex"),
      inner_hex: inner.toString("hex"),
      aad_hex: recordAAD.toString("hex"),
      chacha20_poly1305_ciphertext_hex: seal(
        "chacha20-poly1305", recordKey, recordNonce, recordAAD, inner,
      ).toString("hex"),
      aes_256_gcm_ciphertext_hex: seal(
        "aes-256-gcm", recordKey, recordNonce, recordAAD, inner,
      ).toString("hex"),
    },
  ],
}, transport);
write("crypto_vectors.json", cryptoVectors);

function datagramVector(suite) {
  const datagramEpoch = 7;
  const datagramSequence = 11;
  const expiresAt = 2_000_000_000_000;
  const epochZero = hkdfExpand(sessionPRK, label(domain("epoch_zero"), Buffer.from([direction])), 32);
  const rekeyRoot = roots(epochZero).rekeyRoot;
  const datagramEpochSecret = hkdfExpand(
    rekeyRoot,
    label(domain("next_epoch"), h3, Buffer.from([direction]), u32(datagramEpoch)),
    32,
  );
  const unreliableRoot = hkdfExpand(
    datagramEpochSecret,
    label(domain("unreliable_root")),
    32,
  );
  const materialSecret = hkdfExpand(
    unreliableRoot,
    label(domain("unreliable"), h3, Buffer.from([direction]), u32(datagramEpoch)),
    32,
  );
  const datagramKey = hkdfExpand(materialSecret, label(domain("unreliable_key")), 32);
  const datagramNoncePrefix = hkdfExpand(materialSecret, label(domain("unreliable_nonce")), 4);
  const plaintext = Buffer.from(`flowersec-datagram-v3-suite-${suite}`);
  const header = Buffer.alloc(32);
  header.write(transport.registry.frame_family.datagram, 0, "ascii");
  header[4] = transport.registry.frame_family.version_byte;
  header.writeUInt16BE(32, 6);
  header.writeUInt32BE(datagramEpoch, 8);
  header.writeBigUInt64BE(BigInt(datagramSequence), 12);
  header.writeBigUInt64BE(BigInt(expiresAt), 20);
  header.writeUInt32BE(plaintext.length + 16, 28);
  const aad = label(domain("unreliable_aad").replace(/\0$/, ""), h3, Buffer.from([direction]), header);
  const nonce = Buffer.concat([datagramNoncePrefix, u64(datagramSequence)]);
  const ciphertext = seal(
    suite === 1 ? "chacha20-poly1305" : "aes-256-gcm",
    datagramKey,
    nonce,
    aad,
    plaintext,
  );
  return {
    name: `${suite === 1 ? "chacha20poly1305" : "aes256gcm"}_client_to_server_epoch_7`,
    suite,
    session_prk_b64u: sessionPRK.toString("base64url"),
    h3_b64u: h3.toString("base64url"),
    direction,
    epoch: datagramEpoch,
    sequence: datagramSequence,
    expires_at_unix_ms: expiresAt,
    plaintext_b64u: plaintext.toString("base64url"),
    epoch_secret_b64u: datagramEpochSecret.toString("base64url"),
    unreliable_root_b64u: unreliableRoot.toString("base64url"),
    material_secret_b64u: materialSecret.toString("base64url"),
    record_key_b64u: datagramKey.toString("base64url"),
    nonce_prefix_b64u: datagramNoncePrefix.toString("base64url"),
    nonce_b64u: nonce.toString("base64url"),
    header_hex: header.toString("hex"),
    aad_b64u: aad.toString("base64url"),
    ciphertext_b64u: ciphertext.toString("base64url"),
    wire_b64u: Buffer.concat([header, ciphertext]).toString("base64url"),
  };
}

write("datagram_vectors.json", provenance({ schema_version: 3, vectors: [datagramVector(1), datagramVector(2)] }, transport));

write(
  "session_wire_vectors.json",
  provenance({
    version: 3,
    profile: transport.registry.profiles.session,
    stream_key_update_ack: [{
      logical_id_hex: "0102030405060708",
      transition_id_hex: "1112131415161718",
      next_epoch_hex: "21222324",
      payload_hex: "0102030405060708111213141516171821222324",
    }],
    transition_boundary: {
      maximum_transition_id_hex: "ffffffffffffffff",
      next_after_maximum_hex: "0000000000000000",
      maximum_is_usable_once: true,
      exhaustion_error: "resource_exhausted",
      exhaustion_goaway_reason: 5,
      receive_after_maximum: "protocol_failure",
      goaway_delivery_failure: "session_failure",
    },
    epoch_boundary: {
      maximum_epoch_hex: "ffffffff",
      maximum_is_usable: true,
      rekey_after_maximum: "resource_exhausted",
      exhaustion_goaway_reason: 5,
      receive_after_maximum: "protocol_failure",
      goaway_delivery_failure: "session_failure",
    },
  }, transport),
);
