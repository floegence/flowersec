import {
  createECDH,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
} from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const outputPath = fileURLToPath(new URL("./handshake_vectors.json", import.meta.url));

function sha256(...parts) {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function hmac(key, ...parts) {
  const mac = createHmac("sha256", key);
  for (const part of parts) mac.update(part);
  return mac.digest();
}

function hkdfExtract(salt, ikm) {
  return hmac(salt, ikm);
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

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function withLength(value) {
  return Buffer.concat([u32(value.length), value]);
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function fsc2() {
  const out = Buffer.alloc(16);
  out.write("FSC2", 0, "ascii");
  out[4] = 2;
  out[5] = 1;
  return out;
}

function frame(type, payloadObject) {
  const payload = Buffer.from(canonicalJSON(payloadObject), "utf8");
  const header = Buffer.alloc(12);
  header.write("FSH2", 0, "ascii");
  header[4] = 2;
  header[5] = type;
  header.writeUInt32BE(payload.length, 8);
  return Buffer.concat([header, payload]);
}

function b64u(value) {
  return value.toString("base64url");
}

function fixedBytes(start, length) {
  return Buffer.from(Array.from({ length }, (_, index) => (start + index) & 0xff));
}

function x25519Private(raw) {
  const prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "pkcs8" });
}

function x25519KeyAgreement(clientRaw, serverRaw) {
  const clientPrivate = x25519Private(clientRaw);
  const serverPrivate = x25519Private(serverRaw);
  const clientPublicKey = createPublicKey(clientPrivate);
  const serverPublicKey = createPublicKey(serverPrivate);
  const clientSPKI = clientPublicKey.export({ format: "der", type: "spki" });
  const serverSPKI = serverPublicKey.export({ format: "der", type: "spki" });
  return {
    clientPublic: clientSPKI.subarray(clientSPKI.length - 32),
    serverPublic: serverSPKI.subarray(serverSPKI.length - 32),
    shared: diffieHellman({ privateKey: clientPrivate, publicKey: serverPublicKey }),
  };
}

function p256KeyAgreement(clientRaw, serverRaw) {
  const client = createECDH("prime256v1");
  const server = createECDH("prime256v1");
  client.setPrivateKey(clientRaw);
  server.setPrivateKey(serverRaw);
  return {
    clientPublic: client.getPublicKey(undefined, "uncompressed"),
    serverPublic: server.getPublicKey(undefined, "uncompressed"),
    shared: client.computeSecret(server.getPublicKey()),
  };
}

function buildVector({ id, suite, clientPrivate, serverPrivate, path, maxInboundStreams }) {
  const agreement = suite === 1
    ? x25519KeyAgreement(clientPrivate, serverPrivate)
    : p256KeyAgreement(clientPrivate, serverPrivate);
  const psk = fixedBytes(suite * 16, 32);
  const sessionHash = fixedBytes(0x40 + suite, 32);
  const clientAdmission = fixedBytes(0x70 + suite, 32);
  const serverAdmission = fixedBytes(0xa0 + suite, 32);
  const nonceC = fixedBytes(0x10 + suite, 32);
  const nonceS = fixedBytes(0x30 + suite, 32);
  const handshakeID = fixedBytes(0xd0 + suite, 16);
  const channelID = `channel-${id}`;
  const clientEndpoint = path === "tunnel" ? "endpoint-client" : "";
  const serverEndpoint = path === "tunnel" ? "endpoint-server" : "";

  const clientInit = frame(1, {
    client_admission_binding_b64u: b64u(clientAdmission),
    client_endpoint_instance_id: clientEndpoint,
    client_eph_pub_b64u: b64u(agreement.clientPublic),
    client_role: 1,
    channel_id: channelID,
    max_inbound_streams: maxInboundStreams,
    nonce_c_b64u: b64u(nonceC),
    profile: "flowersec/2",
    selected_features: 0,
    session_contract_hash_b64u: b64u(sessionHash),
    suite,
  });
  const controlPreface = fsc2();
  const handshakePRK = hkdfExtract(psk, agreement.shared);
  const h0 = sha256(Buffer.from("flowersec-v2-handshake\0", "ascii"), controlPreface, withLength(clientInit));

  const serverCoreObject = {
    handshake_id: b64u(handshakeID),
    max_inbound_streams: maxInboundStreams,
    nonce_s_b64u: b64u(nonceS),
    selected_features: 0,
    server_admission_binding_b64u: b64u(serverAdmission),
    server_endpoint_instance_id: serverEndpoint,
    server_eph_pub_b64u: b64u(agreement.serverPublic),
    session_contract_hash_b64u: b64u(sessionHash),
  };
  const serverCore = frame(2, serverCoreObject);
  const h1 = sha256(h0, withLength(serverCore));
  const serverConfirmKey = hkdfExpand(
    handshakePRK,
    Buffer.concat([Buffer.from("flowersec v2 server finished", "ascii"), h1]),
    32,
  );
  const serverConfirm = hmac(serverConfirmKey, h1);
  const serverFinished = frame(2, { ...serverCoreObject, server_confirm_b64u: b64u(serverConfirm) });

  const clientCoreObject = { handshake_id: b64u(handshakeID) };
  const clientCore = frame(3, clientCoreObject);
  const h2 = sha256(h1, withLength(serverFinished), withLength(clientCore));
  const clientConfirmKey = hkdfExpand(
    handshakePRK,
    Buffer.concat([Buffer.from("flowersec v2 client finished", "ascii"), h2]),
    32,
  );
  const clientConfirm = hmac(clientConfirmKey, h2);
  const clientFinished = frame(3, {
    client_confirm_b64u: b64u(clientConfirm),
    handshake_id: b64u(handshakeID),
  });
  const h3 = sha256(h2, withLength(clientFinished));
  const sessionPRK = hkdfExtract(h3, handshakePRK);

  return {
    id,
    suite,
    path,
    max_inbound_streams: maxInboundStreams,
    channel_id: channelID,
    client_endpoint_instance_id: clientEndpoint,
    server_endpoint_instance_id: serverEndpoint,
    psk_hex: psk.toString("hex"),
    client_private_hex: clientPrivate.toString("hex"),
    server_private_hex: serverPrivate.toString("hex"),
    client_public_b64u: b64u(agreement.clientPublic),
    server_public_b64u: b64u(agreement.serverPublic),
    shared_secret_hex: agreement.shared.toString("hex"),
    session_contract_hash_b64u: b64u(sessionHash),
    client_admission_binding_b64u: b64u(clientAdmission),
    server_admission_binding_b64u: b64u(serverAdmission),
    fsc2_hex: controlPreface.toString("hex"),
    client_init_hex: clientInit.toString("hex"),
    server_core_hex: serverCore.toString("hex"),
    server_finished_hex: serverFinished.toString("hex"),
    client_core_hex: clientCore.toString("hex"),
    client_finished_hex: clientFinished.toString("hex"),
    handshake_prk_hex: handshakePRK.toString("hex"),
    h0_hex: h0.toString("hex"),
    h1_hex: h1.toString("hex"),
    server_confirm_key_hex: serverConfirmKey.toString("hex"),
    server_confirm_hex: serverConfirm.toString("hex"),
    h2_hex: h2.toString("hex"),
    client_confirm_key_hex: clientConfirmKey.toString("hex"),
    client_confirm_hex: clientConfirm.toString("hex"),
    h3_hex: h3.toString("hex"),
    session_prk_hex: sessionPRK.toString("hex"),
  };
}

const vectors = [
  buildVector({
    id: "x25519-direct",
    suite: 1,
    clientPrivate: fixedBytes(1, 32),
    serverPrivate: fixedBytes(65, 32),
    path: "direct",
    maxInboundStreams: 1,
  }),
  buildVector({
    id: "p256-tunnel",
    suite: 2,
    clientPrivate: Buffer.concat([Buffer.alloc(31), Buffer.from([1])]),
    serverPrivate: Buffer.concat([Buffer.alloc(31), Buffer.from([2])]),
    path: "tunnel",
    maxInboundStreams: 128,
  }),
];

const output = {
  version: 1,
  profile: "flowersec/2",
  source: {
    runtime: process.version,
    implementation: "Node.js built-in crypto only",
    generator: "testdata/transport_v2/generate_handshake_vectors.mjs",
  },
  vectors,
};

writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, "utf8");
