import { X509Certificate, createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHTTPSServer } from "node:https";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTLSServer } from "node:tls";

import { afterAll, beforeAll, describe, expect, test } from "vitest";

import {
  connectNodeTLSSocketV3,
  connectNodeWebSocketV3,
  isNodeCertificateTrustErrorV3,
  verifyPinnedLeafCertificateV3,
} from "./nodeRuntime.js";
import type { CanonicalArtifactCandidateV3, TransportSecurityPolicyV3 } from "./artifact.js";

if (spawnSync("openssl", ["version"], { stdio: "ignore" }).status !== 0) {
  throw new Error("OpenSSL is required for the transport v3 Node TLS test suite");
}
const require = createRequire(import.meta.url);
const wsModule = require("ws") as { WebSocketServer: new (...args: unknown[]) => any };

let directory = "";
let rootCertificate: Buffer;
let leafCertificate: Buffer;
let leafKey: Buffer;
let purposeLeafCertificate: Buffer;
let expiredLeafCertificate: Buffer;
let futureLeafCertificate: Buffer;
let expiredLeafDigest: Buffer;
let futureLeafDigest: Buffer;
let pinCertificate: Buffer;
let pinKey: Buffer;
let pinDigest: Buffer;
let nextPinCertificate: Buffer;
let nextPinKey: Buffer;
let nextPinDigest: Buffer;
let rsaPinCertificate: Buffer;
let rsaPinKey: Buffer;
let rsaPinDigest: Buffer;
let overlongPinCertificate: Buffer;
let overlongPinKey: Buffer;
let overlongPinDigest: Buffer;
let legacyPinDER: Buffer;

describe("transport v3 Node TLS verifier and WebSocket production path", () => {
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), "flowersec-ts-v3-tls-"));
    generateCertificates(directory);
    rootCertificate = readFileSync(join(directory, "root.pem"));
    leafCertificate = readFileSync(join(directory, "leaf.pem"));
    leafKey = readFileSync(join(directory, "leaf.key"));
    purposeLeafCertificate = readFileSync(join(directory, "leaf-purpose.pem"));
    expiredLeafCertificate = readFileSync(join(directory, "leaf-expired.pem"));
    futureLeafCertificate = readFileSync(join(directory, "leaf-future.pem"));
    expiredLeafDigest = createHash("sha256").update(readFileSync(join(directory, "leaf-expired.der"))).digest();
    futureLeafDigest = createHash("sha256").update(readFileSync(join(directory, "leaf-future.der"))).digest();
    pinCertificate = readFileSync(join(directory, "pin.pem"));
    pinKey = readFileSync(join(directory, "pin.key"));
    pinDigest = createHash("sha256").update(readFileSync(join(directory, "pin.der"))).digest();
    nextPinCertificate = readFileSync(join(directory, "pin-next.pem"));
    nextPinKey = readFileSync(join(directory, "pin-next.key"));
    nextPinDigest = createHash("sha256").update(readFileSync(join(directory, "pin-next.der"))).digest();
    rsaPinCertificate = readFileSync(join(directory, "pin-rsa.pem"));
    rsaPinKey = readFileSync(join(directory, "pin-rsa.key"));
    rsaPinDigest = createHash("sha256").update(readFileSync(join(directory, "pin-rsa.der"))).digest();
    overlongPinCertificate = readFileSync(join(directory, "pin-overlong.pem"));
    overlongPinKey = readFileSync(join(directory, "pin-overlong.key"));
    overlongPinDigest = createHash("sha256").update(readFileSync(join(directory, "pin-overlong.der"))).digest();
    legacyPinDER = certificateWithVersion(readFileSync(join(directory, "pin.der")), 1);
  });

  afterAll(() => {
    if (directory !== "") rmSync(directory, { recursive: true, force: true });
  });

  test("accepts a deployment CA and rejects the same server without its trust root", async () => {
    const server = createTLSServer({ cert: leafCertificate, key: leafKey });
    const port = await listen(server);
    const candidate = websocketCandidate(port, { mode: "ca" });
    try {
      const socket = await connectNodeTLSSocketV3(candidate, nowSeconds(), {
        roots: rootCertificate,
        timeoutMilliseconds: 2_000,
      });
      expect(socket.authorized).toBe(true);
      socket.destroy();
      await expect(connectNodeTLSSocketV3(candidate, nowSeconds(), { timeoutMilliseconds: 2_000 }))
        .rejects.toMatchObject({ code: "tls_failed", detail: "ca_untrusted" });
    } finally {
      await closeServer(server);
    }
  });

  test("does not resume or accept TLS session tickets for v3 clients", async () => {
    expect(readFileSync(new URL("./nodeRuntime.ts", import.meta.url), "utf8"))
      .toContain("secureOptions: constants.SSL_OP_NO_TICKET");
    const server = createTLSServer({ cert: leafCertificate, key: leafKey });
    const port = await listen(server);
    try {
      const socket = await connectNodeTLSSocketV3(websocketCandidate(port, { mode: "ca" }), nowSeconds(), {
        roots: rootCertificate,
        timeoutMilliseconds: 2_000,
      });
      expect(socket.isSessionReused()).toBe(false);
      socket.destroy();
    } finally {
      await closeServer(server);
    }
  });

  test.each([
    ["expired", () => expiredLeafCertificate, "CERT_HAS_EXPIRED"],
    ["not-yet-valid", () => futureLeafCertificate, "CERT_NOT_YET_VALID"],
  ] as const)("classifies a real %s CA certificate as terminal trust failure", async (_name, certificate, code) => {
    const server = createTLSServer({ cert: certificate(), key: leafKey });
    const port = await listen(server);
    try {
      await expect(connectNodeTLSSocketV3(
        websocketCandidate(port, { mode: "ca" }),
        nowSeconds(),
        { roots: rootCertificate, timeoutMilliseconds: 2_000 },
      )).rejects.toMatchObject({
        code: "tls_failed",
        detail: "ca_untrusted",
        cause: expect.objectContaining({ code }),
      });
    } finally {
      await closeServer(server);
    }
  });

  test("classifies a trusted client-only certificate purpose as terminal CA trust failure", async () => {
    const server = createTLSServer({ cert: purposeLeafCertificate, key: leafKey });
    const port = await listen(server);
    try {
      await expect(connectNodeTLSSocketV3(
        websocketCandidate(port, { mode: "ca" }),
        nowSeconds(),
        { roots: rootCertificate, timeoutMilliseconds: 2_000 },
      )).rejects.toMatchObject({
        code: "tls_failed",
        detail: "ca_untrusted",
        cause: expect.objectContaining({ code: "INVALID_PURPOSE" }),
      });
    } finally {
      await closeServer(server);
    }
  });

  test("classifies the authoritative Node/OpenSSL PKI verification codes", () => {
    for (const code of [
      "CERT_HAS_EXPIRED",
      "CERT_NOT_YET_VALID",
      "CERT_REJECTED",
      "CERT_REVOKED",
      "CERT_SIGNATURE_FAILURE",
      "DEPTH_ZERO_SELF_SIGNED_CERT",
      "ERR_TLS_CERT_ALTNAME_INVALID",
      "INVALID_CA",
      "INVALID_PURPOSE",
      "PATH_LENGTH_EXCEEDED",
      "SELF_SIGNED_CERT_IN_CHAIN",
      "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
      "UNABLE_TO_GET_ISSUER_CERT",
      "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
      "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    ]) {
      expect(isNodeCertificateTrustErrorV3(code), code).toBe(true);
    }
    for (const code of [undefined, "CERT_EXPIRED", "ECONNREFUSED", "ERR_SSL_WRONG_VERSION_NUMBER"]) {
      expect(isNodeCertificateTrustErrorV3(code), String(code)).toBe(false);
    }
  });

  test("accepts exact and old-new overlap P-256 DER pins and rejects a mismatch", async () => {
    const server = createTLSServer({ cert: pinCertificate, key: pinKey });
    const port = await listen(server);
    try {
      const socket = await connectNodeTLSSocketV3(
        websocketCandidate(port, pinPolicy(pinDigest)),
        nowSeconds(),
        { timeoutMilliseconds: 2_000 },
      );
      expect(socket.authorized).toBe(false);
      socket.destroy();
      const wrong = Buffer.from(pinDigest);
      wrong[0] = (wrong[0] ?? 0) ^ 0xff;
      await expect(connectNodeTLSSocketV3(
        websocketCandidate(port, pinPolicy(wrong)),
        nowSeconds(),
        { roots: pinCertificate, timeoutMilliseconds: 2_000 },
      )).rejects.toMatchObject({ code: "tls_failed", detail: "pin_mismatch" });

      const overlapPolicy = overlapPinPolicy(pinDigest, nextPinDigest);
      const oldCertificate = await connectNodeTLSSocketV3(
        websocketCandidate(port, overlapPolicy),
        nowSeconds(),
        { timeoutMilliseconds: 2_000 },
      );
      expect(oldCertificate.authorized).toBe(false);
      oldCertificate.destroy();

      const nextServer = createTLSServer({ cert: nextPinCertificate, key: nextPinKey });
      const nextPort = await listen(nextServer);
      try {
        const nextCertificate = await connectNodeTLSSocketV3(
          websocketCandidate(nextPort, overlapPolicy),
          nowSeconds(),
          { timeoutMilliseconds: 2_000 },
        );
        expect(nextCertificate.authorized).toBe(false);
        nextCertificate.destroy();
      } finally {
        await closeServer(nextServer);
      }
    } finally {
      await closeServer(server);
    }
  });

  test.each([
    ["rsa", () => rsaPinCertificate, () => rsaPinKey, () => rsaPinDigest],
    ["overlong", () => overlongPinCertificate, () => overlongPinKey, () => overlongPinDigest],
    ["not-yet-valid", () => futureLeafCertificate, () => leafKey, () => futureLeafDigest],
    ["expired", () => expiredLeafCertificate, () => leafKey, () => expiredLeafDigest],
  ] as const)("rejects a hash-matched %s pin profile through the production TLS adapter", async (
    _name,
    certificate,
    key,
    digest,
  ) => {
    const server = createTLSServer({ cert: certificate(), key: key() });
    const port = await listen(server);
    try {
      await expect(connectNodeTLSSocketV3(
        websocketCandidate(port, pinPolicy(digest())),
        nowSeconds(),
        { timeoutMilliseconds: 2_000 },
      )).rejects.toMatchObject({ code: "tls_failed", detail: "unknown" });
    } finally {
      await closeServer(server);
    }
  });

  test("freezes active pins at attempt start but checks certificate validity at secureConnect", async () => {
    const certificate = new X509Certificate(pinCertificate);
    const notBefore = Date.parse(certificate.validFrom);
    const notAfter = Date.parse(certificate.validTo);
    expect(Number.isFinite(notBefore) && Number.isFinite(notAfter)).toBe(true);
    const policy: TransportSecurityPolicyV3 = {
      mode: "pin",
      pins: [{
        algorithm: "sha-256",
        value_b64u: pinDigest.toString("base64url"),
        not_after_unix_s: Math.floor(notAfter / 1_000) + 3_600,
      }],
    };
    const server = createTLSServer({ cert: pinCertificate, key: pinKey });
    const port = await listen(server);
    try {
      const socket = await connectNodeTLSSocketV3(
        websocketCandidate(port, policy),
        Math.floor((notBefore - 1_000) / 1_000),
        {
          timeoutMilliseconds: 2_000,
          nowUnixMilliseconds: () => notBefore + 1_000,
        },
      );
      socket.destroy();

      await expect(connectNodeTLSSocketV3(
        websocketCandidate(port, policy),
        Math.floor((notBefore + 1_000) / 1_000),
        {
          timeoutMilliseconds: 2_000,
          nowUnixMilliseconds: () => notAfter,
        },
      )).rejects.toMatchObject({ code: "tls_failed", detail: "unknown" });
    } finally {
      await closeServer(server);
    }
  });

  test("performs WebSocket Upgrade only after pin verification", async () => {
    const server = createHTTPSServer({ cert: pinCertificate, key: pinKey });
    const webSocketServer = new wsModule.WebSocketServer({
      server,
      handleProtocols: (protocols: Set<string>) => protocols.has("flowersec.direct.v3")
        ? "flowersec.direct.v3"
        : false,
    });
    const port = await listen(server);
    let upgrades = 0;
    server.on("upgrade", () => { upgrades += 1; });
    const candidate = websocketCandidate(port, pinPolicy(pinDigest));
    try {
      const socket = await connectNodeWebSocketV3(candidate, nowSeconds(), {
        origin: "https://app.example",
        timeoutMilliseconds: 2_000,
      });
      expect(socket.protocol).toBe("flowersec.direct.v3");
      expect(upgrades).toBe(1);
      socket.close();

      const wrong = Buffer.from(pinDigest);
      wrong[31] = (wrong[31] ?? 0) ^ 0xff;
      await expect(connectNodeWebSocketV3(
        websocketCandidate(port, pinPolicy(wrong)),
        nowSeconds(),
        { origin: "https://app.example", timeoutMilliseconds: 2_000 },
      )).rejects.toMatchObject({ code: "tls_failed", detail: "pin_mismatch" });
      expect(upgrades).toBe(1);
    } finally {
      await new Promise<void>((resolve) => webSocketServer.close(() => resolve()));
      await closeServer(server);
    }
  });

  test("rejects a hash-matched X.509 version 2 certificate", () => {
    const digest = createHash("sha256").update(legacyPinDER).digest();
    expect(() => verifyPinnedLeafCertificateV3(
      legacyPinDER,
      {
        mode: "pin",
        activePins: [{
          algorithm: "sha-256",
          not_after_unix_s: Math.floor(Date.now() / 1_000) + 600,
          value_b64u: digest.toString("base64url"),
        }],
        activeLeafDerSHA256: [digest],
      },
      Date.now(),
    )).toThrowError(expect.objectContaining({ code: "tls_failed", detail: "unknown" }));
  });
});

function generateCertificates(target: string): void {
  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "root.key")]);
  runOpenSSL([
    "req", "-x509", "-new", "-key", join(target, "root.key"), "-sha256", "-days", "2",
    "-subj", "/CN=Flowersec Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", join(target, "root.pem"),
  ]);
  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "leaf.key")]);
  runOpenSSL([
    "req", "-new", "-key", join(target, "leaf.key"), "-subj", "/CN=localhost", "-out", join(target, "leaf.csr"),
  ]);
  writeFileSync(join(target, "leaf.ext"), [
    "subjectAltName=DNS:localhost",
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=serverAuth",
    "",
  ].join("\n"));
  writeFileSync(join(target, "leaf-purpose.ext"), [
    "subjectAltName=DNS:localhost",
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=clientAuth",
    "",
  ].join("\n"));
  runOpenSSL([
    "x509", "-req", "-in", join(target, "leaf.csr"), "-CA", join(target, "root.pem"),
    "-CAkey", join(target, "root.key"), "-CAcreateserial", "-days", "2", "-sha256",
    "-extfile", join(target, "leaf.ext"), "-out", join(target, "leaf.pem"),
  ]);
  runOpenSSL([
    "x509", "-req", "-in", join(target, "leaf.csr"), "-CA", join(target, "root.pem"),
    "-CAkey", join(target, "root.key"), "-CAcreateserial", "-days", "2", "-sha256",
    "-extfile", join(target, "leaf-purpose.ext"), "-out", join(target, "leaf-purpose.pem"),
  ]);
  writeFileSync(join(target, "index.txt"), "");
  writeFileSync(join(target, "serial"), "1000\n");
  writeFileSync(join(target, "ca.cnf"), [
    "[ca]",
    "default_ca=flowersec_ca",
    "[flowersec_ca]",
    `database=${join(target, "index.txt")}`,
    `serial=${join(target, "serial")}`,
    `new_certs_dir=${target}`,
    `certificate=${join(target, "root.pem")}`,
    `private_key=${join(target, "root.key")}`,
    "default_md=sha256",
    "policy=flowersec_policy",
    "unique_subject=no",
    "copy_extensions=copy",
    "[flowersec_policy]",
    "commonName=supplied",
    "",
  ].join("\n"));
  for (const [name, start, end] of [
    ["expired", "20000101000000Z", "20000102000000Z"],
    ["future", "20400101000000Z", "20400102000000Z"],
  ]) {
    runOpenSSL([
      "ca", "-batch", "-config", join(target, "ca.cnf"), "-in", join(target, "leaf.csr"),
      "-startdate", start, "-enddate", end, "-out", join(target, `leaf-${name}.pem`),
    ]);
    runOpenSSL([
      "x509", "-in", join(target, `leaf-${name}.pem`), "-outform", "DER",
      "-out", join(target, `leaf-${name}.der`),
    ]);
  }
  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "pin.key")]);
  runOpenSSL([
    "req", "-x509", "-new", "-key", join(target, "pin.key"), "-sha256", "-days", "2",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
    "-out", join(target, "pin.pem"),
  ]);
  runOpenSSL(["x509", "-in", join(target, "pin.pem"), "-outform", "DER", "-out", join(target, "pin.der")]);
  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "pin-next.key")]);
  runOpenSSL([
    "req", "-x509", "-new", "-key", join(target, "pin-next.key"), "-sha256", "-days", "2",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
    "-out", join(target, "pin-next.pem"),
  ]);
  runOpenSSL(["x509", "-in", join(target, "pin-next.pem"), "-outform", "DER", "-out", join(target, "pin-next.der")]);

  runOpenSSL([
    "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
    "-out", join(target, "pin-rsa.key"),
  ]);
  runOpenSSL([
    "req", "-x509", "-new", "-key", join(target, "pin-rsa.key"), "-sha256", "-days", "2",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
    "-out", join(target, "pin-rsa.pem"),
  ]);
  runOpenSSL(["x509", "-in", join(target, "pin-rsa.pem"), "-outform", "DER", "-out", join(target, "pin-rsa.der")]);

  runOpenSSL(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", join(target, "pin-overlong.key")]);
  runOpenSSL([
    "req", "-x509", "-new", "-key", join(target, "pin-overlong.key"), "-sha256", "-days", "30",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
    "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature",
    "-out", join(target, "pin-overlong.pem"),
  ]);
  runOpenSSL([
    "x509", "-in", join(target, "pin-overlong.pem"), "-outform", "DER",
    "-out", join(target, "pin-overlong.der"),
  ]);

}

function certificateWithVersion(der: Buffer, encodedVersion: number): Buffer {
  const marker = Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]);
  const offset = der.indexOf(marker);
  if (offset < 0) throw new Error("generated certificate is not X.509v3");
  const result = Buffer.from(der);
  result[offset + marker.length - 1] = encodedVersion;
  return result;
}

function runOpenSSL(args: readonly string[]): void {
  execFileSync("openssl", [...args], { stdio: "ignore" });
}

function pinPolicy(digest: Uint8Array): TransportSecurityPolicyV3 {
  return {
    mode: "pin",
    pins: [{
      algorithm: "sha-256",
      value_b64u: Buffer.from(digest).toString("base64url"),
      not_after_unix_s: nowSeconds() + 3_600,
    }],
  };
}

function overlapPinPolicy(...digests: readonly Uint8Array[]): TransportSecurityPolicyV3 {
  return {
    mode: "pin",
    pins: digests.map((digest) => ({
      algorithm: "sha-256" as const,
      value_b64u: Buffer.from(digest).toString("base64url"),
      not_after_unix_s: nowSeconds() + 3_600,
    })).sort((left, right) => left.value_b64u < right.value_b64u ? -1 : left.value_b64u > right.value_b64u ? 1 : 0),
  };
}

function websocketCandidate(port: number, tls: TransportSecurityPolicyV3): CanonicalArtifactCandidateV3 {
  return {
    carrier: "websocket",
    id: "node-websocket",
    normalized_url: `wss://localhost:${port}/flowersec/v3/direct`,
    tls,
    wire_profile: "flowersec-direct/3",
  };
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

async function listen(server: { listen(port: number, host: string): unknown; address(): unknown }): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server as unknown as NodeJS.EventEmitter, "listening");
  const address = server.address();
  if (typeof address !== "object" || address === null || !("port" in address)) throw new Error("server did not listen");
  return (address as { port: number }).port;
}

async function closeServer(server: { close(callback: (error?: Error) => void): void; closeAllConnections?: () => void }): Promise<void> {
  server.closeAllConnections?.();
  await new Promise<void>((resolve, reject) => server.close((error) => error === undefined ? resolve() : reject(error)));
}
