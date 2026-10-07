import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { array, bytes, fill, map, text, u } from "../v4/testSupport/credentials.js";

/** Short-lived original listener material for engineering pin-policy tests. */
export async function createCurrentP256TLSFixture() {
  const directory = mkdtempSync(join(dirname(fileURLToPath(new URL("../../..", import.meta.url))), "flowersec-wss-pin-current-"));
  const close = () => rmSync(directory, { recursive: true, force: true });
  try {
    const certificatePath = join(directory, "leaf.pem"), keyPath = join(directory, "leaf.key");
    const openssl = (arguments_: string[]) => execFileSync("openssl", arguments_, { stdio: "ignore", timeout: 5000 });
    openssl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyPath]);
    openssl(["req", "-x509", "-new", "-key", keyPath, "-sha256", "-days", "2", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE",
      "-addext", "keyUsage=critical,digitalSignature", "-out", certificatePath]);
    const certificatePEM = readFileSync(certificatePath, "utf8"), privateKeyPEM = readFileSync(keyPath, "utf8");
    const certificate = new X509Certificate(certificatePEM);
    // X.509 dates have one-second precision. Allow the engineering client's
    // original +/-50ms clock interval to fit inside this real certificate.
    const waitMS = Math.max(0, certificate.validFromDate.getTime() + 100 - Date.now());
    if (waitMS > 0) await new Promise<void>(resolve => setTimeout(resolve, waitMS));
    const certificateDER = new Uint8Array(certificate.raw);
    return Object.freeze({ certificatePEM, privateKeyPEM, certificateDER, close });
  } catch (error) { close(); throw error; }
}

/** The independent test issuer signs this Leg; these bytes are not TLS proof. */
export function currentPinnedWSSLeg(host: string, port: number, origin: string, leafDER: Uint8Array, notAfterMS: bigint) {
  const leaf = new X509Certificate(leafDER), from = BigInt(leaf.validFromDate.getTime()), until = BigInt(leaf.validToDate.getTime());
  const now = BigInt(Date.now());
  if (from > now || notAfterMS <= now || notAfterMS > until) throw new Error("engineering pin window is outside the original certificate validity");
  const digest = new Uint8Array(createHash("sha256").update(leafDER).digest());
  return map({ 0: u(0), 1: bytes(fill(21, 16)), 2: u(1), 3: u(0), 4: u(1), 5: u(1),
    6: text(host), 7: u(port), 8: text("/flowersec/v4/direct"), 9: text("http/1.1"), 10: text("flowersec.direct.v4"),
    11: map({ 0: u(1), 1: { kind: "bool", value: true }, 2: u(0), 3: array(map({ 0: bytes(digest), 1: u(from), 2: u(notAfterMS), 3: text("x509v3-p256-14d") })) }),
    12: map({ 0: array(text(origin)), 1: { kind: "bool", value: false } }) });
}
