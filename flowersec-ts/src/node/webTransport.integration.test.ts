import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, test } from "vitest";

import { createNodeWebTransportClientV2 } from "./webTransportClient.js";
import { startNodeWebTransportServerV2 } from "./webTransportServer.js";

const text = (value: string): Uint8Array => new TextEncoder().encode(value);
const decode = (value: Uint8Array | null): string => value === null ? "" : new TextDecoder().decode(value);

describe("Node WebTransport runtime adapter", () => {
  test("carries native stream FIN and DATAGRAM without a browser", async () => {
    const temporary = mkdtempSync(path.join(os.tmpdir(), "flowersec-node-webtransport-"));
    const certificate = path.join(temporary, "certificate.pem");
    const privateKey = path.join(temporary, "private-key.pem");
    const certificateDER = path.join(temporary, "certificate.der");
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
      "-nodes", "-days", "1", "-sha256", "-subj", "/CN=127.0.0.1",
      "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", privateKey, "-out", certificate,
    ], { stdio: "ignore" });
    execFileSync("openssl", ["x509", "-in", certificate, "-outform", "DER", "-out", certificateDER]);
    const certificateHash = createHash("sha256").update(readFileSync(certificateDER)).digest();
    const server = await startNodeWebTransportServerV2({
      host: "127.0.0.1",
      port: 0,
      path: "/flowersec/webtransport/v2/direct",
      certificate: readFileSync(certificate, "utf8"),
      privateKey: readFileSync(privateKey, "utf8"),
      carrierPath: "direct",
      inboundBidirectionalStreamCapacity: 10,
    });
    let client;
    let accepted;
    try {
      const address = server.address();
      [client, accepted] = await Promise.all([
        createNodeWebTransportClientV2(
          `https://127.0.0.1:${address.port}/flowersec/webtransport/v2/direct`,
          {
            path: "direct",
            inboundBidirectionalStreamCapacity: 10,
            serverCertificateHash: certificateHash,
          },
        ),
        server.accept(),
      ]);
      const clientStream = await client.openStream();
      const serverStream = await accepted.acceptStream();
      await clientStream.write(text("FSC2"));
      await clientStream.closeWrite();
      expect(decode(await serverStream.read())).toBe("FSC2");
      expect(await serverStream.read()).toBeNull();

      expect(await client.unreliableDatagrams!.send(text("FSD2"))).toBe("accepted");
      expect(decode(await accepted.unreliableDatagrams!.receive())).toBe("FSD2");
    } finally {
      await Promise.all([client?.close(), accepted?.close()]);
      await server.close();
      rmSync(temporary, { recursive: true, force: true });
    }
  }, 30_000);
});
