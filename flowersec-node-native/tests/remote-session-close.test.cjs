"use strict";

const assert = require("node:assert/strict");
const { createPrivateKey, X509Certificate } = require("node:crypto");
const test = require("node:test");
const { testCertificatePEM, testPrivateKeyPEM } = require("../../flowersec-ts/src/testSupport/tlsFixture.ts");

const addon = require(process.env.FLOWERSEC_SERVER_PARITY_NATIVE_ADDON ?? "..");
const certificateChainDer = [new X509Certificate(testCertificatePEM).raw];
const privateKeyDer = createPrivateKey(testPrivateKeyPEM).export({ type: "pkcs8", format: "der" });
const common = { path: "tunnel", inboundBidirectionalStreamCapacity: 4, handshakeTimeoutMs: 3_000 };
const bind = { ...common, host: "127.0.0.1", port: 0, certificateChainDer, privateKeyDer };
const dial = { ...common, tlsMode: "ca", trustRootsDer: certificateChainDer };
const origin = "https://client.example";

async function withPeers(profile, inspect) {
  const raw = profile === "raw_quic";
  const listener = raw ? await addon.bindRawQuic(bind) : await addon.bindWebTransport({
    ...bind, profile, authorityHost: bind.host, allowedOrigins: [origin],
  });
  let client, server;
  try {
    const { host, port } = listener.address();
    const accepting = listener.accept();
    const dialing = raw ? addon.connectRawQuic({ ...dial, host, port, serverName: "localhost" }) :
      addon.connectWebTransport({ ...dial, profile, origin, url: `https://${host}:${port}/flowersec/webtransport/v5/tunnel` });
    [client, server] = await Promise.all([dialing.result(), accepting.result()]);
    await inspect(client, server);
  } finally {
    client?.abort();
    server?.abort();
    await listener.close();
  }
}

for (const profile of ["raw_quic", "draft02", "native_h3"]) {
  for (const [code, reason, expected] of [[1, "session closed", true], [7, "session closed", false], [1, "session closed\0", false]]) {
    test(`${profile} remote close ${code}/${JSON.stringify(reason)} returns ${expected}`, { timeout: 10_000 }, async () => {
      await withPeers(profile, async (client, server) => {
        const first = client.waitRemoteSessionClose();
        const second = client.waitRemoteSessionClose();
        await server.close(code, reason);
        assert.deepEqual(await Promise.all([first, second, client.waitTermination()]), [expected, expected, undefined]);
        assert.equal(await client.waitRemoteSessionClose(), expected);
        assert.equal(await server.waitRemoteSessionClose(), false);
      });
    });
  }
}

for (const profile of ["draft02", "native_h3"]) {
  test(`${profile} local shutdown and default peer close are not relay confirmation`, { timeout: 10_000 }, async () => {
    await withPeers(profile, async (client, server) => {
      const remoteClose = client.waitRemoteSessionClose();
      await server.close();
      assert.deepEqual(await Promise.all([remoteClose, client.waitTermination()]), [false, undefined]);
      assert.equal(await client.waitRemoteSessionClose(), false);
      assert.equal(await server.waitRemoteSessionClose(), false);
    });
  });
}
