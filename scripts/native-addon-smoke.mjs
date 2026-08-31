#!/usr/bin/env node
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const TEST_CERTIFICATE_DER = "MIIBvjCCAWOgAwIBAgIUN4shFZRsaT+JJ701zSpNVB4lIUMwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgxMjAzMjg1NloXDTM2MDgwOTAzMjg1NlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHEdVVZLIF45DYFqsBAUmPnWO64Go6R+pw3Mi9eIHphwoCAHL6JyHZufMZqGHccvoTbrDmYS4f7j3x72Y9Sb70qOBkjCBjzAdBgNVHQ4EFgQUix3PEaIuA4OxflJpuKZcxWmNY0owHwYDVR0jBBgwFoAUix3PEaIuA4OxflJpuKZcxWmNY0owDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQDq1Ik9VP3XDTTwuGupv65LRfGs1lgE1P79bPEmYGKz0gIhANnJYQXv/L+nDteil7cgxRhnIcJTvSIqQ9186Alh7WuF";
const TEST_PRIVATE_KEY_DER = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgK56d5JUnqxQLkkzNNJ45z0m3YUDYkyCRFBjcq/59FVmhRANCAAQcR1VVksgXjkNgWqwEBSY+dY7rgajpH6nDcyL14gemHCgIAcvonIdm58xmoYdxy+hNusOZhLh/uPfHvZj1JvvS";

const addonPath = process.env.FLOWERSEC_NATIVE_ADDON_PATH;
assert.ok(addonPath, "FLOWERSEC_NATIVE_ADDON_PATH is required");
const addon = createRequire(import.meta.url)(addonPath);
assert.equal(typeof addon.contractVersion, "function");
assert.equal(addon.contractVersion(), 3);
assert.equal(typeof addon.bindRawQuic, "function");
assert.equal(typeof addon.connectRawQuic, "function");
assert.equal("bindRawQuicV3" in addon, false);
assert.equal("connectRawQuicV3" in addon, false);

const certificateChainDer = [Buffer.from(TEST_CERTIFICATE_DER, "base64")];
const privateKeyDer = Buffer.from(TEST_PRIVATE_KEY_DER, "base64");
const listener = await addon.bindRawQuic({
  host: "127.0.0.1", port: 0, path: "direct", certificateChainDer, privateKeyDer,
  inboundBidirectionalStreamCapacity: 4, handshakeTimeoutMs: 2_000,
});
try {
  const accepting = listener.accept();
  const address = listener.address();
  const operation = addon.connectRawQuic({
    host: address.host, port: address.port, serverName: "localhost", path: "direct",
    trustRootsDer: certificateChainDer, inboundBidirectionalStreamCapacity: 4, handshakeTimeoutMs: 2_000,
  });
  const client = await operation.result();
  const server = await accepting.result();
  await Promise.all([client.close(), server.close()]);
  await Promise.all([client.waitTermination(), server.waitTermination()]);
} finally {
  await listener.close();
}
