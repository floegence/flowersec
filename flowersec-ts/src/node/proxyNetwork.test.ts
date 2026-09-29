import { once } from "node:events";
import { createServer, type AddressInfo } from "node:net";
import { afterEach, expect, test, vi } from "vitest";

import { ProxyNetworkPolicy, proxyUpstreamHost } from "./proxyNetwork.js";

const resolver = vi.hoisted(() => vi.fn());
vi.mock("node:dns/promises", async importOriginal => ({ ...await importOriginal<object>(), lookup: resolver }));
afterEach(() => resolver.mockReset());

test("rejects numeric rewrites and requires independent hostname ranges", () => {
  for (const host of ["127.1", "0177.0.0.1", "2130706433", "0x7f.0.0.1", "example.test.", "a..test", "[fe80::1%en0]"]) {
    expect(() => proxyUpstreamHost(`http://${host}:8080`)).toThrow();
  }
  expect(proxyUpstreamHost("http://[::1]:8080")).toBe("::1");
  expect(() => new ProxyNetworkPolicy("proxy.test", 8080, [], 1)).toThrow();
  for (const range of ["192.0.2.1/24", "::ffff:127.0.0.1/95", "0.0.0.0/033", "fe80::1%en0"]) {
    expect(() => new ProxyNetworkPolicy("proxy.test", 8080, [range], 1)).toThrow();
  }
  expect(() => new ProxyNetworkPolicy("127.0.0.1", 8080, ["192.0.2.0/24"], 1)).toThrow();
  expect(() => new ProxyNetworkPolicy("0.0.0.0", 8080, [], 1)).toThrow();
});

test.each([
  ["127.0.0.1", "192.0.2.1"], ["127.0.0.1", "0.0.0.0"], ["127.0.0.1", "224.0.0.1"],
  ["127.0.0.1", "fe80::1%en0"], Array<string>(65).fill("127.0.0.1"), [],
])("rejects the whole DNS answer before dialing: %j", async (...addresses) => {
  let connections = 0;
  const listener = createServer(socket => { connections++; socket.destroy(); });
  listener.listen(0, "127.0.0.1"); await once(listener, "listening");
  const policy = new ProxyNetworkPolicy("proxy.test", (listener.address() as AddressInfo).port, ["127.0.0.1"], 1);
  resolver.mockResolvedValue(addresses.map(address => ({ address, family: 4 })));
  try {
    await expect(policy.connect(false, new AbortController().signal)).rejects.toThrow();
    expect(connections).toBe(0);
  } finally { await policy.close(); await new Promise<void>(resolve => listener.close(() => resolve())); }
});

test("retains resolver tails and prevents canceled answers from dialing", async () => {
  let finish!: (value: { address: string; family: number }[]) => void;
  resolver.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const policy = new ProxyNetworkPolicy("proxy.test", 8080, ["127.0.0.1"], 1);
  const controller = new AbortController(), pending = policy.connect(false, controller.signal);
  controller.abort(new Error("caller stopped"));
  await expect(pending).rejects.toThrow("caller stopped");
  await expect(policy.connect(false, new AbortController().signal)).rejects.toThrow("capacity");
  let cleaned = false;
  const closing = policy.close().then(() => { cleaned = true; });
  await Promise.resolve(); expect(cleaned).toBe(false);
  finish([{ address: "127.0.0.1", family: 4 }]);
  await closing;
  expect(resolver).toHaveBeenCalledTimes(1);
});

test("normalizes mapped DNS addresses and checks the actual numeric peer", async () => {
  const listener = createServer(socket => socket.resume());
  listener.listen(0, "127.0.0.1"); await once(listener, "listening");
  const port = (listener.address() as AddressInfo).port;
  resolver.mockResolvedValue([{ address: "::ffff:127.0.0.1", family: 6 }]);
  const policy = new ProxyNetworkPolicy("proxy.test", port, ["127.0.0.1"], 1);
  try {
    const connection = await policy.connect(false, new AbortController().signal);
    expect(connection.socket.remoteAddress).toBe("127.0.0.1");
    expect(connection.socket.remotePort).toBe(port);
    expect(resolver).toHaveBeenCalledTimes(1);
    await connection.close();
  } finally { await policy.close(); await new Promise<void>(resolve => listener.close(() => resolve())); }
});

test("TLS retains the logical identity and frozen roots through numeric dialing", async () => {
  const { createServer: createTLS, getCACertificates, setDefaultCACertificates } = await import("node:tls");
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = mkdtempSync(join(tmpdir(), "flowersec-proxy-network-"));
  const roots = getCACertificates("default");
  let listener: ReturnType<typeof createTLS> | undefined;
  let policy: ProxyNetworkPolicy | undefined, wrongIdentity: ProxyNetworkPolicy | undefined;
  try {
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
      "-keyout", join(directory, "key.pem"), "-out", join(directory, "cert.pem"), "-days", "1", "-subj", "/CN=localhost",
      "-addext", "subjectAltName=DNS:localhost", "-addext", "extendedKeyUsage=serverAuth"], { stdio: "ignore" });
    const cert = readFileSync(join(directory, "cert.pem"), "utf8");
    listener = createTLS({ key: readFileSync(join(directory, "key.pem")), cert }, socket => socket.resume());
    listener.on("tlsClientError", () => undefined);
    listener.listen(0, "127.0.0.1"); await once(listener, "listening");
    const port = (listener.address() as AddressInfo).port;
    setDefaultCACertificates([cert]);
    policy = new ProxyNetworkPolicy("localhost", port, ["127.0.0.1"], 1, true);
    wrongIdentity = new ProxyNetworkPolicy("wrong.test", port, ["127.0.0.1"], 1, true);
    setDefaultCACertificates(roots);
    resolver.mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);
    const connection = await policy.connect(true, new AbortController().signal);
    expect(connection.socket.remoteAddress).toBe("127.0.0.1");
    await connection.close();
    await expect(wrongIdentity.connect(true, new AbortController().signal)).rejects.toThrow(/certificate|hostname|altnames/iu);
  } finally {
    setDefaultCACertificates(roots);
    await policy?.close(); await wrongIdentity?.close();
    if (listener !== undefined) await new Promise<void>(resolve => listener!.close(() => resolve()));
    rmSync(directory, { recursive: true, force: true });
  }
});
