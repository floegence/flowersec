import { execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createHTTPSServer, get as httpsGet } from "node:https";
import { connect as connectTCP } from "node:net";
import { Duplex } from "node:stream";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, afterAll, describe, expect, test } from "vitest";
import { createConnectionPathAgent, openOwnedConnectionPath, type NodeConnectionPath } from "./connectionPath.js";
let directory: string, rootCertificate: Buffer, leafCertificate: Buffer, leafKey: Buffer;
describe("explicit Node HTTPS routes", () => {
  beforeAll(() => {
    directory = mkdtempSync(join(tmpdir(), "flowersec-path-tls-"));
    execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", join(directory,"key.pem"), "-out", join(directory,"cert.pem"), "-days","1", "-subj","/CN=localhost", "-addext","subjectAltName=DNS:localhost"], {stdio:"ignore"});
    rootCertificate = leafCertificate = readFileSync(join(directory,"cert.pem")); leafKey = readFileSync(join(directory,"key.pem"));
  });
  afterAll(() => rmSync(directory, {recursive:true,force:true}));
  test("uses the same path for HTTPS bootstrap without accepting TLS overrides", async () => {
    const server = createHTTPSServer({ cert: leafCertificate, key: leafKey }, (req, res) => {
      expect(req.headers.host).toBe("localhost:1");
      res.end("bootstrap");
    });
    const port = await listen(server);
    let routes = 0;
    const connectionPath: NodeConnectionPath = { connect: async ({ signal }) => { routes += 1; return connectTCP({ host: "127.0.0.1", port, signal }); } };
    const agent = createConnectionPathAgent({ connectionPath, ca: rootCertificate, connectTimeoutMs: 100 });
    const untrusted = createConnectionPathAgent({ connectionPath });
    const read = (selected: typeof agent, url = "https://localhost:1/"): Promise<string> => new Promise((resolve, reject) => {
      httpsGet(url, { agent: selected, rejectUnauthorized: false }, (res) => {
        let body = ""; res.on("data", (part) => { body += part; }); res.on("end", () => resolve(body));
      }).on("error", reject);
    });
    try {
      expect(await read(agent)).toBe("bootstrap");
      // Admission timeout cannot terminate an established reusable connection.
      await new Promise((resolve) => setTimeout(resolve, 130));
      expect(await read(agent)).toBe("bootstrap");
      expect(routes).toBe(1);
      await expect(read(untrusted)).rejects.toBeInstanceOf(Error);
      await expect(read(agent, "https://wrong.invalid:1/")).rejects.toMatchObject({ code: "ERR_TLS_CERT_ALTNAME_INVALID" });
    } finally { agent.destroy(); untrusted.destroy(); await closeServer(server); }
  });

  test("samples authenticated trust only after the explicit route is ready", async () => {
    const server = createHTTPSServer({ cert: leafCertificate, key: leafKey }, (_req, res) => res.end("refreshed"));
    const port = await listen(server);
    const roots: string[] = [];
    const agent = createConnectionPathAgent({ ca: roots, connectionPath: { connect: async () => {
      await new Promise(resolve => setImmediate(resolve));
      roots.splice(0, roots.length, rootCertificate);
      return connectTCP({ host: "127.0.0.1", port });
    } } });
    try {
      const body = await new Promise<string>((resolve, reject) => {
        httpsGet("https://localhost:1/", { agent }, res => {
          let text = ""; res.on("data", chunk => { text += chunk; });
          res.on("end", () => resolve(text)); res.once("error", reject);
        }).once("error", reject);
      });
      expect(body).toBe("refreshed");
    } finally { agent.destroy(); await closeServer(server); }
  });

  test("counts pending explicit routes against the HTTPS connection pool", async () => {
    const server = createHTTPSServer({ cert: leafCertificate, key: leafKey }, (_req, res) => res.end("bounded"));
    const port = await listen(server);
    let routes = 0;
    const agent = createConnectionPathAgent({ ca: rootCertificate, connectionPath: { connect: async () => {
      routes++;
      await new Promise(resolve => setTimeout(resolve, 20));
      return connectTCP({ host: "127.0.0.1", port });
    } } });
    agent.maxSockets = 2;
    agent.maxTotalSockets = 2;
    const read = (): Promise<string> => new Promise((resolve, reject) => {
      httpsGet("https://localhost:1/", { agent }, res => {
        let body = ""; res.on("data", part => { body += part; });
        res.on("end", () => resolve(body)); res.on("error", reject);
      }).on("error", reject);
    });
    try {
      expect(await Promise.all(Array.from({ length: 32 }, read))).toEqual(Array(32).fill("bounded"));
      expect(routes).toBeLessThanOrEqual(2);
    } finally { agent.destroy(); await closeServer(server); }
  });

  test("cancels pending HTTPS admission and destroys a late route", async () => {
    let deliver!: (stream: Duplex) => void;
    let attempted!: () => void;
    const started = new Promise<void>(resolve => { attempted = resolve; });
    const agent = createConnectionPathAgent({ connectionPath: { connect: async () => {
      attempted();
      return await new Promise<Duplex>(resolve => { deliver = resolve; });
    } } });
    const failed = Array.from({ length: 8 }, () => new Promise<Error>(resolve => {
      httpsGet("https://localhost:1/", { agent }).once("error", resolve);
    }));
    await started;
    agent.destroy();
    for (const error of await Promise.all(failed)) expect(error).toBeInstanceOf(Error);
    const late = new Duplex({ read() {}, write(_chunk, _encoding, done) { done(); } });
    deliver(late);
    await new Promise(resolve => setImmediate(resolve));
    expect(late.destroyed).toBe(true);
  });

  test("retains an admitted late route until cancellation cleanup actually completes", async () => {
    let deliver!: (stream: Duplex) => void;
    const cancel = new AbortController();
    const operation = openOwnedConnectionPath({ connect: async () => new Promise<Duplex>(resolve => { deliver = resolve; }) }, "localhost", 443, cancel.signal);
    let settled = false; void operation.catch(() => { settled = true; }); cancel.abort();
    await Promise.resolve(); expect(settled).toBe(false);
    const stream = new Duplex({read() {},write(_chunk,_encoding,done) {done();}}); deliver(stream);
    await expect(operation).rejects.toThrow("canceled"); expect(stream.closed).toBe(true);
  });
});
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
