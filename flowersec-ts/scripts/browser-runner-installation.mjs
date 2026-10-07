import { DatabaseSync } from "node:sqlite";
import { createHash, randomBytes, timingSafeEqual, constants } from "node:crypto";
import { isIP } from "node:net";
import { promises as fs, existsSync } from "node:fs";
import path from "node:path";
import https from "node:https";

const maximum = 1 << 20;
const digest = (text) => createHash("sha256").update(text).digest("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
function decode(text, bound, exact) {
  if (typeof text !== "string" || text.length > Math.ceil(bound / 3) * 4) throw new Error("invalid installation bytes");
  const bytes = Buffer.from(text, "base64");
  if (bytes.length === 0 || bytes.length > bound || exact !== undefined && bytes.length !== exact || b64(bytes) !== text) throw new Error("invalid installation bytes");
  return bytes;
}
function integer(value) { if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 0xffffffffffffffffn) throw new Error("invalid history epoch"); return value; }

/** The host file is installed by the original Go deployment owner before any
 * acquisition publication. No enclosed credential selects a root, key, clock,
 * carrier declaration or history identity. History persists outside Chromium's
 * profile and module origin, including after renderer loss or IDB eviction. */
export async function createBrowserRunnerHost(manifestPath, historyDirectory) {
  if (!path.isAbsolute(manifestPath) || !path.isAbsolute(historyDirectory)) throw new Error("runner installation and history paths must be absolute");
  await fs.mkdir(historyDirectory, { recursive: true, mode: 0o700 });
  const historyPath = path.join(historyDirectory, "browser-history.sqlite");
  if (!existsSync(historyPath)) throw new Error("original host history must be independently provisioned");
  const disk = new DatabaseSync(historyPath);
  disk.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000");
  disk.exec("CREATE TABLE IF NOT EXISTS stores (id TEXT PRIMARY KEY, authority TEXT NOT NULL, generation TEXT NOT NULL, material TEXT NOT NULL UNIQUE, epoch TEXT NOT NULL, phase INTEGER NOT NULL, retired INTEGER NOT NULL DEFAULT 0)");
  disk.exec("CREATE TABLE IF NOT EXISTS spend (authority TEXT NOT NULL, lease BLOB NOT NULL, store TEXT NOT NULL, projection BLOB NOT NULL, PRIMARY KEY(authority, lease))");
  const capabilities = new Map(); let origin; let runtime; let closed = false; let closing;
  const stop = new AbortController(), operations = new Set(), requests = new Set();
  const assertOpen = () => { if (closed) throw new Error("original browser host is closed"); };
  const track = (operation) => {
    if (closed) return Promise.reject(new Error("original browser host is closed"));
    const pending = Promise.resolve().then(operation);
    operations.add(pending);
    void pending.then(() => operations.delete(pending), () => operations.delete(pending));
    return pending;
  };
  const lookup = (capability) => {
    if (typeof capability !== "string") throw new Error("host capability missing");
    const entry = capabilities.get(capability); if (entry === undefined) throw new Error("host installation unavailable"); return entry;
  };
  const transaction = (run) => { disk.exec("BEGIN IMMEDIATE"); try { const result = run(); disk.exec("COMMIT"); return result; } catch (error) { disk.exec("ROLLBACK"); throw error; } };
  const host = {
    setOrigin(value) { assertOpen(); if (origin !== undefined) throw new Error("host origin already installed"); origin = value; },
    async publishRuntime(observed) {
      assertOpen();
      if (runtime !== undefined || origin === undefined || typeof observed.userAgent !== "string" || observed.userAgent.length > 1024) throw new Error("original runtime observation unavailable");
      runtime = { schema_version: 1, runtime_id: randomBytes(32).toString("hex"), origin, ...observed };
      const staged = path.join(historyDirectory, `runtime-${runtime.runtime_id}.json`), destination = path.join(historyDirectory, "browser-runtime.json");
      try { const file = await fs.open(staged, "wx", 0o600); try { await file.writeFile(JSON.stringify(runtime)); await file.sync(); } finally { await file.close(); } assertOpen(); await fs.rename(staged, destination); }
      finally { await fs.rm(staged, { force: true }); }
    },
    async install(raw, options) {
      assertOpen(); options.signal?.throwIfAborted();
      if (typeof raw !== "string" || Buffer.byteLength(raw) > maximum) throw new Error("material exceeds installation bound");
      const source = await fs.readFile(manifestPath, { signal: options.signal }); assertOpen(); options.signal?.throwIfAborted(); if (source.length > 16 * maximum) throw new Error("host installation exceeds bound");
      const manifest = JSON.parse(source.toString("utf8"));
      const identity = disk.prepare("SELECT identity FROM history_identity WHERE id=1").get();
      if (identity === undefined || manifest.history_identity !== identity.identity) throw new Error("host history differs from independent installation");
      const materialHash = digest(raw), config = manifest.installations?.[materialHash];
      if (manifest.schema_version !== 1 || config === undefined || config.material_sha256 !== materialHash || config.application_origin !== origin || runtime === undefined || config.runtime_id !== runtime.runtime_id) throw new Error("material has no original host installation");
      if (typeof config.trust_pem !== "string" || config.trust_pem.length === 0 || config.trust_pem.length > maximum || typeof config.spend_authority !== "string" || config.deployment?.applicationOrigin !== origin || config.carrier === "webtransport" && config.deployment?.userAgent !== runtime.userAgent) throw new Error("original bootstrap trust or spend authority missing");
      const material = JSON.parse(raw); if (material.wire_revision !== 4 || material.source !== "preauthorized_pool" || material.role !== 0) throw new Error("runner requires original current pool material");
      // Host installation owns keys and namespace declarations separately from
      // acquisition. Exact copies in the Go material must agree before import.
      if (material.identity_seed !== config.identity_seed || material.dh_seed !== config.dh_seed || JSON.stringify(material.namespaces) !== JSON.stringify(config.namespaces)) throw new Error("acquisition differs from independent host installation");
      decode(config.identity_seed, 32, 32); decode(config.dh_seed, 32, 32);
      const id = randomBytes(32).toString("hex"), capability = randomBytes(32).toString("hex");
      const { pool_server_allow: allow, ...publicConfig } = config;
      if (material.tunnels != null && !Array.isArray(material.tunnels)) throw new Error("invalid original tunnel installation");
      if ((material.tunnels?.length ?? 0) > 0) {
        const installed = allow?.installation, binding = allow?.binding, transport = installed?.server_allow;
        if (installed?.wire_revision !== 4 || installed.tenant !== config.policy.tenant || installed.audience !== config.policy.audience ||
          transport === undefined || binding?.endpoint !== transport.endpoint || "clientCertificateDER" in transport || BigInt(integer(transport.workMS)) < 1n || BigInt(transport.workMS) > 2000n) throw new Error("original pool Allow installation missing");
        const url = new URL(transport.endpoint);
        if (url.protocol !== "https:" || url.pathname !== "/tunnel/server-allow" || url.username || url.password || url.hash || url.search || isIP(url.hostname.replace(/^\[|\]$/g, "")) === 0 || !url.port) throw new Error("invalid installed Allow endpoint");
        for (const value of [transport.tls?.certificatePEM, transport.tls?.privateKeyPEM, transport.tls?.trustPEM]) if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value) > 262144) throw new Error("original Allow TLS identity missing");
        for (const value of [binding.recipient, binding.incarnation]) { const fixed = decode(value, 16, 16); try { if (!fixed.some(byte => byte !== 0)) throw new Error("empty original Allow binding"); } finally { fixed.fill(0); } }
      } else if (allow !== undefined) throw new Error("direct installation cannot publish tunnel Allow");
      transaction(() => disk.prepare("INSERT INTO stores(id,authority,generation,material,epoch,phase) VALUES(?,?,?,?,?,0)").run(id, config.spend_authority, "1", materialHash, "0"));
      const entry = { id, capability, config, allowUsed: false }; capabilities.set(capability, entry);
      return { ...publicConfig, ...(allow === undefined ? {} : { pool_server_allow: { endpoint: "/runner/server-allow", recipient: allow.binding.recipient, incarnation: allow.binding.incarnation } }),
        database_name: `flowersec-runner-${id}`, store_id: b64(Buffer.from(id, "hex")), store_generation: "1", host_capability: capability, host_endpoint: "/runner/history", bootstrap_endpoint: "/runner/bootstrap" };
    },
    async handle(request, response) {
      if (!request.url?.startsWith("/runner/")) return false;
      try {
        if (request.method !== "POST" || request.headers.origin !== origin || request.headers["content-type"] !== "application/json") throw new Error("host request origin mismatch");
        const chunks = []; let size = 0;
        for await (const chunk of request) { size += chunk.length; if (size > maximum) throw new Error("host request exceeds bound"); chunks.push(chunk); }
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")), entry = lookup(body.capability);
        if (request.url === "/runner/server-allow") {
          const installed = entry.config.pool_server_allow?.installation.server_allow;
          if (installed === undefined || entry.allowUsed || Object.keys(body).length !== 2 || request.aborted || response.destroyed) throw new Error("original Allow unavailable");
          const wire = decode(body.wire, 66560); entry.allowUsed = true;
          try {
            // Only the original browser Connect submits these bytes. The host
            // is an authenticated transport; no journal query can invoke it.
            await serverAllowReply(installed, wire, request, response, stop.signal); assertOpen();
            response.writeHead(200, { "content-type": "application/cbor", "content-length": "1", "cache-control": "no-store" }); response.end(Buffer.from([0xf5])); return true;
          } finally { wire.fill(0); }
        }
        if (request.url === "/runner/bootstrap") {
          const namespace = entry.config.namespaces[body.index]; if (namespace === undefined) throw new Error("namespace not installed");
          const nonce = decode(body.nonce, 32, 32), url = new URL(namespace.bootstrap_url);
          if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) throw new Error("invalid installed bootstrap URL");
          const query = JSON.stringify({ tenant: namespace.tenant, authority: namespace.authority, nonce: b64(nonce) });
          const reply = await bootstrapReply(url, entry.config.trust_pem, query, request, response, stop.signal);
          assertOpen();
          const parsed = JSON.parse(reply); decode(parsed.response, 65536); decode(parsed.state, 65536); response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); response.end(reply); return true;
        }
        if (request.url !== "/runner/history") throw new Error("unknown host interface");
        transaction(() => {
          const store = disk.prepare("SELECT * FROM stores WHERE id=?").get(entry.id);
          if (store === undefined || store.retired || body.authority !== store.authority || body.store_id !== b64(Buffer.from(entry.id, "hex")) || body.generation !== store.generation) throw new Error("history identity mismatch");
          const epoch = integer(body.epoch);
          if (body.action === "check") {
            if (body.provisioning) {
              const valid = store.phase === 0 && epoch === "0" || store.phase === 1 && epoch === "1";
              if (!valid) throw new Error("history already provisioned");
              disk.prepare("UPDATE stores SET phase=phase+1,epoch=? WHERE id=?").run(epoch, entry.id);
            } else if (store.phase !== 2 || epoch !== store.epoch) throw new Error("history fenced");
          } else if (body.action === "reserve") {
            if (store.phase !== 2 || epoch !== store.epoch) throw new Error("history fenced");
            const count = disk.prepare("SELECT count(*) AS count FROM spend WHERE store=?").get(entry.id).count;
            if (body.count !== count) throw new Error("IDB history differs from original host journal");
            disk.prepare("INSERT INTO spend(authority,lease,store,projection) VALUES(?,?,?,?)").run(store.authority, decode(body.key, 161), entry.id, decode(body.projection, 65536));
          } else if (body.action === "record") {
            const row = disk.prepare("SELECT projection FROM spend WHERE authority=? AND lease=? AND store=?").get(store.authority, decode(body.key, 161), entry.id);
            const projection = decode(body.projection, 65536);
            if (row === undefined || row.projection.length !== projection.length || !timingSafeEqual(row.projection, projection)) throw new Error("IDB record differs from original host journal");
          } else if (body.action === "records") {
            if (body.count !== disk.prepare("SELECT count(*) AS count FROM spend WHERE store=?").get(entry.id).count) throw new Error("IDB history incomplete");
          } else if (body.action === "retire") {
            disk.prepare("UPDATE stores SET retired=1 WHERE id=?").run(entry.id);
          } else throw new Error("unknown history operation");
        });
        response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" }); response.end('{"status":"committed"}');
      } catch { response.writeHead(409, { "content-type": "application/json", "cache-control": "no-store" }); response.end('{"error":"history_unavailable"}'); }
      return true;
    },
    close() {
      if (closing !== undefined) return closing;
      closed = true;
      stop.abort(new Error("original browser host closed"));
      for (const request of requests) request.destroy();
      closing = (async () => {
        await Promise.allSettled(Array.from(operations));
        capabilities.clear(); disk.close();
      })();
      return closing;
    },
  };
  return Object.freeze({
    ...host,
    publishRuntime: (observed) => track(() => host.publishRuntime(observed)),
    install: (raw, options = {}) => track(() => host.install(raw, options)),
    handle(request, response) {
      if (!request.url?.startsWith("/runner/")) return Promise.resolve(false);
      return track(async () => {
        requests.add(request);
        try { assertOpen(); return await host.handle(request, response); }
        finally { requests.delete(request); }
      });
    },
  });
}

async function serverAllowReply(installed, wire, request, response, hostSignal) {
  const controller = new AbortController(), stop = () => controller.abort();
  const browserStopped = () => { if (!response.writableEnded) stop(); };
  hostSignal.addEventListener("abort", stop, { once: true }); request.once("aborted", browserStopped); response.once("close", browserStopped);
  if (hostSignal.aborted || request.aborted || response.destroyed) stop();
  const timer = setTimeout(stop, Number(installed.workMS)); let remote, nativeEnd, read;
  try {
    controller.signal.throwIfAborted();
    await new Promise((resolve, reject) => {
      remote = https.request(installed.endpoint, { method: "POST", agent: false, maxHeaderSize: 8192, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", ALPNProtocols: ["http/1.1"], secureOptions: constants.SSL_OP_NO_TICKET,
        rejectUnauthorized: true, cert: installed.tls.certificatePEM, key: installed.tls.privateKeyPEM, ca: installed.tls.trustPEM, signal: controller.signal,
        headers: { "content-type": "application/cbor", "content-length": wire.length, "connection": "close" } }, incoming => {
        read = (async () => {
          if (incoming.statusCode !== 200 || !incoming.socket.authorized || incoming.socket.getProtocol() !== "TLSv1.3") throw new Error("original Allow rejected");
          let type = false, length = false;
          for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
            const name = incoming.rawHeaders[index].toLowerCase(), value = incoming.rawHeaders[index + 1];
            if (name === "content-type") { if (type || value !== "application/cbor") throw new Error("invalid Allow response"); type = true; }
            if (name === "content-length") { if (length || value !== "1") throw new Error("invalid Allow response"); length = true; }
            if (["transfer-encoding", "content-encoding", "trailer"].includes(name)) throw new Error("invalid Allow response");
          }
          if (!type || !length) throw new Error("invalid Allow response"); let count = 0;
          for await (const chunk of incoming) { controller.signal.throwIfAborted(); if (chunk.length > 1 - count || chunk.length !== 0 && chunk[0] !== 0xf5) throw new Error("invalid Allow response"); count += chunk.length; }
          controller.signal.throwIfAborted(); if (count !== 1 || !incoming.complete) throw new Error("truncated Allow response");
        })(); void read.then(resolve, error => { incoming.destroy(); reject(error); });
      });
      nativeEnd = new Promise(resolve => { let assigned = false; remote.once("socket", socket => { assigned = true; socket.once("close", resolve); }); remote.once("close", () => { if (!assigned) resolve(); }); });
      remote.once("error", reject); controller.signal.throwIfAborted(); remote.end(wire);
    });
  } finally {
    clearTimeout(timer); controller.abort(); remote?.destroy(); await nativeEnd; await read?.catch(() => undefined);
    hostSignal.removeEventListener("abort", stop); request.removeListener("aborted", browserStopped); response.removeListener("close", browserStopped);
  }
}

async function bootstrapReply(url, trustPEM, query, request, response, hostSignal) {
  const controller = new AbortController();
  const abortFromHost = () => controller.abort(hostSignal.reason);
  const abortFromBrowser = () => { if (!response.writableEnded) controller.abort(new Error("original browser bootstrap canceled")); };
  hostSignal.addEventListener("abort", abortFromHost, { once: true });
  request.once("aborted", abortFromBrowser); response.once("close", abortFromBrowser);
  if (hostSignal.aborted) abortFromHost();
  if (request.aborted || response.destroyed) abortFromBrowser();
  let remote;
  let remoteClosed = Promise.resolve();
  const timer = setTimeout(() => controller.abort(new Error("bootstrap deadline exceeded")), 10000);
  try {
    controller.signal.throwIfAborted();
    return await new Promise((resolve, reject) => {
      remote = https.request(url, { method: "POST", ca: trustPEM, minVersion: "TLSv1.3", maxVersion: "TLSv1.3", agent: false, signal: controller.signal,
        headers: { "content-type": "application/json" } }, incoming => {
        const data = []; let count = 0;
        incoming.on("data", chunk => { count += chunk.length; if (count > maximum) incoming.destroy(new Error("bootstrap reply exceeds bound")); else data.push(chunk); });
        incoming.once("aborted", () => reject(new Error("bootstrap authority truncated reply")));
        incoming.once("error", reject);
        incoming.once("end", () => { if (incoming.statusCode !== 200 || !incoming.complete) reject(new Error("bootstrap authority refused or truncated")); else resolve(Buffer.concat(data).toString("utf8")); });
      });
      remoteClosed = new Promise(resolveClose => remote.once("close", resolveClose));
      remote.once("error", reject); remote.end(query);
    });
  } finally {
    clearTimeout(timer);
    controller.abort(new Error("original bootstrap request finished"));
    remote?.destroy();
    await remoteClosed;
    hostSignal.removeEventListener("abort", abortFromHost);
    request.removeListener("aborted", abortFromBrowser); response.removeListener("close", abortFromBrowser);
  }
}

/** Explicit deployment provisioning, never called by runner startup or
 * acquisition. The original Go owner pins the returned identity in the
 * independent installation file. Existing files are never initialized again. */
export async function provisionBrowserRunnerHistory(historyDirectory, identity) {
  if (!path.isAbsolute(historyDirectory) || typeof identity !== "string" || !/^[0-9a-f]{64}$/.test(identity)) throw new Error("invalid independent history installation");
  await fs.mkdir(historyDirectory, { recursive: true, mode: 0o700 });
  const file = path.join(historyDirectory, "browser-history.sqlite");
  const handle = await fs.open(file, "wx", 0o600); await handle.sync(); await handle.close();
  const disk = new DatabaseSync(file);
  try { disk.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL"); disk.exec("CREATE TABLE history_identity(id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL)"); disk.prepare("INSERT INTO history_identity(id,identity) VALUES(1,?)").run(identity); }
  finally { disk.close(); }
  const parent = await fs.open(historyDirectory, "r"); try { await parent.sync(); } finally { await parent.close(); }
}
