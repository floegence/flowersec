#!/usr/bin/env node
// Flowersec demos dev server:
// - Starts the demo services (controlplane + tunnel + server endpoint + direct demo)
// - Serves the static browser demos from the bundle/repo root
// - Exposes a same-origin JSON API so browser demos can fetch grants without manual copy/paste

import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(scriptDir, "../..");
const binDir = path.join(rootDir, "bin");

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 5173;
const DEFAULT_ORIGIN_HOST = "127.0.0.1";
const DEFAULT_TUNNEL_URL = "ws://127.0.0.1:8080/ws";

function usage() {
  return `
Usage:
  node ./examples/ts/dev-server.mjs [flags]

Starts the Flowersec demo services and serves the browser demos.

Flags:
  --host <ip>           HTTP listen host for the dev server (default: ${DEFAULT_HOST})
  --port <port>         HTTP listen port for the dev server (default: ${DEFAULT_PORT})
  --origin <origin>     Origin allow-list value to pass to tunnel/direct demos (default: http://${DEFAULT_ORIGIN_HOST}:<port>)
  --tunnel-url <wsurl>  Tunnel WS URL embedded into channel grants (default: ${DEFAULT_TUNNEL_URL})
  --no-direct           Do not start the direct demo server
  --no-tunnel           Do not start the tunnel stack (controlplane+tunnel+server-endpoint)
  -h, --help            Show this help
`.trim();
}

function parseArgs(argv) {
  const out = {
    host: DEFAULT_HOST,
    port: DEFAULT_PORT,
    origin: undefined,
    tunnelUrl: DEFAULT_TUNNEL_URL,
    startDirect: true,
    startTunnel: true,
    help: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") {
      out.help = true;
      continue;
    }
    if (a === "--no-direct") {
      out.startDirect = false;
      continue;
    }
    if (a === "--no-tunnel") {
      out.startTunnel = false;
      continue;
    }
    const readValue = () => {
      const v = argv[i + 1];
      if (v == null || v.startsWith("-")) throw new Error(`missing value for ${a}`);
      i++;
      return v;
    };
    if (a === "--host") {
      out.host = readValue();
      continue;
    }
    if (a === "--port") {
      const v = Number(readValue());
      if (!Number.isFinite(v) || !Number.isInteger(v) || v <= 0 || v > 65535) throw new Error(`invalid --port: ${v}`);
      out.port = v;
      continue;
    }
    if (a === "--origin") {
      out.origin = readValue();
      continue;
    }
    if (a === "--tunnel-url") {
      out.tunnelUrl = readValue();
      continue;
    }
    throw new Error(`unknown flag: ${a}`);
  }
  if (out.origin == null || out.origin === "") {
    out.origin = `http://${DEFAULT_ORIGIN_HOST}:${out.port}`;
  }
  return out;
}

function exeName(base) {
  return process.platform === "win32" ? `${base}.exe` : base;
}

function resolveBin(base) {
  return path.join(binDir, exeName(base));
}

function logErr(line) {
  process.stderr.write(line.endsWith("\n") ? line : `${line}\n`);
}

function prefixLines(stream, prefix) {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (d) => {
    buf += d;
    for (;;) {
      const i = buf.indexOf("\n");
      if (i < 0) break;
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      logErr(`${prefix}${line}`);
    }
  });
  stream.on("end", () => {
    if (buf !== "") logErr(`${prefix}${buf}`);
  });
}

async function waitForFirstStdoutLine(proc, label, timeoutMs) {
  if (!proc.stdout) throw new Error(`${label}: missing stdout`);
  let buf = "";
  proc.stdout.setEncoding("utf8");
  return await new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      cleanup();
      reject(new Error(`${label}: timeout waiting for ready JSON`));
    }, timeoutMs);
    t.unref?.();

    const onExit = (code, signal) => {
      cleanup();
      reject(new Error(`${label}: exited before ready (code=${code} signal=${signal ?? "none"})`));
    };
    const onData = (d) => {
      buf += d;
      const i = buf.indexOf("\n");
      if (i < 0) return;
      const line = buf.slice(0, i).trim();
      const rest = buf.slice(i + 1);
      cleanup();
      proc.stdout.off("data", onData);
      // Keep draining any further stdout to stderr to avoid backpressure.
      if (rest !== "") logErr(`[${label}:stdout] ${rest.trimEnd()}`);
      prefixLines(proc.stdout, `[${label}:stdout] `);
      resolve(line);
    };
    const cleanup = () => {
      clearTimeout(t);
      proc.off("exit", onExit);
      proc.stdout?.off("data", onData);
    };
    proc.on("exit", onExit);
    proc.stdout.on("data", onData);
  });
}

async function spawnJSONReadyProcess(label, spec, opts = {}) {
  const p = spawn(spec.cmd, spec.args, {
    cwd: spec.cwd,
    env: spec.env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  if (!p.pid) throw new Error(`${label}: failed to start`);

  if (p.stderr) prefixLines(p.stderr, `[${label}] `);

  if (opts.stdinText != null) {
    p.stdin.write(opts.stdinText);
    p.stdin.end();
  }

  const line = await waitForFirstStdoutLine(p, label, opts.readyTimeoutMs ?? 20000);
  let obj;
  try {
    obj = JSON.parse(line);
  } catch (e) {
    throw new Error(`${label}: invalid ready JSON: ${line}`);
  }
  return { proc: p, ready: obj };
}

function resolveRunner(binBase, goRun) {
  const binPath = resolveBin(binBase);
  if (fs.existsSync(binPath)) {
    return { cmd: binPath, args: [] };
  }
  // Fallback for repository clones: use go run when the demo bundle binaries are not present.
  return goRun;
}

function serveFile(res, absPath) {
  const ext = path.extname(absPath).toLowerCase();
  const ct =
    ext === ".html"
      ? "text/html; charset=utf-8"
      : ext === ".js" || ext === ".mjs"
        ? "text/javascript; charset=utf-8"
        : ext === ".css"
          ? "text/css; charset=utf-8"
          : ext === ".json"
            ? "application/json; charset=utf-8"
            : ext === ".svg"
              ? "image/svg+xml"
              : ext === ".png"
                ? "image/png"
                : ext === ".ico"
                  ? "image/x-icon"
                  : "application/octet-stream";
  res.writeHead(200, { "content-type": ct });
  fs.createReadStream(absPath).pipe(res);
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv);
  } catch (e) {
    logErr(String(e?.message ?? e));
    logErr("");
    logErr(usage());
    process.exit(2);
    return;
  }
  if (args.help) {
    process.stdout.write(usage() + "\n");
    return;
  }

  const origin = args.origin;
  const browserTunnelURL = `${origin}/examples/ts/browser-tunnel/`;
  const browserDirectURL = `${origin}/examples/ts/browser-direct/`;

  const procs = [];
  const killAll = async () => {
    for (const p of procs) {
      try {
        p.kill("SIGTERM");
      } catch {
        // ignore
      }
    }
    await Promise.allSettled(
      procs.map((p) => (p.exitCode != null || p.signalCode != null ? Promise.resolve() : once(p, "exit")))
    );
  };
  const onSignal = async (sig) => {
    logErr(`[dev-server] received ${sig}, shutting down...`);
    await killAll();
    process.exit(0);
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  let controlplane = null;
  let tunnel = null;
  let serverEndpoint = null;
  let direct = null;

  if (args.startTunnel) {
    logErr("[dev-server] starting controlplane-demo...");
    const controlplaneRunner = resolveRunner("flowersec-controlplane-demo", {
      cmd: "go",
      cwd: path.join(rootDir, "examples"),
      args: ["run", "./go/controlplane_demo"],
    });
    const cp = await spawnJSONReadyProcess(
      "controlplane-demo",
      {
        ...controlplaneRunner,
        args: [...controlplaneRunner.args, "--listen", "127.0.0.1:0", "--tunnel-url", args.tunnelUrl],
      },
      { readyTimeoutMs: 20000 }
    );
    procs.push(cp.proc);
    controlplane = cp.ready;

    logErr("[dev-server] starting flowersec-tunnel...");
    const tunnelRunner = resolveRunner("flowersec-tunnel", {
      cmd: "go",
      cwd: path.join(rootDir, "flowersec-go"),
      args: ["run", "./cmd/flowersec-tunnel"],
    });
    const env = {
      ...process.env,
      FSEC_TUNNEL_ALLOW_ORIGIN: origin,
      FSEC_TUNNEL_ISSUER_KEYS_FILE: controlplane.issuer_keys_file,
      FSEC_TUNNEL_AUD: controlplane.tunnel_audience,
      FSEC_TUNNEL_ISS: controlplane.tunnel_issuer,
      FSEC_TUNNEL_LISTEN: controlplane.tunnel_listen,
      FSEC_TUNNEL_WS_PATH: controlplane.tunnel_ws_path,
    };
    const t = await spawnJSONReadyProcess("tunnel", { ...tunnelRunner, env }, { readyTimeoutMs: 20000 });
    procs.push(t.proc);
    tunnel = t.ready;

    logErr("[dev-server] starting server-endpoint-demo...");
    const serverEndpointRunner = resolveRunner("flowersec-server-endpoint-demo", {
      cmd: "go",
      cwd: path.join(rootDir, "examples"),
      args: ["run", "./go/server_endpoint"],
    });
    const se = await spawnJSONReadyProcess(
      "server-endpoint-demo",
      {
        ...serverEndpointRunner,
        env: { ...process.env, FSEC_ORIGIN: origin },
      },
      { stdinText: JSON.stringify(controlplane) + "\n", readyTimeoutMs: 20000 }
    );
    procs.push(se.proc);
    serverEndpoint = se.ready;
  }

  if (args.startDirect) {
    logErr("[dev-server] starting direct-demo...");
    const directRunner = resolveRunner("flowersec-direct-demo", {
      cmd: "go",
      cwd: path.join(rootDir, "examples"),
      args: ["run", "./go/direct_demo"],
    });
    const d = await spawnJSONReadyProcess(
      "direct-demo",
      {
        ...directRunner,
        args: [...directRunner.args, "--allow-origin", origin],
      },
      { readyTimeoutMs: 20000 }
    );
    procs.push(d.proc);
    direct = d.ready;
  }

  const devServer = http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url ?? "/", `http://${args.host}:${args.port}`);
      if (u.pathname === "/__demo/status") {
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        res.end(
          JSON.stringify({
            status: "ready",
            origin,
            browser_tunnel_url: browserTunnelURL,
            browser_direct_url: browserDirectURL,
            ...(controlplane != null ? { controlplane } : {}),
            ...(tunnel != null ? { tunnel } : {}),
            ...(serverEndpoint != null ? { server_endpoint: serverEndpoint } : {}),
            ...(direct != null ? { direct } : {}),
          })
        );
        return;
      }
      if (u.pathname === "/__demo/channel/init") {
        if (controlplane == null || typeof controlplane.controlplane_http_url !== "string" || controlplane.controlplane_http_url === "") {
          res.writeHead(503, { "content-type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ error: "tunnel stack not started" }));
          return;
        }
        if (req.method !== "POST") {
          res.writeHead(405, { "content-type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ error: "method not allowed" }));
          return;
        }
        const body = await readBody(req, 8 * 1024);
        const url = new URL("/v1/channel/init", controlplane.controlplane_http_url);
        const resp = await fetch(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: body ?? "{}",
        });
        const text = await resp.text();
        res.writeHead(resp.status, { "content-type": resp.headers.get("content-type") ?? "application/json; charset=utf-8" });
        res.end(text);
        return;
      }
      if (u.pathname === "/__demo/direct/info") {
        if (direct == null) {
          res.writeHead(503, { "content-type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ error: "direct demo not started" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(direct));
        return;
      }
      if (u.pathname.startsWith("/__demo/")) {
        res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "not found" }));
        return;
      }

      // Static file server rooted at the demo bundle/repo root.
      // This allows running browser demos without an extra python/http server.
      const rel = decodeURIComponent(u.pathname);
      const abs = safeResolve(rootDir, rel);
      if (abs == null) {
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
        res.end("bad request");
        return;
      }
      const st = fs.statSync(abs, { throwIfNoEntry: false });
      if (!st) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        res.end("not found");
        return;
      }
      if (st.isDirectory()) {
        const indexPath = path.join(abs, "index.html");
        const st2 = fs.statSync(indexPath, { throwIfNoEntry: false });
        if (!st2 || !st2.isFile()) {
          res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
          res.end("directory listing disabled");
          return;
        }
        serveFile(res, indexPath);
        return;
      }
      if (!st.isFile()) {
        res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
        res.end("forbidden");
        return;
      }
      serveFile(res, abs);
    } catch (e) {
      res.writeHead(500, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ error: "internal error" }));
      logErr(`[dev-server] request failed: ${String(e?.stack ?? e)}`);
    }
  });

  devServer.listen(args.port, args.host, () => {
    const ready = {
      status: "ready",
      origin,
      browser_tunnel_url: browserTunnelURL,
      browser_direct_url: browserDirectURL,
    };
    process.stdout.write(JSON.stringify(ready) + "\n");
    logErr(`[dev-server] ready: ${browserTunnelURL} (tunnel), ${browserDirectURL} (direct)`);
  });

  devServer.on("error", async (err) => {
    logErr(`[dev-server] listen error: ${String(err)}`);
    await killAll();
    process.exit(1);
  });
}

function safeResolve(root, pathname) {
  // Prevent path traversal.
  const clean = pathname.startsWith("/") ? pathname.slice(1) : pathname;
  const joined = path.resolve(root, clean);
  const rootPrefix = root.endsWith(path.sep) ? root : root + path.sep;
  if (joined !== root && !joined.startsWith(rootPrefix)) return null;
  return joined;
}

async function readBody(req, limitBytes) {
  const chunks = [];
  let total = 0;
  for await (const c of req) {
    const b = Buffer.isBuffer(c) ? c : Buffer.from(c);
    total += b.length;
    if (total > limitBytes) throw new Error("request too large");
    chunks.push(b);
  }
  if (chunks.length === 0) return null;
  return Buffer.concat(chunks).toString("utf8");
}

main().catch((e) => {
  logErr(`[dev-server] fatal: ${String(e?.stack ?? e)}`);
  process.exit(1);
});
