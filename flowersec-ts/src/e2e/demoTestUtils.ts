import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { createExitPromise } from "./harnessProcess.js";
import { createLineReader, createTextBuffer, readJsonLine } from "./interopUtils.js";

export type HarnessReady = Readonly<{
  ws_url: string;
  grant_client: unknown;
  direct_info: unknown;
  controlplane_base_url: string;
  entry_ticket: string;
}>;

export type DirectDemoReady = Readonly<{
  ws_url: string;
  channel_id: string;
  e2ee_psk_b64u: string;
  default_suite: number;
  channel_init_expire_at_unix_s: number;
  example_type_ids?: Record<string, number>;
  example_stream_kinds?: Record<string, string>;
}>;

export type DevServerReady = Readonly<{
  status: string;
  origin: string;
  browser_tunnel_url: string;
  browser_direct_url: string;
  browser_proxy_sandbox_url: string;
  controlplane_http_url?: string;
}>;

export type StartedProcess<T> = Readonly<{
  proc: ChildProcess;
  ready: T;
  stderr: () => string;
  stop: () => Promise<void>;
}>;

type StartJSONReadyProcessOptions = Readonly<{
  command: string;
  args: readonly string[];
  cwd: string;
  env?: NodeJS.ProcessEnv;
  readyTimeoutMs: number;
  label: string;
  cleanup?: () => void;
}>;

export function ensureBuiltDist(): void {
  const distEntry = path.join(process.cwd(), "dist", "node", "index.js");
  if (fs.existsSync(distEntry)) return;
  execFileSync("npm", ["run", "build"], {
    cwd: process.cwd(),
    stdio: ["ignore", "inherit", "inherit"],
  });
}

export async function getFreePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address == null || typeof address === "string") {
    server.close();
    throw new Error("failed to allocate free port");
  }
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  return port;
}

export async function startGoHarness(): Promise<StartedProcess<HarnessReady>> {
  const cwd = path.join(process.cwd(), "..", "flowersec-go");
  const built = buildTemporaryGoBinary(cwd, "./internal/cmd/flowersec-e2e-harness", "flowersec-e2e-harness");
  return await startJSONReadyProcess<HarnessReady>({
    command: built.binary,
    args: [],
    cwd,
    readyTimeoutMs: 60_000,
    label: "go harness",
    cleanup: built.cleanup,
  });
}

export async function startDirectDemo(origin: string): Promise<StartedProcess<DirectDemoReady>> {
  const cwd = path.join(process.cwd(), "..", "examples");
  const built = buildTemporaryGoBinary(cwd, "./go/direct_demo", "flowersec-direct-demo");
  return await startJSONReadyProcess<DirectDemoReady>({
    command: built.binary,
    args: ["--allow-origin", origin],
    cwd,
    readyTimeoutMs: 60_000,
    label: "direct demo",
    cleanup: built.cleanup,
  });
}

export async function startDevServer(port: number, origin: string): Promise<StartedProcess<DevServerReady>> {
  const tunnelPort = await getFreePort();
  const tunnelURL = `ws://127.0.0.1:${tunnelPort}/ws`;
  return await startJSONReadyProcess<DevServerReady>({
    command: process.execPath,
    args: [
      path.join(process.cwd(), "..", "examples", "ts", "dev-server.mjs"),
      "--port",
      String(port),
      "--origin",
      origin,
      "--tunnel-url",
      tunnelURL,
    ],
    cwd: process.cwd(),
    readyTimeoutMs: 90_000,
    label: "examples dev server",
  });
}

export function makeTunnelArtifactEnvelope(grantClient: unknown): { connect_artifact: unknown } {
  return {
    connect_artifact: {
      v: 1,
      transport: "tunnel",
      tunnel_grant: grantClient,
    },
  };
}

export function makeDirectArtifactEnvelope(ready: DirectDemoReady): { connect_artifact: unknown } {
  return {
    connect_artifact: {
      v: 1,
      transport: "direct",
      direct_info: {
        ws_url: ready.ws_url,
        channel_id: ready.channel_id,
        e2ee_psk_b64u: ready.e2ee_psk_b64u,
        channel_init_expire_at_unix_s: ready.channel_init_expire_at_unix_s,
        default_suite: ready.default_suite,
      },
    },
  };
}

export function runNodeDemoScript(
  scriptRelativePath: string,
  options: Readonly<{
    input?: string;
    env?: NodeJS.ProcessEnv;
    timeoutMs?: number;
  }> = {}
): string {
  const scriptPath = path.join(process.cwd(), "..", "examples", "ts", scriptRelativePath);
  try {
    return execFileSync(process.execPath, [scriptPath], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      ...(options.input === undefined ? {} : { input: options.input }),
      env: { ...process.env, ...options.env },
      timeout: options.timeoutMs ?? 60_000,
    });
  } catch (error) {
    const err = error as {
      message?: string;
      stdout?: string | Buffer;
      stderr?: string | Buffer;
    };
    const stdout = typeof err.stdout === "string" ? err.stdout : Buffer.isBuffer(err.stdout) ? err.stdout.toString("utf8") : "";
    const stderr = typeof err.stderr === "string" ? err.stderr : Buffer.isBuffer(err.stderr) ? err.stderr.toString("utf8") : "";
    throw new Error(
      `failed to run ${scriptRelativePath}: ${String(err.message ?? error)}\nstdout:\n${stdout}\nstderr:\n${stderr}`
    );
  }
}

async function startJSONReadyProcess<T>(options: StartJSONReadyProcessOptions): Promise<StartedProcess<T>> {
  const proc = spawn(options.command, [...options.args], {
    cwd: options.cwd,
    env: options.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (!proc.stdout || !proc.stderr) {
    throw new Error(`${options.label}: missing stdio`);
  }
  const stderr = createTextBuffer(proc.stderr);
  try {
    const ready = await readJsonLine<T>(createLineReader(proc.stdout), options.readyTimeoutMs);
    return {
      proc,
      ready,
      stderr,
      stop: async () => {
        try {
          if (proc.exitCode == null && proc.signalCode == null) {
            proc.kill("SIGTERM");
          }
          await createExitPromise(proc).catch(() => undefined);
        } finally {
          options.cleanup?.();
        }
      },
    };
  } catch (error) {
    try {
      if (proc.exitCode == null && proc.signalCode == null) {
        proc.kill("SIGTERM");
      }
      await createExitPromise(proc).catch(() => undefined);
    } finally {
      options.cleanup?.();
    }
    throw new Error(`${options.label} failed to start: ${String(error)}\nstderr:\n${stderr()}`);
  }
}

function buildTemporaryGoBinary(
  cwd: string,
  packagePath: string,
  binaryName: string
): Readonly<{ binary: string; cleanup: () => void }> {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-e2e-"));
  const binary = path.join(directory, binaryName);
  try {
    execFileSync("go", ["build", "-o", binary, packagePath], {
      cwd,
      stdio: ["ignore", "ignore", "pipe"],
      timeout: 60_000,
    });
  } catch (error) {
    fs.rmSync(directory, { recursive: true, force: true });
    throw error;
  }
  return {
    binary,
    cleanup: () => fs.rmSync(directory, { recursive: true, force: true }),
  };
}
