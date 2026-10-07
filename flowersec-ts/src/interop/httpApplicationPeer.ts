import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { promisify } from "node:util";

interface HTTPApplicationReady {
  readonly wire_revision: 4;
  readonly origin: string;
  readonly trust_pem: string;
  readonly artifact_json?: string;
  readonly bridge_token?: string;
}

async function bounded<T>(operation: Promise<T>, milliseconds: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`${label} timed out`)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

/** Own the current peer executable directly, so cancellation joins the server
 * and its cleanup rather than terminating a compiler with a surviving child. */
export async function startHTTPApplicationPeer(mode: "direct" | "local") {
  const base = process.env.FLOWERSEC_TEST_ARTIFACT_DIR ?? join(homedir(), ".cache", "flowersec-engineering");
  await mkdir(base, { recursive: true, mode: 0o700 });
  const directory = await mkdtemp(join(base, "http-application-peer-"));
  const executable = join(directory, process.platform === "win32" ? "peer.exe" : "peer");
  const cwd = new URL("../../../flowersec-go/", import.meta.url);
  let preservationFailed = false;
  let retainedFailures = 0;
  const retainFailure = async (error: unknown, diagnostic = "") => {
    try {
      const bytes = Buffer.from(`${String(error)}\n${diagnostic}`);
      const path = join(base, `${basename(directory)}-${++retainedFailures}.log`);
      const checksum = createHash("sha256").update(bytes).digest("hex");
      await writeFile(path, bytes, { mode: 0o600 });
      await writeFile(path + ".sha256", `${checksum}  ${basename(path)}\n`, { mode: 0o600 });
      if (createHash("sha256").update(await readFile(path)).digest("hex") !== checksum) throw new Error("peer diagnostic preservation failed");
    } catch (failure) { preservationFailed = true; throw failure; }
  };
  try {
    await promisify(execFile)("go", ["build", "-o", executable, "./internal/cmd/http-application-peer"], {
      cwd, timeout: 60000, maxBuffer: 65536,
    });
  } catch (error) {
    await retainFailure(error);
    await rm(directory, { recursive: true });
    throw error;
  }
  const child = spawn(executable, ["--mode", mode], {
    cwd, env: { ...process.env, FLOWERSEC_SERVER_PARITY_PEER: "1", FLOWERSEC_TEST_ARTIFACT_DIR: join(directory, "runtime") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let exited = false, diagnostic = "", output = "", launchError: Error | undefined;
  const completed = new Promise<Readonly<{ code: number | null; signal: NodeJS.Signals | null }>>(resolve => {
    child.once("error", error => { launchError = error; });
    child.once("close", (code, signal) => { exited = true; resolve({ code, signal }); });
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => { diagnostic = (diagnostic + chunk).slice(-65536); });
  let resolveLine!: (line: string) => void, rejectLine!: (error: Error) => void;
  const firstLine = new Promise<string>((resolve, reject) => { resolveLine = resolve; rejectLine = reject; });
  child.stdout.setEncoding("utf8");
  const receive = (chunk: string) => {
    if (output.length + chunk.length > 1048576) { rejectLine(new Error("HTTP application readiness exceeds its bound")); return; }
    output += chunk;
    const newline = output.indexOf("\n");
    if (newline >= 0) {
      child.stdout.removeListener("data", receive); child.stdout.resume(); resolveLine(output.slice(0, newline));
    }
  };
  child.stdout.on("data", receive);
  void completed.then(result => rejectLine(launchError ?? new Error(`HTTP application peer exited ${String(result.code)} before readiness: ${diagnostic}`)));
  const signal = (value: NodeJS.Signals) => {
    if (exited || child.pid === undefined) return;
    try { child.kill(value); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
  };
  let stopping: Promise<void> | undefined;
  const stop = () => stopping ??= (async () => {
    try {
      if (!exited) {
        signal("SIGTERM");
        let signalError: unknown;
        const escalation = setTimeout(() => { try { signal("SIGKILL"); } catch (error) { signalError = error; } }, 6000);
        try {
          await bounded(completed, 9000, "HTTP application peer cleanup");
          if (signalError !== undefined) throw signalError;
        } finally { clearTimeout(escalation); }
      }
      const result = await completed;
      if (launchError !== undefined) throw launchError;
      if (result.code !== 0 || result.signal !== null) throw new Error(`peer exit ${String(result.code)} (${String(result.signal)}): ${diagnostic}`);
      if (!preservationFailed) await rm(directory, { recursive: true });
    } catch (error) {
      await retainFailure(error, diagnostic);
      // Retain an executable only while its original process is still live.
      // A failed joined process needs its verified diagnostic, not scratch files.
      if (exited && !preservationFailed) await rm(directory, { recursive: true, force: true });
      throw error;
    }
  })();
  try {
    const ready = JSON.parse(await bounded(firstLine, 15000, "HTTP application peer readiness")) as HTTPApplicationReady;
    if (ready === null || typeof ready !== "object" || ready.wire_revision !== 4 ||
        typeof ready.origin !== "string" || typeof ready.trust_pem !== "string" ||
        mode === "local" && (typeof ready.artifact_json !== "string" || typeof ready.bridge_token !== "string")) {
      throw new Error("invalid current HTTP application deployment");
    }
    return Object.freeze({ ready, stop, async wait() {
      const result = await bounded(completed, 20000, "HTTP application peer completion");
      if (launchError !== undefined) throw launchError;
      if (result.code !== 0 || result.signal !== null) throw new Error(`HTTP application peer failed ${String(result.code)} (${String(result.signal)}): ${diagnostic}`);
    } });
  } catch (error) {
    const failures = [error];
    try { await retainFailure(error, diagnostic); } catch (failure) { failures.push(failure); }
    try { await stop(); } catch (failure) { failures.push(failure); }
    if (failures.length === 1) throw error;
    throw new AggregateError(failures, "HTTP application peer startup and cleanup failed");
  } finally { child.stdout.removeListener("data", receive); }
}
