import { spawn } from "node:child_process";

interface Exit { readonly code: number | null; readonly signal: NodeJS.Signals | null; readonly error?: Error; }
async function bounded<T>(operation: Promise<T>, milliseconds: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error("invalid-proof peer observation timed out")), milliseconds);
    })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

/** The Go TLS engine presents a real P-256 leaf and signs CertificateVerify
 * with a different key. The SDK must reject that proof before admission. */
export async function startInvalidProofPeer(carrier: "websocket" | "raw_quic") {
  const child = spawn("go", ["run", "./internal/cmd/invalid-proof-peer", "--carrier", carrier], {
    cwd: new URL("../../../flowersec-go/", import.meta.url), stdio: ["ignore", "pipe", "pipe"],
    detached: process.platform !== "win32",
  });
  let stderr = "", stdout = "", launchError: Error | undefined, exited = false;
  const completed = new Promise<Exit>(resolve => {
    child.once("error", error => { launchError = error; });
    child.once("close", (code, signal) => { exited = true; resolve({ code, signal, ...(launchError === undefined ? {} : { error: launchError }) }); });
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => { stderr = (stderr + chunk).slice(-65536); });
  let stopping: Promise<void> | undefined;
  const terminate = (signal: NodeJS.Signals) => {
    if (exited || child.pid === undefined) return;
    try { if (process.platform === "win32") child.kill(signal); else process.kill(-child.pid, signal); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
  };
  const stop = () => stopping ??= (async () => {
    if (exited) return;
    terminate("SIGTERM");
    let escalation: ReturnType<typeof setTimeout> | undefined;
    try {
      escalation = setTimeout(() => { try { terminate("SIGKILL"); } catch { child.kill("SIGKILL"); } }, 1000);
      await bounded(completed, 5000);
    } finally { if (escalation !== undefined) clearTimeout(escalation); }
  })();
  let readyLine!: (line: string) => void, failedReady!: (error: Error) => void;
  const firstLine = new Promise<string>((resolve, reject) => { readyLine = resolve; failedReady = reject; });
  child.stdout.setEncoding("utf8");
  const receive = (chunk: string) => {
    if (stdout.length + chunk.length > 65536) { failedReady(new Error("invalid-proof peer readiness exceeds its bound")); return; }
    stdout += chunk;
    const newline = stdout.indexOf("\n");
    if (newline >= 0) { child.stdout.removeListener("data", receive); child.stdout.resume(); readyLine(stdout.slice(0, newline)); }
  };
  child.stdout.on("data", receive);
  void completed.then(result => failedReady(result.error ?? new Error(`invalid-proof peer exited ${String(result.code)} before readiness: ${stderr}`)));
  try {
    const record: unknown = JSON.parse(await bounded(firstLine, 15000));
    if (record === null || typeof record !== "object") throw new Error("invalid-proof peer readiness is not a record");
    const ready = record as { address?: unknown; leaf_der_base64?: unknown };
    if (typeof ready.address !== "string" || !/^127\.0\.0\.1:[1-9][0-9]{0,4}$/u.test(ready.address) || typeof ready.leaf_der_base64 !== "string") throw new Error("invalid-proof peer readiness has invalid fields");
    const port = Number(ready.address.slice(ready.address.lastIndexOf(":") + 1));
    const leafDER = Buffer.from(ready.leaf_der_base64, "base64");
    if (port > 65535 || leafDER.length < 1 || leafDER.length > 65536 || leafDER.toString("base64") !== ready.leaf_der_base64) throw new Error("invalid-proof peer readiness has invalid TLS material");
    return Object.freeze({ address: ready.address, leafDER, stop, async wait() {
      const result = await bounded(completed, 15000);
      if (result.error !== undefined) throw result.error;
      if (result.code !== 0 || result.signal !== null) throw new Error(`invalid-proof peer exited ${String(result.code)} (${String(result.signal)}): ${stderr}`);
    } });
  } catch (error) { await stop(); throw error; }
  finally { child.stdout.removeListener("data", receive); }
}
