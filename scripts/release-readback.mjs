const DEFAULT_TIMEOUT_MS = 30_000;

export async function fetchResponseBody(url, options = {}, maximumBytes, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, { ...options, signal: controller.signal });
    assertResponseSize(response, maximumBytes);
    if (response.body === null) throw new Error("registry response has no body");
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maximumBytes) {
          controller.abort();
          throw new Error(`registry response exceeds ${maximumBytes}-byte limit`);
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      reader.releaseLock();
    }
    return { response, body: Buffer.concat(chunks, total) };
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`registry request timed out after ${timeoutMs}ms: ${url}`, { cause: error });
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export function assertResponseSize(response, maximumBytes) {
  const value = response.headers.get("content-length");
  if (value === null) return;
  const length = Number(value);
  if (!Number.isSafeInteger(length) || length < 0 || length > maximumBytes) {
    throw new Error("invalid registry archive size");
  }
}

export function killProcessGroup(child) {
  if (child.pid === undefined) return;
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch (error) {
    if (error.code !== "ESRCH") throw error;
  }
}

export function execFileBounded(file, args, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, {
      cwd: options.cwd,
      env: options.env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let timedOut = false;
    let outputTooLarge = false;
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessGroup(child);
    }, timeoutMs);
    const maxStdoutBytes = options.maxStdoutBytes ?? 4 * 1024 * 1024;
    const maxStderrBytes = options.maxStderrBytes ?? 64 * 1024;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      stdout.push(chunk);
      if (stdoutBytes > maxStdoutBytes) { outputTooLarge = true; killProcessGroup(child); }
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      stderr.push(chunk);
      if (stderrBytes > maxStderrBytes) { outputTooLarge = true; killProcessGroup(child); }
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      const stdoutText = Buffer.concat(stdout).toString("utf8");
      const stderrText = Buffer.concat(stderr).toString("utf8");
      if (timedOut) {
        const error = new Error(`${file} timed out after ${timeoutMs}ms`);
        error.code = "ETIMEDOUT";
        error.killed = true;
        error.signal = "SIGKILL";
        error.stdout = stdoutText;
        error.stderr = stderrText;
        reject(error);
        return;
      }
      if (outputTooLarge) {
        reject(new Error(`${file} output exceeded the bounded readback limit`));
        return;
      }
      if (code !== 0) {
        const error = new Error(`${file} exited with ${signal ?? `status ${code}`}`);
        error.code = code;
        error.signal = signal;
        error.stdout = stdoutText;
        error.stderr = stderrText;
        reject(error);
        return;
      }
      resolve({ stdout: stdoutText, stderr: stderrText });
    });
  });
}
import { spawn } from "node:child_process";
