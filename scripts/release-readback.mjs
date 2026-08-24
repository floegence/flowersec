const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_REDIRECTS = 4;

export async function fetchResponseBody(url, options = {}, maximumBytes, timeoutMs = DEFAULT_TIMEOUT_MS, validateResponse = undefined) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  let currentURL = url;
  try {
    for (let redirects = 0; ; redirects++) {
      response = await fetch(currentURL, {
        ...options,
        ...(validateResponse === undefined ? {} : { redirect: "manual" }),
        signal: controller.signal,
      });
      if (validateResponse !== undefined && response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (location === null) throw new Error("registry response redirect has no location");
        if (redirects >= MAX_REDIRECTS) throw new Error(`registry response exceeded ${MAX_REDIRECTS} redirects`);
        const nextURL = new URL(location, currentURL).href;
        try {
          validateResponse({ url: nextURL, redirectedFrom: currentURL });
        } finally {
          await response.body?.cancel();
        }
        currentURL = nextURL;
        continue;
      }
      break;
    }
    validateResponse?.(response);
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
      throw new Error(`registry request timed out after ${timeoutMs}ms: ${currentURL}`, { cause: error });
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
    let terminationError;
    let settled = false;
    const terminate = () => {
      try {
        killProcessGroup(child);
        return undefined;
      } catch (error) {
        return error;
      }
    };
    const rejectTerminationFailure = (error) => {
      terminationError = error;
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`${file} failed to terminate child process group`, { cause: error }));
    };
    const timer = setTimeout(() => {
      timedOut = true;
      const error = terminate();
      if (error !== undefined) rejectTerminationFailure(error);
    }, timeoutMs);
    const maxStdoutBytes = options.maxStdoutBytes ?? 4 * 1024 * 1024;
    const maxStderrBytes = options.maxStderrBytes ?? 64 * 1024;
    let stdoutBytes = 0;
    let stderrBytes = 0;
    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxStdoutBytes) {
        outputTooLarge = true;
        const error = terminate();
        if (error !== undefined) rejectTerminationFailure(error);
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes += chunk.length;
      if (stderrBytes > maxStderrBytes) {
        outputTooLarge = true;
        const error = terminate();
        if (error !== undefined) rejectTerminationFailure(error);
        return;
      }
      stderr.push(chunk);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      settled = true;
      reject(error);
    });
    child.once("close", (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      settled = true;
      if (terminationError !== undefined) {
        reject(new Error(`${file} failed to terminate child process group`, { cause: terminationError }));
        return;
      }
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
