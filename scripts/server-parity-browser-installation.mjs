import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

// This is an explicit issuer-side provisioning request. The browser page only
// opens its existing manifest/history and observes the resulting installation.
// Native qualification is always supplied separately by the deployment owner.
export async function prepareBrowserParityInstallation(repositoryRoot, id) {
  const nativeInstallation = process.env.FLOWERSEC_BROWSER_NATIVE_INSTALLATION;
  const artifactRoot = process.env.FLOWERSEC_TEST_ARTIFACT_DIR;
  if (typeof nativeInstallation !== "string" || !path.isAbsolute(nativeInstallation)) throw new Error(`${id}: independent FLOWERSEC_BROWSER_NATIVE_INSTALLATION is required`);
  if (typeof artifactRoot !== "string" || !path.isAbsolute(artifactRoot)) throw new Error(`${id}: absolute repository-external FLOWERSEC_TEST_ARTIFACT_DIR is required`);
  const requestedRoot = path.resolve(artifactRoot), repository = path.resolve(repositoryRoot);
  const outside = (root, forbidden) => {
    const relative = path.relative(forbidden, root);
    return relative !== "" && (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative));
  };
  const forbidden = await Promise.all([repositoryRoot, os.tmpdir(), "/tmp", "/private/tmp"].map(async value => {
    try { return await realpath(value); } catch (error) { if (error?.code === "ENOENT") return path.resolve(value); throw error; }
  }));
  if (forbidden.some(value => !outside(requestedRoot, value))) throw new Error(`${id}: browser history must be outside the repository and system temporary roots`);
  await mkdir(requestedRoot, { recursive: true, mode: 0o700 });
  const root = await realpath(requestedRoot);
  if (forbidden.some(value => !outside(root, value))) throw new Error(`${id}: resolved browser history root is not independent`);
  const identity = randomUUID(), directory = path.join(root, `browser-parity-${identity}`);
  await mkdir(directory, { mode: 0o700 });
  let closed = false;
  return Object.freeze({
    environment: Object.freeze({
      FLOWERSEC_BROWSER_NATIVE_INSTALLATION: nativeInstallation,
      FLOWERSEC_BROWSER_INSTALLATION_MANIFEST: path.join(directory, "installation.json"),
      FLOWERSEC_BROWSER_HISTORY_DIRECTORY: path.join(directory, "history"),
      FLOWERSEC_BROWSER_SOURCE_ROOT: repository,
      FLOWERSEC_BROWSER_NODE: process.execPath,
    }),
    async cleanup(failure) {
      if (closed) return;
      if (failure !== undefined) {
        const body = Buffer.from(`${id}\n${failure}\n`), name = `browser-parity-${identity}.log`;
        try {
          const digest = createHash("sha256").update(body).digest("hex");
          const retain = async (file, expected) => {
            try { await writeFile(file, expected, { flag: "wx", mode: 0o600 }); }
            catch (error) { if (error?.code !== "EEXIST") throw error; }
            const recorded = await readFile(file);
            try { if (!recorded.equals(expected)) throw new Error(`${id}: retained browser failure evidence differs`); }
            finally { recorded.fill(0); }
          };
          await retain(path.join(root, name), body);
          const checksum = Buffer.from(`${digest}  ${name}\n`);
          try { await retain(path.join(root, `${name}.sha256`), checksum); }
          finally { checksum.fill(0); }
        } finally { body.fill(0); }
      }
      // Failed evidence retention leaves the original history available for
      // diagnosis and a later cleanup attempt. Only physical removal closes it.
      await rm(directory, { recursive: true, force: true });
      closed = true;
    },
  });
}

// Each peer/controller is started in a task-owned process group so terminating
// a go-run/npm wrapper also stops its actual child runtime before scratch removal.
export function signalParityProcess(child, signal) {
  if (child.pid === undefined) return;
  try {
    if (process.platform === "win32") child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) { if (error?.code !== "ESRCH") throw error; }
}
// On macOS a child whose pipes just ended can still be an unreaped zombie:
// kill(-pid) returns EPERM until Node observes its exit. Join the original
// child, then require proof that its process group is gone before dismissing
// that race. A live group or a real permission failure remains an error.
export async function stopAndJoinParityProcesses(peers) {
  const pending = peers.filter(Boolean), failures = [];
  const deadline = Date.now() + 5000;
  for (const peer of pending) {
    try { signalParityProcess(peer.child, "SIGKILL"); }
    catch (error) { failures.push({ child: peer.child, error }); }
  }
  let timer;
  try {
    await Promise.race([
      joinParityProcesses(pending),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("parity processes did not exit within cleanup deadline", { cause: new AggregateError(failures.map(value => value.error)) })), Math.max(0, deadline - Date.now())); }),
    ]);
  } finally { clearTimeout(timer); }
  const remaining = failures.filter(({ child, error }) => {
    if (error?.code !== "EPERM" || process.platform === "win32" || child.pid === undefined) return true;
    try { process.kill(-child.pid, 0); }
    catch (probe) { if (probe?.code === "ESRCH") return false; }
    return true;
  });
  if (remaining.length !== 0) throw new AggregateError(remaining.map(value => value.error), "parity process cleanup failed");
  // Wrapper close does not prove that detached grandchildren have exited.
  // Keep the same cleanup deadline until every original group is gone.
  if (process.platform !== "win32") {
    const groups = new Set(pending.map(peer => peer.child.pid).filter(pid => pid !== undefined));
    while (groups.size !== 0) {
      for (const pid of groups) {
        try { process.kill(-pid, 0); }
        catch (error) {
          if (error?.code === "ESRCH") groups.delete(pid);
          // Reaping an already joined child's last descendant can briefly
          // deny the group probe too. Require ESRCH within the original bound.
          else if (error?.code !== "EPERM" || Date.now() >= deadline) throw error;
        }
      }
      if (groups.size === 0) break;
      if (Date.now() >= deadline) throw new Error("parity process groups did not exit within cleanup deadline");
      await new Promise(resolve => setTimeout(resolve, Math.min(25, deadline - Date.now())));
    }
  }
}

// A failed physical join keeps installations/addons owned by that process.
export class ParityProcessCleanupError extends AggregateError {}
export function parityCleanupIncomplete(error) {
  if (error instanceof ParityProcessCleanupError) return true;
  if (error instanceof AggregateError && error.errors.some(parityCleanupIncomplete)) return true;
  return error?.cause !== undefined && error.cause !== error && parityCleanupIncomplete(error.cause);
}

// Artifact cleanup can fail independently of the protocol. Keep both causes,
// and keep physical-process-owned artifacts while an original join is incomplete.
export async function cleanupParityArtifact(failure, cleanup) {
  if (parityCleanupIncomplete(failure)) return;
  try { await cleanup(); }
  catch (error) {
    if (failure !== undefined) throw new AggregateError([failure, error], "parity run and artifact cleanup failed");
    throw error;
  }
}

// Timer callbacks only publish expiration and start the original bounded join.
// Every wait observes expiration, even when a denied signal leaves a child live.
export function parityProcessDeadline(peers, timeoutMS, message, onTimeout) {
  let expired, rejectExpired, cleanup;
  const expiration = new Promise((_, reject) => { rejectExpired = reject; });
  void expiration.catch(() => {});
  const stop = () => cleanup ??= stopAndJoinParityProcesses(peers()).then(() => undefined, error => error);
  const cancel = reason => {
    if (expired !== undefined) return;
    expired = reason ?? new Error(message);
    try { onTimeout?.(expired); } catch (error) { expired = new AggregateError([expired, error], message); }
    rejectExpired(expired);
    void stop();
  };
  const timer = timeoutMS === undefined ? undefined : setTimeout(() => cancel(), timeoutMS);
  return Object.freeze({
    check() { if (expired !== undefined) throw expired; },
    wait(pending) { return Promise.race([pending, expiration]); },
    stop,
    cancel,
    async finish(failure, afterCleanup) {
      clearTimeout(timer);
      failure ??= expired;
      const cleanupFailure = await stop();
      if (failure !== undefined && cleanupFailure !== undefined) {
        throw new ParityProcessCleanupError([failure, cleanupFailure], `${failure instanceof Error ? failure.message : String(failure)}; parity process cleanup failed`);
      }
      if (cleanupFailure !== undefined) throw new ParityProcessCleanupError([cleanupFailure], "parity process cleanup failed");
      if (parityCleanupIncomplete(failure)) throw failure;
      try { await afterCleanup?.(); }
      catch (error) {
        if (failure !== undefined) throw new AggregateError([failure, error], `${failure instanceof Error ? failure.message : String(failure)}; parity artifact cleanup failed`);
        throw error;
      }
      if (failure !== undefined) throw failure;
      if (expired !== undefined) throw expired;
    },
  });
}
export async function joinParityProcesses(peers) {
  await Promise.all(peers.filter(Boolean).map(({ child, completion }) => {
    if (completion !== undefined) return completion;
    if (child.pid === undefined || (child.exitCode !== null || child.signalCode !== null) && child.stdout?.closed && child.stderr?.closed) return;
    return new Promise(resolve => child.once("close", resolve));
  }));
}
