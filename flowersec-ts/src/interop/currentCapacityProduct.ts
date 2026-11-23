import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { concurrentCalls, frames, originalDeadline, replyBytes, requestBytes, roleSocket, send } from "./currentCapacityChannel.js";
import type { CurrentDirectCapacityWorker } from "./currentDirectCapacityWorker.js";

type Deployment = Pick<CurrentDirectCapacityWorker, 'prepare' | 'checkOpen' | 'quiesce' | 'close'> & {
  connect(index: number, signal: AbortSignal, deadline: AbortSignal): Promise<unknown>;
  readState(inventory: boolean, signal: AbortSignal): unknown;
  probe(id: string, signal: AbortSignal, deadline: AbortSignal): Promise<unknown>;
  closeSession(id: string, signal: AbortSignal): Promise<unknown>;
  directCommand?(command: string, fields: Record<string, unknown>, signal: AbortSignal, deadline: AbortSignal): Promise<unknown>;
  tunnelCommand?(op: string, fields: Record<string, unknown>, signal: AbortSignal, deadline: AbortSignal): Promise<unknown>;
  readonly initialization: object; prepareServer?(count: number, signal: AbortSignal): Promise<unknown>;
};
function index(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error("invalid deployment index");
  return value;
}
function session(value: unknown): string {
  if (typeof value !== "string" || !value || value.length > 256) throw new Error("invalid session handle");
  return value;
}

export async function serveCapacityDeployment(create = async (value: unknown, terminate: (id: string) => Promise<void>): Promise<Deployment> => {
  if (value && typeof value === 'object' && 'serverCarrier' in value) {
    const { CurrentTunnelCapacityWorker } = await import('./currentTunnelCapacityWorker.js');
    return CurrentTunnelCapacityWorker.create(value, terminate);
  }
  if (value && typeof value === 'object' && 'overlapSuccessors' in value) {
    const { CurrentDirectCapacityWorker, validateNativeCapacityOptions } = await import('./currentDirectOverlapWorker.js');
    return CurrentDirectCapacityWorker.create(validateNativeCapacityOptions(value), terminate);
  }
  const { CurrentDirectCapacityWorker, validateNativeCapacityOptions } = await import("./currentDirectCapacityWorker.js");
  return CurrentDirectCapacityWorker.create(validateNativeCapacityOptions(value), terminate);
}): Promise<void> {
  const socket = roleSocket();
  const active = new Map<number, { abort: AbortController; done: Promise<void> }>();
  let last = 0, deployment: Deployment | undefined, initializing = false, closed = false, quiescing = false, closing = false;
  let failure: unknown, cleanupMS: number | undefined;
  const terminate = (id: string) => send(socket, { event: "terminated", session: id }, replyBytes);
  async function run(r: Record<string, unknown>, signal: AbortSignal): Promise<unknown> {
    if (r.op === "initialize") {
      if (initializing || deployment) throw new Error("deployment already initialized");
      initializing = true;
      deployment = await create(r.options, terminate);
      cleanupMS = (r.options as { operationTimeoutMS: number }).operationTimeoutMS;
      return deployment.initialization;
    }
    if (!deployment || (closed || closing) && r.op !== "state" || quiescing && !["state", "close"].includes(String(r.op)))
      throw new Error("deployment operation outside its lifetime");
    switch (r.op) {
      case "direct_command": {
        const command = r.command;
        if (!deployment.directCommand || typeof command !== "string") throw new Error("configuration");
        const deadline = command === "replace_direct" || command === "connect_successor" ? originalDeadline(r.started, 10000) : command === "probe" ? originalDeadline(r.started, 5000) : signal;
        return deployment.directCommand(command, r, signal, deadline);
      }
      case 'business': case 'connect_successor': case 'install_tunnel_server': case 'install_tunnel_client': case 'replace_tunnel_server': case 'replace_tunnel': case 'confirm_tunnel_releases': case 'check_tunnel_id':
        if (!deployment.tunnelCommand) throw new Error('configuration');
        return deployment.tunnelCommand(r.op,r,signal,r.op === 'replace_tunnel' || r.op === 'connect_successor' ? originalDeadline(r.started,10000) : signal);
      case "prepare_server": if (!deployment.prepareServer) throw new Error("no registration stage"); return deployment.prepareServer(index(r.count), signal);
      case "prepare": return deployment.prepare(index(r.count), signal);
      case "connect": {
        const position = index(r.index), deadline = originalDeadline(r.started, 10000);
        return deployment.connect(position, signal, deadline);
      }
      case "probe": return deployment.probe(session(r.session), signal, originalDeadline(r.started, 5000));
      case "close_session": return deployment.closeSession(session(r.session), signal);
      case "check_open": return deployment.checkOpen(signal);
      case "state":
        if (typeof r.inventory !== "boolean") throw new Error("invalid deployment read");
        return deployment.readState(r.inventory, signal);
      case "quiesce": quiescing = true; return deployment.quiesce(signal);
      case "close": closing = true; await deployment.close(signal); closed = true; return;
      default: throw new Error("unknown deployment operation");
    }
  }
  try {
    for await (const r of frames(socket, requestBytes)) {
      if (Object.hasOwn(r, "cancel")) {
        const id = index(r.cancel); if (id < 1 || id > last) throw new Error("unknown cancellation");
        active.get(id)?.abort.abort(new Error("capacity caller canceled")); continue;
      }
      const id = index(r.id);
      if (id <= last || active.size >= concurrentCalls) throw new Error("invalid product request sequence or concurrency");
      last = id; const abort = new AbortController();
      const done = run(r, abort.signal).then(result => send(socket, { id, result: result ?? {} }, replyBytes),
        error => send(socket, { id, error: String(error instanceof Error ? error.message : error).slice(0, 2048) }, replyBytes))
        .catch(error => { failure ??= error; socket.destroy(); }).finally(() => active.delete(id));
      active.set(id, { abort, done });
    }
  } catch (error) { failure ??= error; }
  finally {
    for (const call of active.values()) call.abort.abort(new Error("deployment control channel closed"));
    await Promise.allSettled(Array.from(active.values(), call => call.done));
    try { if (deployment && !closed) await deployment.close(AbortSignal.timeout(cleanupMS!)); }
    finally { socket.end(); }
  }
  if (failure !== undefined) throw failure;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await serveCapacityDeployment(); } catch (error) { console.error(error); process.exitCode = 1; }
}
