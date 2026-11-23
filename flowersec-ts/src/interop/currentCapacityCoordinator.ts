import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { concurrentCalls, frames, replyBytes, requestBytes, roleSocket, send } from "./currentCapacityChannel.js";
import type { DeploymentReading, NativeCapacityOptions } from "./currentDirectCapacityWorker.js";
import type { DeploymentReading as OverlapReading } from "./currentDirectOverlapWorker.js";
type Options = NativeCapacityOptions & { overlapSuccessors?: number };
type Call = (op: string, args: Record<string, unknown>, signal?: AbortSignal) => Promise<unknown>;

function options(value: unknown): Options {
  const v = value as Options;
  if (!v || v.nativeSDK !== "typescript" || v.sessions !== 1000 || v.streamsPerSession !== 0 ||
    !Number.isSafeInteger(v.operationTimeoutMS) || v.operationTimeoutMS < 1 || v.operationTimeoutMS > 86400000)
    throw new Error("invalid capacity workload");
  return v;
}
function adapter(call: Call, configuration: Options, initialization: unknown) {
  let quiesced = false, closed = false;
  return { initialization,
    ...(configuration.directReplacement === true && !("serverCarrier" in configuration) ? {
      directCommand: (command: string, fields: Record<string, unknown>, s: AbortSignal) => call("direct_command", { command, ...fields, started: process.hrtime.bigint().toString() }, s),
    } : {}),
    ...('tunnelReplacement' in configuration && configuration.tunnelReplacement === true ? {
      tunnelCommand: (op: string, fields: Record<string, unknown>, s: AbortSignal) => call(op, { ...fields, started: process.hrtime.bigint().toString() }, s),
    } : {}),
    ...("serverCarrier" in configuration ? { prepareServer: (count: number, s: AbortSignal) => call("prepare_server", { count }, s) } : {}),
    prepare: (count: number, s: AbortSignal) => call("prepare", { count }, s),
    connect: (index: number, s: AbortSignal) => call("connect", { index, started: process.hrtime.bigint().toString() }, s),
    probe: (session: string, s: AbortSignal) => call("probe", { session, started: process.hrtime.bigint().toString() }, s),
    closeSession: (session: string, s: AbortSignal) => call("close_session", { session }, s),
    async checkLive(count: number, s: AbortSignal) {
      const state = await call("state", { inventory: true }, s) as DeploymentReading;
      const overlap = configuration.overlapSuccessors === 4;
      if ((count !== configuration.sessions && !(overlap && count === configuration.sessions + 4)) || !state.prepared || state.pairs.length !== count) throw new Error("original capacity incomplete");
      const seen = new Set<number>();
      for (const [ready, left, right] of state.pairs) {
        if (!ready || !left?.[1] || !right?.[1]) throw new Error("original pair is not live");
        for (const [id] of [left, right]) {
          if (!Number.isSafeInteger(id) || id < 1 || seen.has(id)) throw new Error("original capacity reused a Session"); seen.add(id);
        }
      }
      if (overlap) {
        const positions = new Set<number>(), owners = new Set<string>(); let successors = 0;
        for (const [, , , index, generation, id] of (state as unknown as OverlapReading).pairs) {
          if (!Number.isInteger(index) || index < 0 || index >= configuration.sessions || ![1,2].includes(generation) ||
              id !== `p${index}${generation === 2 ? '-g2' : ''}` || owners.has(id)) throw new Error('invalid capacity generation');
          positions.add(index); owners.add(id); if (generation === 2) successors++;
        }
        if (positions.size !== configuration.sessions || successors !== 4 && !(count === configuration.sessions && successors === 0)) throw new Error('incomplete generation inventory');
        return { activePairs: owners.size, distinctEnds: seen.size, originals: count - successors, successors };
      }
    },
    async snapshot(s: AbortSignal) {
      const state = await call("state", { inventory: false }, s) as DeploymentReading;
      let activeSessions = 0, activeStreams = 0, residualStreams = 0;
      for (const [, left, right] of state.pairs) {
        if (left?.[1] && right?.[1]) activeSessions++;
        for (const end of [left, right]) if (end) { activeStreams += end[2]; residualStreams += end[3]; }
      }
      return { activeSessions, activeStreams, residualStreams, closed: state.closed };
    },
    async openStreams(count: number, s: AbortSignal) {
      s.throwIfAborted(); if (closed || quiesced || count !== 0) throw new Error("original idle capacity has no added stream workload");
      await call("check_open", {}, s);
    },
    async quiesce(s: AbortSignal) { quiesced = true; await call("quiesce", {}, s); },
    async close(s: AbortSignal) { await call("close", {}, s); closed = true; },
  };
}

export async function runCapacityCoordinator(): Promise<void> {
  const socket = roleSocket();
  const pending = new Map<number, { resolve(value: unknown): void; reject(reason: unknown): void }>();
  let next = 0, finishing = false, failure: Error | undefined, terminate: ((id: string) => Promise<void>) | undefined;
  function fail(reason: unknown) {
    failure ??= reason instanceof Error ? reason : new Error(String(reason));
    for (const p of pending.values()) p.reject(failure); pending.clear(); socket.destroy();
    if (!finishing) process.stdin.destroy(failure);
  }
  const reader = (async () => {
    try {
      for await (const frame of frames(socket, replyBytes)) {
        if (frame.event === "terminated" && typeof frame.session === "string" && terminate) { await terminate(frame.session); continue; }
        const id = frame.id, p = typeof id === "number" ? pending.get(id) : undefined;
        if (!p || typeof id !== "number") throw new Error("unknown product reply");
        pending.delete(id);
        if (typeof frame.error === "string") p.reject(new Error(frame.error));
        else if (Object.hasOwn(frame, "result")) p.resolve(frame.result);
        else { const error = new Error("missing product result"); p.reject(error); throw error; }
      }
      if (!finishing || pending.size) throw new Error("product exited before the workload joined");
    } catch (error) { fail(error); }
  })();
  const call: Call = async (op, args, signal) => {
    if (failure) throw failure; signal?.throwIfAborted();
    if (pending.size >= concurrentCalls || !Number.isSafeInteger(next + 1)) throw new Error("product control capacity exceeded");
    const id = ++next;
    const result = new Promise<unknown>((resolve, reject) => pending.set(id, { resolve, reject }));
    const cancel = () => { void send(socket, { cancel: id }, requestBytes).catch(fail); };
    try {
      void send(socket, { id, op, ...args }, requestBytes).catch(fail);
      signal?.addEventListener("abort", cancel, { once: true }); if (signal?.aborted) cancel();
      return await result;
    } finally { signal?.removeEventListener("abort", cancel); pending.delete(id); }
  };
  try {
    const url = new URL("../../../scripts/capacity-browser-protocol.mjs", import.meta.url);
    const protocol = await import(url.href) as { serveBrowserCapacityProtocol(input: { input: typeof process.stdin; output: typeof process.stdout;
      validateOptions: typeof options; createWorker(config: Options, onTermination: (id: string) => Promise<void>): Promise<ReturnType<typeof adapter>> }): Promise<void> };
    await protocol.serveBrowserCapacityProtocol({ input: process.stdin, output: process.stdout, validateOptions: options,
      createWorker: async (config, onTermination) => { terminate = onTermination; return adapter(call, config, await call("initialize", { options: config })); } });
  } finally { finishing = true; socket.end(); await reader; }
  if (failure) throw failure;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await runCapacityCoordinator(); } catch (error) { console.error(error); process.exitCode = 1; }
}
