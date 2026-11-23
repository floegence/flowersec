import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { connect, createAcceptor, createArtifactLease, SessionHandlers, type Acceptor, type AcceptedSession, type Session } from '../node/index.js';
import { privateBytes, positionArtifact, durableMark } from './currentDirectCapacityStore.js';
import { sessionInventory } from '../v3/publicSession.js';
import { registerParityEndpoints } from '../../../examples/ts/parity.mjs';
import { capacityFrameBytes, CapacityParityEndpoint as ParityEndpoint, runCapacityBusiness } from '../../../examples/ts/capacity-business.mjs';

const count = 1000, origin = "https://client.example";
const parityMethods = new Set([7001, 7002, 7003, 7005]);
export type NativeCapacityOptions = Readonly<{ nativeSDK: "typescript"; sessions: number; streamsPerSession: 0;
  carrier: "websocket"; operationTimeoutMS: number; materialPath: string; storeDirectory: string; directReplacement: true; overlapSuccessors: 4 }>;
type EndReading = readonly [number, boolean, number, number];
export type DeploymentReading = { prepared: boolean; closed: boolean; pairs: (readonly [boolean, EndReading | null, EndReading | null, number, number, string])[] };

export function validateNativeCapacityOptions(input: unknown): NativeCapacityOptions {
  const o = input as NativeCapacityOptions;
  if (!o || o.nativeSDK !== "typescript" || o.carrier !== "websocket" || "serverCarrier" in o || o.sessions !== count ||
      o.streamsPerSession !== 0 || !Number.isSafeInteger(o.operationTimeoutMS) || o.operationTimeoutMS < 1 || o.operationTimeoutMS > 86400000 ||
      (o.directReplacement !== true || o.overlapSuccessors !== 4) ||
      !isAbsolute(o.materialPath) || !isAbsolute(o.storeDirectory)) throw new Error("TypeScript Direct WSS 1000 configuration required");
  return o;
}

const positionID = (index: number, generation: number) => generation === 1 ? `p${index}` : `p${index}-g${generation}`;

class Pair {
  readonly apps: readonly [ParityEndpoint, ParityEndpoint];
  readonly accepted = deferred<AcceptedSession>();
  ready = false; closed = false; notified = false;
  client?: Session; server?: AcceptedSession; monitor?: Promise<void>; closing?: Promise<void>;
  constructor(readonly index: number, readonly generation: number, readonly id: string, readonly key: string, allowed: (pair: Pair, id: number) => boolean) {
    const permitted = (method: number) => allowed(this, method);
    this.apps = [new ParityEndpoint(permitted), new ParityEndpoint(permitted)];
    void this.accepted.promise.catch(() => {});
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

/** The original load admits four simultaneous business queries per direction. */
class QuerySlots {
  #available = 4;
  readonly #waiting = new Set<() => void>();
  async run(signal: AbortSignal, body: () => Promise<void>) {
    signal.throwIfAborted();
    if (this.#available) this.#available--;
    else await new Promise<void>((resolve, reject) => {
      const enter = () => { this.#waiting.delete(enter); signal.removeEventListener("abort", stop); resolve(); };
      const stop = () => { this.#waiting.delete(enter); reject(signal.reason); };
      this.#waiting.add(enter); signal.addEventListener("abort", stop, { once: true });
    });
    try { signal.throwIfAborted(); await body(); }
    finally { const next = this.#waiting.values().next(); if (!next.done) next.value(); else this.#available++; }
  }
}

export class CurrentDirectCapacityWorker {
  readonly #handlers = registerParityEndpoints(new SessionHandlers());
  readonly initialization: { endpointAddress: string };
  readonly #byKey = new Map<string, Pair>();
  readonly #pairs = new Map<string, Pair>();
  readonly #seen = new Set<number>();
  readonly #successors = new Set<number>();
  readonly #queries = [new QuerySlots(), new QuerySlots()] as const;
  readonly #abort = new AbortController();
  readonly #acceptAbort = new AbortController();
  readonly #acceptTask: Promise<void>;
  readonly #endpoint: string;
  readonly #invitations: string;
  readonly #records: string; readonly #approvals: string;
  #failure?: Error;
  #prepared = false; #closed = false; #quiesced = false;
  private constructor(readonly options: NativeCapacityOptions, readonly acceptor: Acceptor,
    readonly roots: string, readonly terminate: (id: string) => Promise<void>) {
    const port = acceptor.addresses()[0]!.port;
    this.initialization = { endpointAddress: `127.0.0.1:${port}` };
    this.#endpoint = `wss://127.0.0.1:${port}/flowersec/v5/direct`;
    const base = dirname(options.materialPath);
    this.#invitations = process.env.FSEC_CAPACITY_INVITATION_DIR ?? join(base, "invitations");
    this.#approvals = join(base, "approvals");
    this.#records = process.env.FSEC_CAPACITY_RECORD_DIR ?? join(base, "records");
    if (!isAbsolute(this.#records) || !isAbsolute(this.#invitations)) throw new Error("absolute issuer directories required");
    this.#acceptTask = this.#accept();
  }
  static async create(o: NativeCapacityOptions, terminate: (id: string) => Promise<void>) {
    const [certificate, privateKey, roots] = await Promise.all([
      privateBytes(process.env.FSEC_CAPACITY_TLS_CERT ?? '', 128 << 10, false),
      privateBytes(process.env.FSEC_CAPACITY_TLS_KEY ?? '', 128 << 10),
      privateBytes(process.env.FSEC_CAPACITY_TLS_ROOT ?? '', 128 << 10, false),
    ]);
    let acceptor: Acceptor | undefined, deployment: CurrentDirectCapacityWorker;
    try {
      acceptor = await createAcceptor({ listeners: [{ carrier: "websocket", path: "direct", host: "127.0.0.1", port: 0,
        allowedOrigins: [origin], tls: { certificate: certificate.toString("utf8"), privateKey: privateKey.toString("utf8") } }],
        maxPendingSessions: count + 4, maxRpcFrameBytes: capacityFrameBytes, maxInboundStreams: 32, admissionReasons: ["invalid_credential"],
        async authorize(req, { signal }) {
          const key = req.lookupKey();
          const record = JSON.parse((await privateBytes(join(deployment.#records, key + ".json"), 96 * 1024)).toString("utf8"));
          if (record.schema_version !== 1 || record.lookup_key !== key || record.allow_replacement !== false ||
              record.direct_upstream !== "127.0.0.1:1" || typeof record.artifact_base64url !== "string")
            throw new Error("invalid direct authorization record");
          const bytes = Buffer.from(record.artifact_base64url, "base64url");
          if (bytes.toString("base64url") !== record.artifact_base64url) throw new Error("invalid authorization encoding");
          const pair = deployment.#byKey.get(key);
          signal?.throwIfAborted();
          if (!pair || pair.closed) return { accepted: false, retryable: false, reason: "invalid_credential" };
          const approved = await privateBytes(join(deployment.#approvals, pair.id + '.json'), 65536);
          if (!approved.equals(bytes)) throw new Error('record differs from role-scoped approval');
          const approval = positionArtifact(approved, pair.id, deployment.#endpoint);
          return approval.key === key && req.matchesDirectArtifact(approval.handle) && !pair.closed ? { accepted: true, artifact: approval.handle } :
            { accepted: false, retryable: false, reason: "invalid_credential" };
        },
        async resolveHandlers(req, { signal }) {
          signal?.throwIfAborted(); const pair = deployment.#byKey.get(req.lookupKey());
          if (!pair || pair.closed) throw new Error("inactive direct grant");
          await durableMark(o.storeDirectory, "admitted", pair.key); signal?.throwIfAborted();
          return deployment.#handlers.forSession(pair.apps[1]);
        } });
      return deployment = new CurrentDirectCapacityWorker(o, acceptor, roots.toString("utf8"), terminate);
    } catch (error) { await acceptor?.close(); throw error; }
  }
  #allowed(pair: Pair, id: number) {
    return !pair.closed && parityMethods.has(id) && existsSync(join(this.#records, pair.key + ".json"));
  }
  async #accept() {
    while (!this.#acceptAbort.signal.aborted) {
      try {
        const end = await this.acceptor.accept({ signal: this.#acceptAbort.signal });
        const pair = this.#byKey.get(end.authorizationKey);
        if (!pair || pair.closed || pair.server) { await end.close(); continue; }
        pair.server = end; pair.accepted.resolve(end);
      } catch (err) {
        if (this.#acceptAbort.signal.aborted) return;
        this.#failure ??= err instanceof Error ? err : new Error("unexpected direct admission failure");
        this.#abort.abort(this.#failure); return;
      }
    }
  }
  prepare(n: number, signal: AbortSignal) {
    signal.throwIfAborted(); if (this.#prepared || n !== count || this.#quiesced) throw new Error("invalid Direct preparation");
    this.#prepared = true;
  }
  async connect(index: number, signal: AbortSignal, deadline: AbortSignal) {
    const op = AbortSignal.any([signal, deadline, this.#abort.signal]); op.throwIfAborted();
    if (!this.#prepared || this.#quiesced || !Number.isSafeInteger(index) || index < 0 || index >= count || this.#seen.has(index))
      throw new Error(this.options.directReplacement ? "configuration" : "invalid Direct position");
    this.#seen.add(index);
    return this.#connectGeneration(index, 1, op);
  }
  async #connectGeneration(index: number, generation: number, op: AbortSignal) {
    const id = positionID(index, generation);
    const invitation = positionArtifact(await privateBytes(join(this.#invitations, id + ".json"), 65536), id, this.#endpoint);
    if (this.#byKey.has(invitation.key)) throw new Error("duplicate Direct invitation");
    const pair = new Pair(index, generation, id, invitation.key, (p, method) => this.#allowed(p, method)); this.#byKey.set(pair.key, pair); this.#pairs.set(id, pair);
    const cancel = () => pair.accepted.reject(op.reason); op.addEventListener("abort", cancel, { once: true });
    const stop = new AbortController(), bindSignal = AbortSignal.any([op, stop.signal]);
    let tasks: Promise<void>[] = [];
    try {
      op.throwIfAborted();
      const lease = createArtifactLease(invitation.handle, async s => { s?.throwIfAborted(); await durableMark(this.options.storeDirectory, "spent", pair.key); });
      pair.client = await connect(lease, { origin, maxRpcFrameBytes: capacityFrameBytes, roots: this.roots, rpcHandlers: this.#handlers.forSession(pair.apps[0]), signal: op });
      const accepted = await pair.accepted.promise; op.throwIfAborted();
      const ends = [pair.client, accepted.session];
      tasks = ends.map((end, n) => this.#queries[n]!.run(bindSignal, () => pair.apps[n]!.bind(end, bindSignal)));
      await Promise.all(tasks); op.throwIfAborted();
      if (!ends.every(end => sessionInventory(end).active)) throw new Error("direct session terminated during query");
      pair.ready = true;
      const lives = ends.map(end => end.waitTermination());
      pair.monitor = Promise.race(lives).then(async () => { pair.notified = true; await this.terminate(id); await Promise.all(lives); });
      void pair.monitor.catch(err => { this.#failure ??= err; this.#abort.abort(err); });
      return { id, generation, lookupKey: pair.key, verifiedContractsPerEndpoint: 4 };
    } catch (err) { stop.abort(); await Promise.allSettled(tasks); await this.#closePair(pair); throw err; }
    finally { op.removeEventListener("abort", cancel); }
  }
  async probe(id: string, signal: AbortSignal, deadline: AbortSignal) {
    const p = this.#pairs.get(id); if (!p?.ready || p.closed || p.notified) throw new Error(this.options.directReplacement ? "configuration" : "unavailable Direct session");
    const op = { signal: AbortSignal.any([signal, deadline, this.#abort.signal]) };
    if (this.options.directReplacement) {
      const results = await Promise.allSettled([p.client!.probeLiveness(op), p.server!.session.probeLiveness(op)]);
      for (const result of results) if (result.status === "rejected") throw result.reason;
      op.signal.throwIfAborted();
      if (p.closed || p.notified) throw new Error("configuration");
      return { id, generation: p.generation, clientResponsive: true, serverResponsive: true };
    }
    await p.client!.probeLiveness(op);
    if (!sessionInventory(p.server!.session).active) throw new Error("inactive Direct peer");
  }
  async directCommand(command: string, fields: Record<string, unknown>, signal: AbortSignal, deadline: AbortSignal) {
    this.checkOpen(signal);
    if (!this.options.directReplacement || this.#quiesced && command !== "close_session") throw new Error("configuration");
    const { index, generation, expectedSession, session } = fields;
    if (command === 'connect_successor') {
      if (typeof index !== 'number' || !Number.isSafeInteger(index) || index < 0 || index >= count || this.#successors.has(index) || this.#successors.size >= 4 ||
          session !== positionID(index, 1) || expectedSession !== positionID(index, 2)) throw new Error('configuration');
      const old = this.#pairs.get(session);
      if (!old?.ready || old.closed || old.notified || !sessionInventory(old.client!).active || !sessionInventory(old.server!.session).active) throw new Error('configuration');
      this.#successors.add(index);
      return this.#connectGeneration(index, 2, AbortSignal.any([signal, deadline, this.#abort.signal]));
    }
    const pair = typeof session === "string" ? this.#pairs.get(session) : undefined;
    if (!pair?.ready || pair.closed || generation !== undefined && generation !== pair.generation || index !== undefined && index !== pair.index) throw new Error("configuration");
    if (command === "close_session") return this.closeSession(pair.id, signal);
    if (pair.notified || !sessionInventory(pair.client!).active || !sessionInventory(pair.server!.session).active) throw new Error("configuration");
    if (command === "check_live") return { id: pair.id, generation: pair.generation, liveEnds: [1, 1] };
    if (command === 'business') {
      const { operation, bytes } = fields;
      if (pair.generation !== 1 || (operation !== 'echo' && operation !== 'raw') || (bytes !== 256 && bytes !== 1048576)) throw new Error('configuration');
      const receipt = await runCapacityBusiness(pair.client!, pair.server!.session, operation, bytes, AbortSignal.any([signal, deadline, this.#abort.signal]));
      return { id: pair.id, generation: pair.generation, ...receipt };
    }
    if (command === "probe") return this.probe(pair.id, signal, deadline);
    throw new Error("configuration");
  }
  checkOpen(signal: AbortSignal) { signal.throwIfAborted(); this.#abort.signal.throwIfAborted(); }
  readState(inventory: boolean, signal: AbortSignal): DeploymentReading {
    signal.throwIfAborted(); if (inventory) this.checkOpen(signal);
    const ids = new Map<Session, number>();
    const read = (s?: Session): EndReading | null => {
      if (!s) return null;
      if (!ids.has(s)) ids.set(s, ids.size + 1);
      const i = sessionInventory(s); return [ids.get(s)!, i.active, i.streams, i.residual];
    };
    return { prepared: this.#prepared, closed: this.#closed,
      pairs: Array.from(this.#pairs.values(), p => [p.ready && !p.closed && !p.notified, read(p.client), read(p.server?.session), p.index, p.generation, p.id] as const) };
  }
  async #closePair(p: Pair) {
    p.closing ??= (async () => {
      p.closed = true; p.accepted.reject(new Error("direct pair closed")); for (const app of p.apps) app.stop();
      const outcome = await Promise.allSettled([p.client?.close(), p.server?.close(), p.monitor]);
      for (const r of outcome) if (r.status === "rejected") throw r.reason;
      if (p.server) {
        const end = sessionInventory(p.server.session);
        if (end.active || end.streams || end.residual) throw new Error('accepted session has not drained');
        await durableMark(this.options.storeDirectory, 'released', p.key);
      }
    })();
    await p.closing;
  }
  async closeSession(id: string, signal: AbortSignal) {
    signal.throwIfAborted(); const p = this.#pairs.get(id); if (!p) throw new Error("unknown Direct session"); await this.#closePair(p);
    if (this.options.directReplacement) {
      if (!p.notified || [p.client!, p.server!.session].some(end => { const state = sessionInventory(end); return state.active || state.streams || state.residual; }))
        throw new Error("Direct generation has not drained");
      this.#pairs.delete(id); this.#byKey.delete(p.key);
      return { id, generation: p.generation, closed: true };
    }
  }
  async quiesce(signal: AbortSignal) {
    signal.throwIfAborted(); this.#quiesced = true; this.#acceptAbort.abort(); await this.#acceptTask;
  }
  async close(signal: AbortSignal) {
    if (this.#closed) return;
    await this.quiesce(signal); this.#abort.abort();
    const results = await Promise.allSettled(Array.from(this.#pairs.values(), p => this.#closePair(p)));
    await this.acceptor.close();
    for (const result of results) if (result.status === "rejected") throw result.reason;
    this.#pairs.clear(); this.#byKey.clear(); this.#seen.clear(); this.#successors.clear(); this.#closed = true;
    signal.throwIfAborted();
  }
}
