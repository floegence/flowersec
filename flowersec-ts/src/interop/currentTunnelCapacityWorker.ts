import { createHash } from 'node:crypto';
import { constants, existsSync } from 'node:fs';
import { open, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { connect, createArtifactLease, parseArtifact, RPCHandlers, type Session } from '../node/index.js';
import { unwrapArtifactHandleV3 } from '../v3/publicApi.js';
import { sessionInventory } from '../v3/publicSession.js';
import { ParityEndpoint, registerParityEndpoints } from '../../../examples/ts/parity.mjs';
import { CapacityParityEndpoint, capacityFrameBytes, runCapacityBusiness } from '../../../examples/ts/capacity-business.mjs';
import type { DeploymentReading, NativeCapacityOptions } from './currentDirectCapacityWorker.js';

const total = 1000, methods = new Set([7001, 7002, 7003, 7005]);
const digest = (v: string | Uint8Array) => createHash('sha256').update(v).digest('base64url');
async function privateInput(path: string, max: number) {
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await f.stat(); if (!stat.isFile() || (stat.mode & 0o077) || stat.size < 1 || stat.size > max) throw Error('invalid private input');
    const raw = Buffer.alloc(stat.size); let pos = 0;
    while (pos < raw.length) { const r = await f.read(raw, pos, raw.length - pos); if (!r.bytesRead) throw Error('short private input'); pos += r.bytesRead; }
    if ((await f.read(Buffer.alloc(1))).bytesRead) throw Error('private input changed'); return raw;
  } finally { await f.close(); }
}
async function publish(dir: string, name: string, data: string) {
  const f = await open(join(dir, name), 'wx', 0o600);
  try { await f.writeFile(data); await f.sync(); } finally { await f.close(); }
  const parent = await open(dir, 'r'); try { await parent.sync(); } finally { await parent.close(); }
}
class Slots {
  #free = 4;
  readonly #waiting = new Set<() => void>();
  async run(signal: AbortSignal, op: () => Promise<void>) {
    signal.throwIfAborted();
    if (this.#free) this.#free--; else await new Promise<void>((resolve, reject) => {
      const enter = () => { this.#waiting.delete(enter); signal.removeEventListener('abort', cancel); resolve(); };
      const cancel = () => { this.#waiting.delete(enter); reject(signal.reason); };
      this.#waiting.add(enter); signal.addEventListener('abort', cancel, { once: true });
    });
    try { signal.throwIfAborted(); await op(); } finally { const first = this.#waiting.values().next(); if (first.done) this.#free++; else first.value(); }
  }
}
class ActiveEndpoint extends ParityEndpoint {
  async close() { this.stop(); await this.session?.close(); }
}
class BusinessEndpoint extends CapacityParityEndpoint {
  async close() { this.stop(); await this.session?.close(); }
}
type Leg = { lease: ReturnType<typeof createArtifactLease>; key: string; record: string; endpoint?: ActiveEndpoint };
type Pair = { readonly id: string; readonly generation: number; readonly previous?: string; readonly legs: [Leg?, Leg?]; attempted: boolean; ready: boolean; closed: boolean; terminated: boolean; responsive?: boolean; released?: boolean; monitor?: Promise<void>; closing?: Promise<void>; opening?: Promise<{id: string; generation?: number}>; interrupt?: AbortController };
function live(pair?: Pair): pair is Pair {
  return !!pair?.ready && !pair.closed && !pair.terminated && [0,1].every(side => {
    const session = pair.legs[side]?.endpoint?.session; return !!session && sessionInventory(session).active;
  });
}
export class CurrentTunnelCapacityWorker {
  readonly #handlers = registerParityEndpoints(new RPCHandlers());
  readonly initialization: { ingressURLs: readonly string[] }; readonly #abort = new AbortController(); readonly #pairs: Pair[] = [];
  readonly #slots = [new Slots(), new Slots()] as const; readonly #keys = new Set<string>();
  readonly #changing = new Set<number>();
  readonly #successors = new Map<number, Pair>();
  #peakConfirmed = false; #retiring: string | undefined; #retired = 0;
  #owners = 0; #drained?: () => void; #shutdown?: Promise<void>;
  #stage = 'empty'; #quiesced = false; #closed = false; #initialClientsInstalled = 0;
  private constructor(readonly root: string, readonly urls: readonly [string, string], readonly ca: string, readonly terminate: (id: string) => Promise<void>, readonly generations: boolean, readonly overlap: boolean) { this.initialization = { ingressURLs: urls }; }
  static async create(input: unknown, terminate: (id: string) => Promise<void>) {
    const opts = input as NativeCapacityOptions & {serverCarrier: string; tunnelReplacement?: boolean; overlapSuccessors?: number};
    if (!opts || opts.nativeSDK !== 'typescript' || opts.carrier !== 'websocket' || opts.serverCarrier !== 'websocket' || opts.sessions !== total || opts.streamsPerSession !== 0 || !Number.isSafeInteger(opts.operationTimeoutMS) || opts.operationTimeoutMS < 1 || opts.operationTimeoutMS > 86400000 || !isAbsolute(opts.materialPath) || !isAbsolute(opts.storeDirectory)) throw Error('original TypeScript WW workload required');
    const root = dirname(opts.materialPath), a = process.env.FSEC_CAPACITY_INGRESS_A, b = process.env.FSEC_CAPACITY_INGRESS_B;
    if (opts.storeDirectory !== join(root, 'stores') || !a || !b || ![a,b].every(u => { const url = new URL(u); return url.protocol === 'wss:' && url.hostname === '127.0.0.1' && url.pathname === '/flowersec/v5/tunnel'; })) throw Error('deployed WSS ingress required');
    if (opts.overlapSuccessors !== undefined && (opts.overlapSuccessors !== 4 || opts.tunnelReplacement !== true || a !== b)) throw Error('four successors on one M required');
    return new CurrentTunnelCapacityWorker(root, [a,b], await readFile(join(root,'ca.pem'),'utf8'), terminate, opts.tunnelReplacement === true, opts.overlapSuccessors === 4);
  }
  async #install(p: Pair, side: 0 | 1, signal: AbortSignal) {
    const file = join(this.root,'invitations',p.id,side === 0 ? 'first.json' : 'second.json');
    const input = await privateInput(file,65536);
    try {
      const handle = parseArtifact(input), a = unwrapArtifactHandleV3(handle), path = a.path;
      if (a.session.channel_id !== p.id || path.kind !== 'tunnel' || path.role !== side+1 || path.rendezvous_group_id !== p.id || path.listener_audience !== 'parity' || path.candidates.length !== 1 || path.candidates[0]?.carrier !== 'websocket' || path.candidates[0].normalized_url !== this.urls[side] || path.candidates[0].tls.mode !== 'ca') throw Error('unexpected WW invitation or ingress');
      const key = digest(path.token), rec = join(this.root,'records',key+'.json');
      const raw = await privateInput(rec,96<<10);
      try { const record = JSON.parse(raw.toString('utf8')); if (record.schema_version !== 1 || record.lookup_key !== key || record.artifact_base64url !== input.toString('base64url') || record.allow_replacement !== false) throw Error('wrong endpoint authorization'); } finally { raw.fill(0); }
      if (this.#keys.has(key)) throw Error('reused leg credential'); this.#keys.add(key); signal.throwIfAborted();
      const lease = createArtifactLease(handle, async s => { s?.throwIfAborted(); await publish(join(this.root,'stores'),'spent-'+key,'flowersec/5\n'); });
      p.legs[side] = {lease,key,record:rec};
      if (side === 1) await publish(join(this.root,'approvals'),p.id+'.json',JSON.stringify({ channel_id:p.id, lookup_key:key, artifact_sha256:digest(input) }));
      return p.legs[side]!;
    } finally { input.fill(0); }
  }
  async #batch(op: (index: number) => Promise<void>) {
    for (let start=0; start<total; start+=8) { const outs = await Promise.allSettled(Array.from({length:Math.min(8,total-start)},(_,idx)=>op(start+idx))); for (const out of outs) if (out.status==='rejected') throw out.reason; }
  }
  async #installServer(index: number, signal: AbortSignal) {
    this.checkOpen(signal);
    if (!Number.isSafeInteger(index) || index < 0 || index >= total || this.#quiesced || this.#pairs[index]) throw Error('unavailable B position');
    const p: Pair = { id:'p'+index, generation:1, legs:[], attempted:false, ready:false, closed:false, terminated:false }; this.#pairs[index] = p;
    await this.#install(p,1,signal);
  }
  async #installClient(index: number, signal: AbortSignal) {
    this.checkOpen(signal); const p=this.#pairs[index];
    if (!p?.legs[1] || p.legs[0] || p.closed || this.#quiesced) throw Error('unavailable A position');
    await this.#install(p,0,signal);
  }
  async prepareServer(n: number, signal: AbortSignal) {
    this.checkOpen(signal);
    if (this.#stage !== 'empty' || n !== total) throw Error('invalid B preparation'); this.#stage = 'installing';
    this.#owners++;
    try {
      await this.#batch(index => this.#installServer(index, signal));
      this.#stage = 'installed'; return { registered: this.#pairs.length };
    } finally { this.#finishOwner(); }
  }
  async prepare(n: number, signal: AbortSignal) {
    this.checkOpen(signal);
    if (this.#stage !== 'installed' || n !== total) throw Error('invalid A publication'); this.#stage = 'reading';
    this.#owners++;
    try { await this.#batch(index => this.#installClient(index, signal)); this.#stage = 'ready'; }
    finally { this.#finishOwner(); }
  }
  async connect(index: number, signal: AbortSignal, deadline: AbortSignal) {
    this.checkOpen(signal);
    const p = this.#pairs[index]; if (p?.generation !== 1 || this.#changing.has(index)) throw Error('configuration');
    this.#owners++;
    try { return await this.#connect(p,signal,deadline); } finally { this.#finishOwner(); }
  }
  async #connect(p: Pair, signal: AbortSignal, deadline: AbortSignal) {
    if (!p.legs[0] || !p.legs[1] || p.attempted || p.closed || this.#quiesced) throw Error('unavailable WW position'); p.attempted = true;
    const stop = p.interrupt = new AbortController();
    try { return await (p.opening = this.#openPair(p,signal,deadline,stop)); }
    finally { delete p.opening; delete p.interrupt; }
  }
  async #openPair(p: Pair, signal: AbortSignal, deadline: AbortSignal, stop: AbortController) {
    const op = AbortSignal.any([signal,deadline,this.#abort.signal,stop.signal]);
    const both = async (task: (side: 0|1, leg: Leg) => Promise<void>) => {
      const results = await Promise.allSettled(([0,1] as const).map(async side => { try { await task(side,p.legs[side]!); } catch (err) { if (!stop.signal.aborted) stop.abort(err); throw err; } }));
      if (results.some(r=>r.status==='rejected')) throw stop.signal.reason; op.throwIfAborted();
    };
    try {
      await both(async (side,leg) => {
        const Endpoint = this.overlap ? BusinessEndpoint : ActiveEndpoint;
        const endpoint = leg.endpoint = new Endpoint((id: number) => !p.closed && methods.has(id) && existsSync(leg.record));
        endpoint.session = await connect(leg.lease,{roots:this.ca,origin:'https://parity.example',tunnelIngressURL:this.urls[side],rpcHandlers:this.#handlers.forSession(endpoint),signal:op,...(this.overlap ? {maxRpcFrameBytes:capacityFrameBytes} : {})});
      });
      await both((side,leg) => this.#slots[side].run(op,()=>leg.endpoint!.bind(leg.endpoint!.session!,op)));
      const sessions = p.legs.map(end=>end!.endpoint!.session!); if (sessions[0]===sessions[1] || !sessions.every(s=>sessionInventory(s).active)) throw Error('WW endpoints not live'); p.ready=true;
      const lives = sessions.map(s=>s.waitTermination()); p.monitor = Promise.race(lives).then(async()=>{p.terminated=true; await this.terminate(p.id); await Promise.all(lives);}); void p.monitor.catch(err=>this.#abort.abort(err));
      return p.generation === 1 ? { id:p.id } : { id:p.id, generation:p.generation };
    } catch (err) {
      try { await this.#closePair(p); }
      catch (cleanup) { throw new AggregateError([err,cleanup],err instanceof Error ? err.message : String(err),{cause:err}); }
      throw err;
    }
  }
  #pair(id: string, allowClosed = false) {
    const index = Number(id.split('-')[0]!.slice(1));
    const p = this.#pairs[index]?.id === id ? this.#pairs[index] : this.#successors.get(index);
    if (!p || p.id !== id || p.closed && !allowClosed) throw Error('configuration'); return p;
  }
  async probe(id: string, signal: AbortSignal, deadline: AbortSignal) {
    const p=this.#pair(id); if (!p.ready || p.terminated) throw Error('inactive WW pair');
    const op=AbortSignal.any([signal,deadline,this.#abort.signal]);
    await p.legs[0]!.endpoint!.session!.probeLiveness({signal:op});
    if (p.generation > 1) await p.legs[1]!.endpoint!.session!.probeLiveness({signal:op});
    if (!sessionInventory(p.legs[1]!.endpoint!.session!).active) throw Error('inactive WW peer');
    if (p.generation > 1) { if (!live(p)) throw Error('inactive WW successor'); p.responsive=true; return { id:p.id, ...(this.overlap ? {generation:p.generation} : {}), responsiveLegs:2 }; }
  }
  async tunnelCommand(op: string, fields: Record<string, unknown>, signal: AbortSignal, deadline: AbortSignal) {
    this.checkOpen(signal);
    if (!this.generations || this.#quiesced) throw Error('configuration');
    if (op === 'business') {
      const p = this.#pair(String(fields.session)), { operation, bytes } = fields;
      if (!this.overlap || !live(p) || (operation !== 'echo' && operation !== 'raw') || (bytes !== 256 && bytes !== 1048576)) throw Error('configuration');
      return {id:p.id, generation:p.generation, ...await runCapacityBusiness(p.legs[0]!.endpoint!.session!,p.legs[1]!.endpoint!.session!,operation,bytes,AbortSignal.any([signal,deadline,this.#abort.signal]))};
    }
    if (op === 'check_tunnel_id') {
      const p = this.#pair(String(fields.session));
      if (!p.ready || p.terminated || !p.legs.every(leg => leg?.endpoint?.session && sessionInventory(leg.endpoint.session).active)) throw Error('inactive WW pair');
      return this.overlap ? {id:p.id,generation:p.generation,liveEnds:[1,1]} : {id:p.id};
    }
    const index=fields.index;
    if (typeof index !== 'number' || !Number.isSafeInteger(index) || index < 0 || index >= total || this.#changing.has(index)) throw Error('configuration');
    this.#changing.add(index); this.#owners++;
    try { return await this.#changePosition(index,op,fields,signal,deadline); }
    finally { this.#changing.delete(index); this.#finishOwner(); }
  }
  async #changePosition(index: number, op: string, fields: Record<string, unknown>, signal: AbortSignal, deadline: AbortSignal) {
    if (op === 'install_tunnel_server') {
      if (this.#stage !== 'empty') throw Error('configuration');
      await this.#installServer(index,signal);
      return {id:'p'+index,generation:1,registered:1};
    }
    if (op === 'install_tunnel_client') {
      if (this.#stage !== 'empty' || this.#pairs[index]?.generation !== 1) throw Error('configuration');
      await this.#installClient(index,signal);
      if (++this.#initialClientsInstalled === total) this.#stage = 'ready';
      return {};
    }
    const p=this.#pairs[index]; if (!p) throw Error('configuration');
    if (op === 'confirm_tunnel_releases') {
      signal = AbortSignal.any([signal,this.#abort.signal]);
      if (p.id !== fields.session || p.generation !== fields.generation || !p.ready || !p.closed || !p.terminated || !p.closing) throw Error('configuration');
      await p.closing;
      for (const leg of [p.legs[0]!,p.legs[1]!]) {
        if (sessionInventory(leg.endpoint!.session!).active) throw Error('old WW endpoint still active');
        for (const prefix of ['admitted-','released-']) {
          const file=join(this.root,'records',prefix+leg.key);
          for (;;) {
            signal.throwIfAborted();
            try { if (!(await privateInput(file,64)).equals(Buffer.from('flowersec/5\n'))) throw Error('wrong authority marker'); break; }
            catch (err) { if (prefix !== 'released-' || (err as NodeJS.ErrnoException).code !== 'ENOENT') throw err; await delay(20,undefined,{signal}); }
          }
        }
      }
      const successor = this.#successors.get(index);
      if (this.overlap && successor) {
        if (this.#retiring !== p.id || successor.previous !== p.id || !live(successor)) throw Error('configuration');
        this.#pairs[index] = successor; this.#successors.delete(index); this.#retired++; this.#retiring=undefined;
      }
      p.released=true; return {id:p.id,generation:p.generation,releasedLegs:2,closed:true};
    }
    const generation=op === 'connect_successor' ? fields.generation ?? 2 : fields.generation, next=`p${index}-g${generation}`;
    if (typeof generation !== 'number' || !Number.isSafeInteger(generation) || generation < 2 || fields.expectedSession !== next) throw Error('configuration');
    if (op === 'replace_tunnel_server') {
      if (this.overlap) {
        if (this.#stage !== 'ready' || generation !== 2 || p.generation !== 1 || fields.session !== p.id || !live(p) || this.#retired || this.#successors.has(index) || this.#successors.size >= 4) throw Error('configuration');
        const successor: Pair = {id:next,previous:p.id,generation,legs:[],attempted:false,ready:false,closed:false,terminated:false};
        this.#successors.set(index,successor); await this.#install(successor,1,signal);
        return {id:next,generation,registered:1};
      }
      if (!p.released || p.id !== fields.session || p.generation+1 !== generation) throw Error('configuration');
      const replacement: Pair={id:next,previous:p.id,generation,legs:[],attempted:false,ready:false,closed:false,terminated:false};
      this.#pairs[index]=replacement;
      await this.#install(replacement,1,signal);
      return {id:next,generation,registered:1};
    }
    if (this.overlap) {
      const successor = this.#successors.get(index);
      if (op !== 'connect_successor' || !live(p) || p.id !== fields.session || !successor || successor.id !== next || !successor.legs[1] || successor.legs[0] || successor.attempted) throw Error('configuration');
      const second=successor.legs[1], first=await this.#install(successor,0,signal); await this.#connect(successor,signal,deadline);
      for (const leg of [first,second]) {
        for (const file of [join(this.root,'records','admitted-'+leg.key),join(this.root,'stores','spent-'+leg.key)]) {
          if (!(await privateInput(file,64)).equals(Buffer.from('flowersec/5\n'))) throw Error('missing WW admission or spend');
        }
      }
      if (!live(successor)) throw Error('inactive WW successor');
      return {id:next,generation,lookupKey:first.key,legKeys:[first.key,second.key],admissionProfile:'flowersec/5',verifiedContractsPerEndpoint:4};
    }
    if (op !== 'replace_tunnel' || p.id !== next || p.previous !== fields.session || !p.legs[1] || p.legs[0] || p.attempted) throw Error('configuration');
    await this.#installClient(index,signal); return this.#connect(p,signal,deadline);
  }
  checkOpen(signal: AbortSignal) { signal.throwIfAborted(); this.#abort.signal.throwIfAborted(); }
  readState(inventory: boolean, signal: AbortSignal): DeploymentReading | {prepared: boolean; closed: boolean; pairs: readonly unknown[]} {
    signal.throwIfAborted(); if (inventory) this.checkOpen(signal); const ids = new Map<Session, number>();
    const read=(leg?: Leg) => { const s=leg?.endpoint?.session; if (!s) return null; if (!ids.has(s)) ids.set(s,ids.size+1); const i=sessionInventory(s); return [ids.get(s)!,i.active,i.streams,i.residual] as const; };
    const pairs = [...this.#pairs,...this.#successors.values()];
    return { prepared:this.#stage==='ready',closed:this.#closed,pairs:Array.from(pairs,p=>{
      const ends = [!!p && p.ready && !p.closed && !p.terminated,read(p?.legs[0]),read(p?.legs[1])] as const;
      return this.overlap && p ? [...ends, Number(p.id.split('-')[0]!.slice(1)), p.generation, p.id] : ends;
    }) };
  }
  #closePair(p: Pair) {
    p.closed = true;
    if (!p.attempted) return;
    return p.closing ??= (async()=>{ const results=await Promise.allSettled([...p.legs.map(leg=>leg?.endpoint?.close()), p.monitor]); for (const r of results) if(r.status==='rejected')throw r.reason; })();
  }
  async closeSession(id: string, signal: AbortSignal) {
    signal.throwIfAborted(); const p=this.#pair(id,!this.generations);
    if (this.overlap && this.#retired < 4) {
      if (this.#retiring || !live(p) || this.#successors.get(Number(p.id.slice(1)))?.previous !== p.id) throw Error('configuration');
      this.#retiring = id;
      try {
        if (!this.#peakConfirmed) {
          if (this.#successors.size !== 4 || this.#pairs.length !== total || !Array.from(this.#pairs).every((old,index) => live(old) && old.id === `p${index}` && old.generation === 1)) throw Error('incomplete WW overlap');
          for (const [index,next] of this.#successors) {
            if (!live(next) || !next.responsive || next.id !== `p${index}-g2` || next.previous !== this.#pairs[index]!.id) throw Error('unresponsive WW successor');
          }
          const ends = new Set<Session>();
          for (const pair of [...this.#pairs,...this.#successors.values()]) for (const leg of pair.legs) ends.add(leg!.endpoint!.session!);
          if (ends.size !== 2*(total+4) || this.#keys.size !== ends.size) throw Error('reused WW endpoint or credential');
          this.#peakConfirmed=true;
        }
        if (![...this.#successors.values()].every(live) || !this.#pairs.every(live)) throw Error('WW overlap no longer live');
        this.checkOpen(signal);
      } catch (error) { this.#retiring=undefined; throw error; }
    }
    if (p.opening && !p.ready) {
      p.interrupt!.abort(new Error('WW position closing'));
      try { await p.opening; } catch { /* The connect caller owns its failure. */ }
    }
    await this.#closePair(p); if (this.generations) return {id:p.id,generation:p.generation,closed:true};
  }
  async quiesce(signal: AbortSignal) { signal.throwIfAborted(); this.#quiesced=true; }
  #finishOwner() { if (--this.#owners === 0) this.#drained?.(); }
  async #closeDeployment() {
    this.#quiesced = true; this.#abort.abort();
    if (this.#owners) await new Promise<void>(resolve => { this.#drained = resolve; });
    const pending: Promise<void>[] = [];
    for (const pair of [...this.#pairs,...this.#successors.values()]) {
      if (!pair) continue;
      const closing = this.#closePair(pair);
      if (closing) pending.push(closing);
    }
    const results = pending.length ? await Promise.allSettled(pending) : [];
    this.#keys.clear(); this.#pairs.length = 0; this.#successors.clear();
    for (const result of results) if (result.status === 'rejected') throw result.reason;
    this.#closed = true;
  }
  async close(signal: AbortSignal) { await (this.#shutdown ??= this.#closeDeployment()); signal.throwIfAborted(); }
}
