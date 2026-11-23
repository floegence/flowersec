import { readFileSync } from "node:fs";

/** @typedef {import('@floegence/flowersec-core/node').JsonValue} JsonValue */
/** @typedef {import('@floegence/flowersec-core/node').RPCHandlers} RPCHandlers */
/** @typedef {import('@floegence/flowersec-core/node').Session} Session */
/** @typedef {Parameters<Parameters<RPCHandlers['handleRPC']>[1]>[1]} HandlerRequest */

const ids = [7001, 7002, 7003, 7005];
const declarations = JSON.parse(readFileSync(new URL("../parity-contracts.json", import.meta.url), "utf8"));

/** @param {JsonValue} value @returns {value is Record<string, JsonValue>} */
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }

/** @param {unknown} value */
function contractBytes(value) {
  if (typeof value !== "string" || value.length === 0) throw new Error("missing parity contract");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new Error("invalid parity contract encoding");
  return bytes;
}

/** Install into the authenticated peer's real handler registry. The same
 * current grant controls both method invocation and disclosure of its contract.
 * @param {Pick<RPCHandlers, 'handleRPC' | 'handleNotification'>} handlers
 * @param {(id: number, request: HandlerRequest) => boolean} permitted
 * @param {(id: number, request: HandlerRequest) => boolean} [mayDisclose]
 */
export function parityRegistrations(handlers, permitted, mayDisclose = permitted) {
  /** @type {Map<number, string>} */
  const registered = new Map();
  const unavailable = () => ({ error: { code: 403, message: "parity method unavailable" } });
  handlers.handleRPC(declarations.query_type_id, async (payload, request) => {
    if (!object(payload) || Object.keys(payload).length !== 2 || payload.namespace !== declarations.namespace ||
        !Array.isArray(payload.type_ids) || payload.type_ids.length < 1 || payload.type_ids.length > ids.length) {
      return { error: { code: 400, message: "invalid parity query" } };
    }
    const contracts = [];
    for (const id of payload.type_ids) {
      if (typeof id !== "number" || !Number.isInteger(id)) return { error: { code: 400, message: "invalid method id" } };
      const declaration = registered.get(id);
      if (declaration === undefined || !mayDisclose(id, request)) return unavailable();
      contracts.push(declaration);
    }
    return { payload: { contracts } };
  });
  /** @param {number} id */
  function declaration(id) {
    const value = declarations.contracts[id];
    contractBytes(value);
    return /** @type {string} */ (value);
  }
  return {
    /** @param {number} id @param {Parameters<RPCHandlers['handleRPC']>[1]} handler */
    handleRPC(id, handler) {
      const value = declaration(id);
      handlers.handleRPC(id, (payload, request) => permitted(id, request) ? handler(payload, request) : Promise.resolve(unavailable()));
      registered.set(id, value);
    },
    /** @param {number} id @param {Parameters<RPCHandlers['handleNotification']>[1]} handler */
    handleNotification(id, handler) {
      const value = declaration(id);
      handlers.handleNotification(id, (payload, request) => { if (permitted(id, request)) return handler(payload, request); });
      registered.set(id, value);
    },
  };
}

/** @param {JsonValue} payload */
const valueOf = payload => object(payload) ? payload.value : undefined;
const bad = () => ({ error: { code: 400, message: "invalid parity payload" } });
const denied = () => ({ error: { code: 403, message: "parity method unavailable" } });

/** Per-endpoint application state. Only the deployment registry is shared. */
export class ParityEndpoint {
  /** @type {Session | undefined} */ session;
  /** @type {(() => void) | undefined} */ #unsubscribe;
  /** @type {Set<() => void>} */ #waiting = new Set();
  #observed = 0;
  #stopped = new AbortController();

  /** @param {(id: number) => boolean} permitted */
  constructor(permitted) { this.permitted = permitted; }

  /** @param {number} id */
  allows(id) { return !this.#stopped.signal.aborted && this.permitted(id); }

  /** @param {Session} session @param {AbortSignal} signal */
  async bind(session, signal) {
    this.session = session;
    await verifyParity(session, signal);
    signal.throwIfAborted();
    this.#stopped.signal.throwIfAborted();
    this.#unsubscribe = session.rpc.onNotify(7002, valueOf, value => {
      if (value !== "notify" || !this.allows(7002)) return;
      this.#observed++;
      for (const wake of this.#waiting) wake();
    });
    for (const wake of this.#waiting) wake();
  }

  /** @param {JsonValue} payload @param {HandlerRequest} request */
  async echo(payload, request) {
    const value = valueOf(payload);
    if (value !== "ping" && value !== "notifications-observed") return bad();
    const signal = request.signal ? AbortSignal.any([request.signal, this.#stopped.signal]) : this.#stopped.signal;
    while (!this.#unsubscribe || (value === "notifications-observed" && this.#observed < 2)) {
      signal.throwIfAborted();
      if (!this.allows(7001)) return denied();
      await new Promise((resolve, reject) => {
        const wake = () => { this.#waiting.delete(wake); signal.removeEventListener("abort", stop); resolve(undefined); };
        const stop = () => { this.#waiting.delete(wake); reject(signal.reason); };
        this.#waiting.add(wake); signal.addEventListener("abort", stop, { once: true });
      });
    }
    return this.allows(7001) ? { payload } : denied();
  }

  /** @param {JsonValue} payload @param {HandlerRequest} request */
  async complete(payload, request) {
    if (valueOf(payload) !== "complete" || !this.session) return bad();
    const signal = request.signal ? AbortSignal.any([request.signal, this.#stopped.signal]) : this.#stopped.signal;
    await this.session.rekey({ signal });
    if (!this.allows(7003)) return denied();
    await this.session.probeLiveness({ signal });
    return this.allows(7003) ? { payload } : denied();
  }

  stop() { this.#stopped.abort(); this.#unsubscribe?.(); this.#unsubscribe = undefined; }
}

/** Register a deployment once; the caller binds a local ParityEndpoint before admission.
 * @template {RPCHandlers} T @param {T} registry @returns {T}
 */
export function registerParityEndpoints(registry) {
  const routes = parityRegistrations(registry, (id, { context }) => context instanceof ParityEndpoint && context.allows(id));
  routes.handleRPC(7001, async (payload, request) => request.context instanceof ParityEndpoint ? request.context.echo(payload, request) : denied());
  routes.handleRPC(7003, async (payload, request) => request.context instanceof ParityEndpoint ? request.context.complete(payload, request) : denied());
  routes.handleRPC(7005, async payload => valueOf(payload) === "datagram-ready" ? { payload } : bad());
  routes.handleNotification(7002, payload => { if (valueOf(payload) !== "notify") throw new Error("invalid parity notification"); });
  return registry;
}

/** @param {Session} session @param {AbortSignal} [signal] */
export async function verifyParity(session, signal) {
  const reply = await session.rpc.call(declarations.query_type_id, { namespace: declarations.namespace, type_ids: ids }, value => value,
    signal === undefined ? {} : { signal });
  if (!reply.ok) throw new Error(`parity query rejected: ${reply.error.code}`);
  const value = reply.payload;
  if (!object(value) || Object.keys(value).length !== 1 || !Array.isArray(value.contracts) || value.contracts.length !== ids.length) {
    throw new Error("incomplete parity contract reply");
  }
  for (const [index, id] of ids.entries()) {
    if (!contractBytes(value.contracts[index]).equals(contractBytes(declarations.contracts[id]))) throw new Error(`parity contract mismatch: ${id}`);
  }
}
