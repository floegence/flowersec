import type { ContractQueryTarget } from "./contractQuery.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ResourceReference } from "./resources.js";
import type { FixedQueryProtection } from "./fixedQueryExecutor.js";

const capability = Symbol("original query renewal position");

/** Exclusive preparation use of an original J/Q position. It conveys no
 * contract authority and is separate from exact execution offer renewal. */
export class QueryPreparationReservation {
  #gate: QueryRenewalPosition | undefined;
  #reference: ResourceReference | undefined;
  constructor(token: symbol, gate: QueryRenewalPosition, reference: ResourceReference) {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner");
    this.#gate = gate; this.#reference = reference.borrow(); Object.freeze(this);
  }
  check(token: symbol, gate: QueryRenewalPosition): void {
    if (token !== capability || this.#gate !== gate) throw new RPCProtocolError("rpc_query_owner"); this.#reference!.checkRetained();
  }
  close(): void {
    const gate = this.#gate; if (gate === undefined) return;
    this.#gate = undefined; this.#reference?.release(); this.#reference = undefined; gate.releasePreparation(capability, this);
  }
}

/** A future claim on one of the owner's existing complete vectors. This is
 * neither an additional query slot nor permission to query a new contract. */
export class QueryRenewalReservation {
  #gate: QueryRenewalPosition | undefined;
  #reference: ResourceReference | undefined;
  constructor(token: symbol, gate: QueryRenewalPosition, reference: ResourceReference) {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner");
    this.#gate = gate; this.#reference = reference.borrow(); Object.freeze(this);
  }
  check(token: symbol, gate: QueryRenewalPosition): void {
    if (token !== capability || this.#gate !== gate) throw new RPCProtocolError("query_renewal_unavailable"); this.#reference!.checkRetained();
  }
  close(): void {
    const gate = this.#gate; if (gate === undefined) return;
    this.#gate = undefined; this.#reference?.release(); this.#reference = undefined; gate.release(capability, this);
  }
  toJSON(): object { return {}; }
}

/** Embedded in the original J/Q owner. Parent metadata prepays this finite
 * user table; physical availability always comes from the original positions.
 * A last user's closure cannot make an in-flight reserved tail free. */
export class QueryRenewalPosition {
  readonly #users = new Set<QueryRenewalReservation>();
  readonly #preparations = new Map<QueryPreparationReservation, number>();
  #index: number | undefined;
  #closed = false;
  #available: ((index: number) => boolean) | undefined;
  constructor(readonly count: 2 | 4, available: (index: number) => boolean) { this.#available = available; }
  protect(reference: ResourceReference): QueryRenewalReservation | undefined {
    if (this.#closed) throw new RPCProtocolError("query_renewal_unavailable");
    if (this.#users.size >= 64) throw new RPCProtocolError("resource_exhausted");
    this.collect();
    let index = this.#index;
    if (index === undefined) {
      for (let at = 0; at < this.count; at++) if (!this.#prepared(at) && this.#available!(at)) { index = at; break; }
      if (index === undefined) return;
    } else if (this.#users.size === 0 && !this.#available!(index)) return;
    const reservation = new QueryRenewalReservation(capability, this, reference);
    this.#index = index; this.#users.add(reservation); return reservation;
  }
  select(reservation?: QueryRenewalReservation, targets?: readonly ContractQueryTarget[]): number {
    if (this.#closed) throw new RPCProtocolError("query_renewal_unavailable"); this.collect();
    if (reservation !== undefined) {
      this.check(reservation);
      if (targets === undefined || targets.length < 1 || targets.length > 8) throw new RPCProtocolError("rpc_query_owner");
      for (const target of targets) {
        const known = target.known;
        if (known === undefined || known.semantics !== "execution" || target.namespace !== known.namespace || target.typeID !== known.typeID ||
            target.wantedDigest === undefined || !known.hasDigest(target.wantedDigest)) throw new RPCProtocolError("query_renewal_target");
      }
      this.check(reservation); return this.#available!(this.#index!) ? this.#index! : -1;
    }
    for (let index = 0; index < this.count; index++) if (index !== this.#index && !this.#prepared(index) && this.#available!(index)) return index;
    return -1;
  }
  #prepared(index: number): boolean { for (const value of this.#preparations.values()) if (value === index) return true; return false; }
  protectPreparation(reference: ResourceReference): QueryPreparationReservation {
    if (this.#closed) throw new RPCProtocolError("query_closed"); this.collect();
    const index = this.select(); if (index < 0) throw new RPCProtocolError("resource_exhausted");
    const reservation = new QueryPreparationReservation(capability, this, reference); this.#preparations.set(reservation, index); return reservation;
  }
  selectPreparation(reservation: QueryPreparationReservation): number {
    const index = this.checkPreparation(reservation);
    return this.#available!(index) ? index : -1;
  }
  checkPreparation(reservation: QueryPreparationReservation): number {
    if (this.#closed) throw new RPCProtocolError("query_closed"); reservation.check(capability, this);
    const index = this.#preparations.get(reservation); if (index === undefined) throw new RPCProtocolError("rpc_query_owner");
    return index;
  }
  releasePreparation(token: symbol, reservation: QueryPreparationReservation): void {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner"); this.#preparations.delete(reservation);
  }
  check(reservation: QueryRenewalReservation): void {
    if (this.#closed) throw new RPCProtocolError("query_renewal_unavailable");
    reservation.check(capability, this);
    if (!this.#users.has(reservation) || this.#index === undefined) throw new RPCProtocolError("rpc_query_owner");
  }
  release(token: symbol, reservation: QueryRenewalReservation): void {
    if (token !== capability) throw new RPCProtocolError("rpc_query_owner"); this.#users.delete(reservation); this.collect();
  }
  collect(): void {
    if (this.#users.size === 0 && this.#index !== undefined && (this.#closed || this.#available!(this.#index))) this.#index = undefined;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const user of this.#users) user.close();
    for (const reservation of this.#preparations.keys()) reservation.close(); this.#available = undefined; this.#index = undefined;
  }
}

/** The two future positions are acquired in one synchronous SDK gate. Closing
 * the pair only relinquishes future use; accepted queries own their real tails. */
export class ContractRenewalProtection {
  #closed = false;
  constructor(readonly environment: QueryRenewalReservation, readonly session: QueryRenewalReservation) { Object.freeze(this); }
  close(): void { if (this.#closed) return; this.#closed = true; this.session.close(); this.environment.close(); }
  toJSON(): object { return {}; }
}

/** One attempt's serial dependency batches reuse the same original J/Q and
 * fixed SDK execution positions after each actual query tail has exited. */
export class ContractQueryPreparation {
  #closed = false;
  constructor(readonly environment: QueryPreparationReservation, readonly session: QueryPreparationReservation, readonly fixed: FixedQueryProtection) { Object.freeze(this); }
  check(): void { if (this.#closed || this.fixed.closed) throw new RPCProtocolError("query_closed"); }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    this.fixed.close(); this.session.close(); this.environment.close();
  }
}
for (const type of [QueryRenewalReservation, QueryPreparationReservation, QueryRenewalPosition, ContractRenewalProtection, ContractQueryPreparation]) { Object.freeze(type.prototype); Object.freeze(type); }
