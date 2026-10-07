import type { V4AuthenticatedContext } from "../streamHandlers.js";
import type { CapturedContractRoute, ContractRoutes } from "./contractRoutes.js";
import type { TrustedDeadline } from "./deadline.js";
import type { RPCRequestInput } from "./rpcInput.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { RPCExecutionIdentity, VolatileExecutions, VolatileExecutionAttempt } from "./volatileExecutions.js";
/** The same Environment execution key owns business dispatch and its one
 * observer fanout. Duplicate physical messages never recreate either fact. */
export class NotificationExecution {
  #input: RPCRequestInput | undefined;
  #route: CapturedContractRoute | undefined;
  #admission: Readonly<{
    history: VolatileExecutions; routes: ContractRoutes; authentication: V4AuthenticatedContext;
    identity: RPCExecutionIdentity; access: RPCPublicationGuard
  }> | undefined;
  #fanout: (() => void) | undefined;
  #attempt: VolatileExecutionAttempt | undefined;
  #closed = false;
  #deadline: TrustedDeadline;
  readonly tryNow: boolean;
  constructor(input: RPCRequestInput, route: CapturedContractRoute, deadline: TrustedDeadline,
    history: VolatileExecutions, routes: ContractRoutes, authentication: V4AuthenticatedContext, identity: RPCExecutionIdentity,
    access: RPCPublicationGuard, fanout: () => void) {
    this.#deadline = deadline; this.tryNow = input.header.uint(7) === 1n; this.#input = input; this.#route = route; this.#admission = { history, routes, authentication, identity, access }; this.#fanout = fanout;
  }
  async admit(stop: () => void): Promise<boolean> {
    this.#deadline.check();
    const a = this.#admission!;
    this.#attempt = (await a.history.admit(this.#input!, this.#route!, a.routes, a.authentication, a.identity, a.access, stop));
    return this.#attempt.created;
  }
  async enter(): Promise<TrustedDeadline> {
    this.#deadline.check();
    this.#admission!.access.check();
    this.#deadline = this.#deadline.forkAgeAt(this.#deadline.sample(), this.#route!.contract.uint(18));
    (await this.#attempt!.enter(() => { this.#deadline.check(); this.#admission!.access.check(); })); this.#deadline.check(); this.#admission!.access.check();
    try { this.#fanout!(); return this.#deadline; } finally { this.#releaseInput(); }
  }
  async finish(): Promise<void> { this.#deadline.check(); (await this.#attempt!.finishNotification(this.#deadline.cap)); }
  fail(): void { this.#attempt?.fail("service_failed"); }
  #releaseInput(): void {
    this.#fanout = undefined; this.#admission = undefined; this.#input?.close(); this.#input = undefined; this.#route?.close(); this.#route = undefined;
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#releaseInput(); this.#attempt?.release(); this.#attempt = undefined;
  }
}
