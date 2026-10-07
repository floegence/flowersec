import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
import { RPCOutputInterest } from "./rpcOutputInterest.js";
import type { V4StreamOwner } from "../public.js";
import type { V4AuthenticatedContext } from "../streamHandlers.js";
import type { ApplicationGroup, ApplicationPermit } from "./applicationExecutor.js";
import type { TrustedClock } from "./clock.js";
import type { ContractRoutes, CapturedContractRoute } from "./contractRoutes.js";
import type { TrustedDeadline } from "./deadline.js";
import { timerChunk } from "./deadline.js";
import type { CheckpointSessionPolicy } from "./checkpointToken.js";
import type { RPCNetwork, RPCNetworkTicket } from "./rpcNetwork.js";
import type { RPCRequestInput } from "./rpcInput.js";
import { RPCPayload, type RPCPayloadBorrow } from "./rpcPayload.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCStreamMessages } from "./rpcStreamMessages.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { ResumeCodec, ResumeOutcome, ResumeTargetFacts } from "./resumeCodec.js";
import type { ServiceInputs } from "./serviceInputs.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import type { RPCExecutionIdentity, VolatileExecutionAttempt } from "./volatileExecutions.js";
export function rpcResumeDispatchCharge(runtimeBytes: bigint): ResourceVector {
  return new ResourceVector([8192n + 8n * runtimeBytes, 0n, 0n, 16n, 1n, 4n, 2n, 0n, 0n, 0n, 0n]);
}
/** Recovery is a prelude of the original accepted raw handler. It uses the
 * original service input, route, history and general network association. */
export class RPCResumeDispatch {
  #input: RPCRequestInput | undefined;
  #route: CapturedContractRoute | undefined;
  #execution: VolatileExecutionAttempt | undefined;
  #target: ResumeTargetFacts | undefined;
  #output: RPCPayload;
  #interest: RPCOutputInterest;
  #work: ResourceReference;
  #authorization: ResourceReference | undefined;
  #working = false;
  #started = false;
  #closed = false;
  #cleaned = false;
  #diagnostic: DiagnosticActivity | undefined;
  #finished: (() => void) | undefined;
  readonly #abort = new AbortController();
  constructor(readonly messages: RPCStreamMessages, readonly adapter: ResourceReference, readonly codec: ResumeCodec,
    readonly network: RPCNetwork, readonly ticket: RPCNetworkTicket, readonly inputs: ServiceInputs,
    readonly routes: ContractRoutes, readonly namespace: string, readonly method: object, readonly kind: string,
    readonly group: ApplicationGroup, readonly authentication: V4AuthenticatedContext, readonly identity: RPCExecutionIdentity,
    readonly policy: CheckpointSessionPolicy, readonly clock: TrustedClock, readonly cleanup: SessionCleanup,
    runtimeBytes: bigint, output: ResourceReference, interest: ResourceReference, work: ResourceReference,
    readonly reserveAuthorization: (bytes: bigint) => ResourceReference, diagnostics?: DiagnosticObserver) {
    this.#work = work.take(rpcResumeDispatchCharge(runtimeBytes));
    try { this.#output = new RPCPayload(4248, runtimeBytes, output); }
    catch (error) { this.#work.release(); throw error; }
    try { this.#interest = new RPCOutputInterest(runtimeBytes, interest); }
    catch (error) { this.#output.close(); this.#work.release(); throw error; }
    let job = false;
    try { this.#diagnostic = new DiagnosticActivity(diagnostics, "application"); cleanup.startJob(); job = true; messages.onChange(() => this.#collect()); }
    catch (error) {
      this.#diagnostic?.failure(error);
      this.#interest.lose("owner_unavailable", true); this.#interest.flush(); this.#interest.endInvocation();
      this.#output.close(); this.#work.release(); if (job) cleanup.finishJob(); throw error;
    }
  }
  onCleanup(callback: () => void): void { this.#finished = callback; this.#collect(); }
  attach(stream: V4StreamOwner, session: object): void {
    if (this.#closed || this.#target !== undefined) throw new RPCProtocolError("resume_binding");
    try { this.#target = this.messages.attachResume(stream, session, this.kind, this.adapter); }
    catch (error) { this.#diagnostic?.failure(error); throw error; }
    finally { this.adapter.release(); }
  }
  async run(parent: TrustedDeadline, signal: AbortSignal): Promise<Readonly<{ outcome: ResumeOutcome; dispatch: boolean }>> {
    if (this.#started || this.#closed || this.#target === undefined) throw new RPCProtocolError("resume_binding");
    this.#started = this.#working = true;
    let deadline = parent, timer: ReturnType<typeof setTimeout> | undefined;
    let permit: ApplicationPermit | undefined, borrow: RPCPayloadBorrow | undefined;
    const abort = (): void => this.close();
    signal.addEventListener("abort", abort, { once: true });
    const check = (): void => {
      if (this.#closed || signal.aborted) throw new RPCProtocolError("service_unavailable");
      deadline.check(); this.messages.check(); this.#route?.handler?.check();
    };
    const tick = (): void => { timer = undefined; try { check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); } catch { this.close(); } };
    try {
      tick();
      const header = await this.messages.read(request => {
        check(); if (request.kind !== "resume_request") throw new RPCProtocolError("resume_binding");
        deadline = parent.fork(request.uint(5) < parent.cap ? request.uint(5) : parent.cap);
        this.network.bindIncomingStream(this.ticket, this.messages, request);
        return this.#input = this.inputs.openInput(this.ticket, request);
      }, this.#abort.signal);
      if (header === undefined) throw new RPCProtocolError("rpc_stream_incomplete");
      this.network.completeStreamRequest(this.ticket, this.messages);
      this.network.inputComplete(this.ticket, this.#input!.state === "complete");
      this.messages.consume();
      check();
      if (this.#input!.refusal !== undefined) throw new RPCProtocolError(this.#input!.refusal);
      this.#route = this.#input!.takeRoute();
      const route = this.#route, handler = route.handler;
      if (route.namespace !== this.namespace || route.method !== this.method || handler?.execution === undefined ||
        route.contract.optionalUint(13) !== 1n || route.definition.request.implementation !== "bytes" || route.definition.response?.implementation !== "bytes") throw new RPCProtocolError("permission_denied");
      handler.admit();
      deadline = deadline.forkAgeAt(this.clock.sample(), route.contract.uint(18));
      if (handler.options.authorization !== "authenticated") {
        this.#authorization = this.reserveAuthorization(handler.options.applicationBytes);
        permit = header.uint(7) === 1n ? this.group.tryOrdinary(handler.options.workClass) : await this.group.acquire(handler.options.workClass, this.#abort.signal, check);
        const invocation = this.group.context(permit, this.authentication, this.#abort.signal, this.#interest.view); this.#interest.attach(invocation.context); this.cleanup.enterCallback();
        try {
          check(); const allowed = await handler.options.authorization(invocation.context); check();
          if (allowed !== true) throw new RPCProtocolError("permission_denied");
        } finally { this.#interest.endInvocation(); invocation.release(); permit.release(); permit = undefined; this.cleanup.exitCallback(); }
      }
      this.#execution = (await handler.execution.admit(this.#input!, route, this.routes, this.authentication, this.identity, { check, current: () => !this.#closed && handler.current() }, () => this.close()));
      const execution = this.#execution;
      let outcome: ResumeOutcome;
      if (execution.created) {
        (await execution.enter(check));
        borrow = this.#input!.borrow();
        outcome = (await execution.finishResume(borrow.bytes, this.#target!, this.policy, deadline.cap, check));
        borrow.release();
        borrow = undefined;
        execution.exit();
      }
      else {
        await execution.wait(this.#abort.signal); check();
        // A join observes history only; it cannot run the recovered handler.
        outcome = { status: "unknown" };
      }
      const result = execution.copyResult(this.#output);
      if (result.sdkError !== undefined || result.applicationError !== undefined) throw new RPCProtocolError(result.sdkError ?? "service_failed");
      borrow = this.#output.borrow(result.bytes);
      if (!execution.created) outcome = this.codec.result(borrow.bytes);
      const response = this.messages.codec().response(header, "resume_response", result.bytes);
      await this.messages.send(response, borrow.bytes, check);
      borrow.release();
      borrow = undefined;
      check();
      this.messages.returnResumeBoundary();
      this.#interest.lose("response_complete", true);
      this.#interest.flush();
      this.#diagnostic?.event({ state: "ready", code: "ok" });
      return Object.freeze({ outcome, dispatch: execution.created && outcome.status === "accepted" });
    }
    catch (error) { this.#diagnostic?.failure(error); this.#execution?.fail("service_unavailable"); throw error; }
    finally {
      if (timer !== undefined) clearTimeout(timer); signal.removeEventListener("abort", abort);
      borrow?.release(); permit?.release(); this.#execution?.release(); this.#execution = undefined;
      this.#route?.close(); this.#route = undefined; this.#input?.close(); this.#input = undefined;
      this.#working = false; this.close(); this.#collect();
    }
  }
  close(): void {
    if (!this.#closed) { this.#closed = true; this.#interest.lose("owner_unavailable", true); this.#interest.flush(); this.#abort.abort(); this.messages.close(); this.adapter.release(); }
    this.#collect();
  }
  #collect(): void {
    if (!this.#closed || this.#working || this.#cleaned || !this.messages.cleanupComplete()) return;
    this.#cleaned = true; this.#interest.endInvocation(); this.#target = undefined; this.#output.close(); this.codec.close(); this.#authorization?.release(); this.#authorization = undefined; this.#work.release(); this.cleanup.finishJob();
    this.#diagnostic?.close(); this.#diagnostic = undefined;
    const finished = this.#finished; this.#finished = undefined; finished?.();
  }
}
