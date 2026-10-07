import { DiagnosticActivity, type DiagnosticObserver } from "./diagnosticObservation.js";
import { ResponsePublication, responsePublicationCharge, type V4MaintenanceOwner } from "../responsePublication.js";
import { bindContentRead } from "../streamContent.js";
import { bindCheckpointIssuer } from "../checkpoint.js";
import type { CheckpointSessionPolicy } from "./checkpointToken.js";
import type { VolatileExecutionAttempt, RPCExecutionIdentity } from "./volatileExecutions.js";
import type { ContractRoutes } from "./contractRoutes.js";
import { serviceError, type V4UnaryContext } from "../serviceHandlers.js";
import type { V4AuthenticatedContext } from "../streamHandlers.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import { ApplicationHeaderCodec, applicationHeaderCharge, applicationHeaderDecoderCharge } from "./applicationHeader.js";
import type { ApplicationGroup, ApplicationPermit } from "./applicationExecutor.js";
import { byteLength } from "./cbor.js";
import type { TrustedClock } from "./clock.js";
import type { CapturedContractRoute } from "./contractRoutes.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { checkApplicationMessageOutput, messageInputBytes } from "./messageCodec.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { ResourceError, ResourceVector, type ResourceReference } from "./resources.js";
import type { RPCChannelRuntime } from "./rpcChannel.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCRequestInput } from "./rpcInput.js";
import type { RPCNetworkTicket } from "./rpcNetwork.js";
import { RPCOutputInterest, rpcOutputInterestCharge } from "./rpcOutputInterest.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { RPCUnaryHandlerCapture } from "./rpcUnaryRegistration.js";
import type { SessionCleanup } from "./sessionCleanup.js";
import { TimeError } from "./timeArithmetic.js";
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }), decodeUTF8 = TextDecoder.prototype.decode;
const encoder = new TextEncoder(), encodeUTF8 = TextEncoder.prototype.encode, codeUnit = String.prototype.charCodeAt;
type Codec = CapturedMethodDefinition["request"];
export function rpcUnaryDispatchCharges(inputBytes: number, responseLimit: number, method: CapturedMethodDefinition,
  handler: RPCUnaryHandlerCapture, runtimeBytes: bigint): readonly ResourceVector[] {
  if (method.shape !== "unary" || method.response === undefined) throw new RPCProtocolError("rpc_handler_binding");
  let resultBytes = 0n;
  for (const codec of [method.response, ...method.errors.map(error => error.codec)]) {
    const n = BigInt(codec.maximum) + (codec.application?.applicationBytes ?? (codec.implementation === "utf8" ? BigInt(codec.maximum) * 3n : 0n));
    if (n > resultBytes) resultBytes = n;
  }
  const requestBytes = method.request.application?.applicationBytes ?? (method.request.implementation === "utf8" ? BigInt(inputBytes) * 3n : 0n);
  return [new ResourceVector([8192n + 8n * runtimeBytes + requestBytes + resultBytes + handler.options.applicationBytes,
    0n, 0n, 24n, 2n, 4n, 1n, 0n, 0n, 0n, 0n]), rpcPayloadCharge(responseLimit, runtimeBytes),
  applicationHeaderCharge(runtimeBytes), applicationHeaderDecoderCharge(runtimeBytes), rpcOutputInterestCharge(runtimeBytes), ...(method.restartFlush ? [responsePublicationCharge(runtimeBytes)] : [])];
}
/** One full-input, prepaid result/handler owner. Transient methods bypass
 * execution history only; they still use the original K/ReplySlot, contract,
 * exact handler generation, ordinary permit and complete inline response. */
export class RPCUnaryDispatch implements RPCPublicationGuard {
  #reference: ResourceReference | undefined;
  #publication: ResponsePublication | undefined;
  get responsePublication(): ResponsePublication | undefined { return this.#publication; }
  #execution: VolatileExecutionAttempt | undefined;
  #routes: ContractRoutes | undefined;
  #executionIdentity: RPCExecutionIdentity | undefined;
  #input: RPCRequestInput | undefined;
  #borrow: RPCPayloadBorrow | undefined;
  #route: CapturedContractRoute | undefined;
  #handler: RPCUnaryHandlerCapture | undefined;
  #output: RPCPayload | undefined;
  #codec: ApplicationHeaderCodec | undefined;
  #interest: RPCOutputInterest | undefined;
  #bound = false;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #group: ApplicationGroup | undefined;
  #permit: ApplicationPermit | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #clock: TrustedClock | undefined;
  #deadline: TrustedDeadline | undefined;
  #runDeadline: TrustedDeadline | undefined;
  #cleanup: SessionCleanup | undefined;
  #job = false;
  #channel: RPCChannelRuntime | undefined;
  #ticket: RPCNetworkTicket | undefined;
  #session: AbortSignal | undefined;
  readonly #abort = new AbortController();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #closed = false;
  #started = false;
  #working = false;
  #workComplete = false;
  #busy = false;
  #collecting = false;
  #queued = false;
  #publicationPhysical = false;
  #outputHeld = false;
  #detached = false;
  #diagnostic: DiagnosticActivity | undefined;
  #onDetach: (() => void) | undefined;
  constructor(input: RPCRequestInput, route: CapturedContractRoute, channel: RPCChannelRuntime, ticket: RPCNetworkTicket,
    group: ApplicationGroup, authentication: V4AuthenticatedContext, clock: TrustedClock, delivery: ReceiveDeliveryGate,
    cleanup: SessionCleanup, session: AbortSignal, runtimeBytes: bigint, references: readonly ResourceReference[], permit?: ApplicationPermit, routes?: ContractRoutes, identity?: RPCExecutionIdentity, private readonly checkpointPolicy?: CheckpointSessionPolicy, maintenanceOwner?: V4MaintenanceOwner, diagnostics?: DiagnosticObserver) {
    const header = input.header, handler = route.handler;
    if (!["transient_unary_request", "execution_unary_request"].includes(header.kind) || handler === undefined ||
      (route.contract.semantics === "execution" && (handler.execution === undefined || routes === undefined || identity === undefined)) ||
      route.definition.restartFlush && maintenanceOwner === undefined || input.state !== "complete") throw new RPCProtocolError("rpc_handler_binding");
    const costs = rpcUnaryDispatchCharges(header.payloadBytes, Number(header.uint(8)), route.definition, handler, runtimeBytes);
    if (references.length !== costs.length || !references.every(reference => references[0]!.sameEnvironment(reference)) ||
      !route.contract.sameEnvironment(references[0]!) || !input.sameEnvironment(references[0]!)) throw new RPCProtocolError("rpc_handler_owner");
    if (handler.execution !== undefined && !handler.execution.sameEnvironment(references[0]!)) throw new RPCProtocolError("rpc_handler_owner");
    this.#reference = references[0]!.take(costs[0]!);
    this.#routes = routes; this.#executionIdentity = identity;
    this.#input = input; this.#route = route; this.#handler = handler; this.#channel = channel; this.#ticket = ticket;
    this.#group = group; this.#authentication = authentication; this.#clock = clock; this.#cleanup = cleanup; this.#session = session; this.#permit = permit;
    this.#busy = true;
    try {
      this.#diagnostic = new DiagnosticActivity(diagnostics, "application");
      cleanup.startJob(); this.#job = true;
      this.#deadline = input.forkDeadline();
      this.#output = new RPCPayload(Number(header.uint(8)), runtimeBytes, references[1]!);
      this.#codec = new ApplicationHeaderCodec(runtimeBytes, references[2]!, references[3]!);
      this.#interest = new RPCOutputInterest(runtimeBytes, references[4]!);
      if (route.definition.restartFlush) this.#publication = new ResponsePublication(maintenanceOwner!, runtimeBytes, references[5]!);
      this.#lease = delivery.retain(this.#reference, () => this.close());
      session.addEventListener("abort", this.#sessionClosed, { once: true });
      if (session.aborted) throw new RPCProtocolError("service_unavailable");
      this.check(); channel.bindOutput(ticket, this.#interest); this.#bound = true;
      this.#interest.observe(() => this.#outputChanged()); Object.freeze(this);
    } catch (error) { this.#closed = true; throw error; }
    finally { this.#busy = false; this.#collect(); }
  }
  readonly #sessionClosed = (): void => this.close();
  check(): void {
    if (this.#closed || this.#reference === undefined) throw new RPCProtocolError("service_unavailable");
    this.#reference.checkRetained(); this.#deadline!.check(); this.#publication?.check();
    if (!this.#workComplete) this.#runDeadline?.check();
    this.#lease!.check(); this.#handler!.check();
    if (this.#closed || this.#session?.aborted) throw new RPCProtocolError("service_unavailable");
  }
  current(): boolean { return !this.#closed && this.#handler?.current() === true && !this.#session?.aborted; }
  onDetach(callback: () => void): void {
    if (this.#onDetach !== undefined) throw new RPCProtocolError("rpc_handler_owner");
    if (this.#detached) callback(); else this.#onDetach = callback;
  }
  start(): void {
    if (this.#closed) return;
    if (this.#started) throw new RPCProtocolError("rpc_handler_owner"); this.#started = true;
    this.#working = true;
    try { this.#channel?.flushOutputEvents(); this.#tick(); } catch (error) { this.#fail(error); }
    void this.#run();
  }
  async #beginRun(): Promise<void> {
    if (this.#runDeadline !== undefined) return;
    this.check();
    const sample = this.#clock!.sample();
    this.#runDeadline = this.#deadline!.forkAgeAt(sample, this.#route!.contract.uint(this.#execution === undefined ? 12 : 18));
    this.check();
    (await this.#execution?.enter(() => this.check())); this.check();
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    this.#tick();
  }
  readonly #tick = (): void => {
    this.#timer = undefined; if (this.#closed || this.#reference === undefined) return;
    try {
      this.check(); let remaining = this.#deadline!.remainingMS();
      if (!this.#workComplete && this.#runDeadline !== undefined) {
        const run = this.#runDeadline.remainingMS(); if (run < remaining) remaining = run;
      }
      if (!this.#closed) this.#timer = setTimeout(this.#tick, timerChunk(remaining));
    } catch (error) { this.#fail(error); }
  };
  async #run(): Promise<void> {
    let invocation: Readonly<{ context: V4UnaryContext; release(): void }> | undefined, callback = false;
    let unbindContent: (() => void) | undefined;
    let unbindCheckpoint: (() => void) | undefined, checkpointSelected = false, checkpointCommitted = false;
    try {
      this.check();
      const handler = this.#handler!, definition = this.#route!.definition;
      this.#permit ??= await this.#group!.acquire(handler.options.workClass, this.#abort.signal, () => this.check());
      this.check();
      invocation = this.#group!.context(this.#permit, this.#authentication!, this.#abort.signal, this.#interest!.view, this.#publication);
      this.#interest!.attach(invocation.context);
      const enter = (): void => { if (!callback) { callback = true; this.#cleanup!.enterCallback(); } };
      if (handler.options.authorization !== "authenticated") {
        (await enter());
        const authorized = await handler.options.authorization(invocation.context);
        this.check();
        if (authorized !== true) throw new RPCProtocolError("permission_denied");
      }
      if (handler.execution !== undefined) {
        this.#execution = (await handler.execution.admit(this.#input!, this.#route!, this.#routes!, this.#authentication!, this.#executionIdentity!, this, () => this.#abort.abort()));
        this.#routes = undefined;
        this.#executionIdentity = undefined;
        if (!this.#execution.created) {
          // A duplicate retains only its real response/input responsibility.
          // It never holds an ordinary application permit while joining work.
          invocation.release(); invocation = undefined; this.#permit?.release(); this.#permit = undefined;
          if (callback) { this.#cleanup!.exitCallback(); callback = false; }
          await this.#execution.wait(this.#abort.signal); this.check();
          const result = this.#execution.copyResult(this.#output!); this.check();
          if (result.sdkError !== undefined) this.#reply(result.sdkError);
          else if (this.#interest!.view.interested) this.#publish(result.bytes, result.applicationError);
          return;
        }
      }
      this.#borrow = this.#input!.borrow();
      const requestCodec = definition.request;
      let request: unknown;
      if (requestCodec.application === undefined)
        request = requestCodec.implementation === "bytes" ? this.#borrow.bytes : decodeUTF8.call(utf8, this.#borrow.bytes);
      else {
        (await this.#beginRun());
        (await enter());
        request = requestCodec.application.execution === "sync" ? requestCodec.application.decode(invocation.context, this.#borrow.bytes)
          : await requestCodec.application.decode(invocation.context, this.#borrow.bytes);
      }
      this.check();
      (await this.#beginRun());
      (await enter());
      unbindCheckpoint = bindCheckpointIssuer(invocation.context, async (original, checkpoint, options) => {
        this.check();
        if (checkpointSelected || this.#execution === undefined || this.checkpointPolicy === undefined ||
          definition.response?.implementation !== "bytes") throw new RPCProtocolError("service_unavailable");
        // Seal before key use. Even an application catching a failed commit
        // cannot retry signing or publish an unrelated successful result.
        checkpointSelected = true;
        (await this.#execution.issueCheckpoint(original, checkpoint, options, this.checkpointPolicy, this.#runDeadline!.cap, () => this.check()));
        checkpointCommitted = true;
        return Object.freeze({ kind: "checkpoint_result" as const });
      });
      unbindContent = bindContentRead(invocation.context, async (target, position, destination) => {
        this.check();
        if (this.#execution === undefined) throw new RPCProtocolError("service_unavailable");
        return (await this.#execution.readContent(target, position, destination, definition.typeID, () => this.check()));
      });
      let value: unknown, errorCode: number | undefined;
      try { value = await handler.handler(invocation.context, request); }
      catch (error) {
        // Once committed, the original token remains the outcome even if
        // application cleanup subsequently throws.
        if (!checkpointCommitted) {
          const applicationError = serviceError(error); if (applicationError === undefined) throw error;
          errorCode = applicationError.code; value = applicationError.value;
        }
      }
      this.#publication?.endHandler();
      request = undefined;
      unbindContent();
      unbindContent = undefined;
      this.check();
      unbindCheckpoint();
      unbindCheckpoint = undefined;
      if (checkpointSelected) {
        if (!checkpointCommitted) throw new RPCProtocolError("service_failed");
        const result = this.#execution!.copyResult(this.#output!);
        if (result.sdkError !== undefined) this.#reply(result.sdkError);
        else if (this.#interest!.view.interested) this.#publish(result.bytes, result.applicationError);
        return;
      }
      // STOP only relinquishes response work. It never restarts or cancels the
      // already admitted business invocation or pretends it did not execute.
      if (this.#execution === undefined && !this.#interest!.view.interested) return;
      const selectedError = errorCode === undefined ? undefined : definition.errors.find(error => error.code === errorCode);
      const resultCodec = errorCode === undefined ? definition.response! : selectedError?.codec;
      if (resultCodec === undefined) throw new RPCProtocolError("service_failed");
      const limit = Math.min(Number(this.#input!.header.uint(8)), selectedError?.maximum ?? definition.maxResponseBytes);
      const encoded = await this.#encode(resultCodec, value, invocation.context, limit);
      value = undefined;
      this.check();
      if (this.#execution === undefined && !this.#interest!.view.interested) return;
      const bytes = checkApplicationMessageOutput(encoded, resultCodec.maximum);
      if (byteLength(bytes) > limit) throw new RPCProtocolError("service_failed");
      // Retain the actual outcome before publishing it. STOP_OUTPUT or a lost
      // response cannot erase history or turn the same key into new work.
      (await this.#execution?.finish(bytes, errorCode, this.#runDeadline!.cap));
      if (!this.#interest!.view.interested) return;
      this.#output!.write(0, bytes);
      this.#publish(byteLength(bytes), errorCode);
    }
    catch (error) { this.#fail(error); }
    finally {
      this.#publication?.endHandler();
      unbindContent?.(); unbindCheckpoint?.(); this.#interest?.endInvocation(); invocation?.release(); this.#permit?.release(); this.#permit = undefined;
      if (callback) this.#cleanup!.exitCallback();
      this.#borrow?.release(); this.#borrow = undefined; this.#input?.close(); this.#input = undefined;
      this.#execution?.exit();
      this.#working = false; this.#workComplete = true;
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
      if (!this.#detached && !this.#closed) this.#tick(); this.#collect();
    }
  }
  #publish(length: number, errorCode: number | undefined): void {
    const execution = this.#input!.header.kind === "execution_unary_request";
    const kind = execution ? errorCode === undefined ? "execution_unary_response" : "execution_unary_application_error"
      : errorCode === undefined ? "transient_unary_response" : "transient_unary_application_error";
    const response = this.#codec!.response(this.#input!.header, kind, length, errorCode);
    this.#route!.contract.checkResponse(this.#input!.header, response); this.check();
    if (!this.current() || this.#channel === undefined) throw new RPCProtocolError("service_unavailable");
    this.#publication?.select(this.#deadline!, this.#clock!, this.#route!.definition.restartFlushDeadlineMS!);
    const original = this.#output!.borrow(response.payloadBytes); this.#outputHeld = true;
    const payload: RPCPayloadBorrow = Object.freeze({
      bytes: original.bytes, retainSend: original.retainSend, release: () => {
        original.release(); this.#outputHeld = false; this.#detach(); this.#collect();
      }
    });
    try { this.#channel.queueResponse(this.#ticket!, response, payload, this); this.#queued = true; this.#output!.close(); }
    catch (error) { payload.release(); throw error; }
  }
  async #encode(codec: Codec, value: unknown, context: V4UnaryContext, limit: number): Promise<Uint8Array> {
    const application = codec.application;
    if (application !== undefined) return application.execution === "sync" ? application.encode(context, value) : await application.encode(context, value);
    if (codec.implementation === "bytes") { messageInputBytes(value, "bytes", limit); return value as Uint8Array; }
    messageInputBytes(value, "utf8", limit);
    const text = value as string; let bytes = 0;
    for (let index = 0; index < text.length; index++) {
      const cp = codeUnit.call(text, index);
      if (cp >= 0xd800 && cp <= 0xdbff) {
        const next = codeUnit.call(text, ++index);
        if (!Number.isFinite(next) || next < 0xdc00 || next > 0xdfff) throw new RPCProtocolError("service_failed"); bytes += 4;
      } else if (cp >= 0xdc00 && cp <= 0xdfff) throw new RPCProtocolError("service_failed");
      else bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : 3;
      if (bytes > limit) throw new RPCProtocolError("service_failed");
    }
    return encodeUTF8.call(encoder, text);
  }
  #outputChanged(): void {
    const reason = this.#interest!.progress().reason;
    if (reason === "owner_unavailable") { this.close(); return; }
    if (reason === "response_output_stopped") this.#publication?.unknown("response_superseded");
    if (reason === "response_output_stopped" && !this.#queued) this.#reply("response_output_stopped");
    if (reason !== undefined) this.#detach();
  }
  #reply(code: RPCSDKError): void {
    if (this.#queued || this.#channel === undefined) return;
    // The SDK reply replaces the original business result. Preserve the
    // original deadline cause when it caused the replacement; other SDK
    // replacements are explicit supersession. Neither can become flushed.
    this.#publication?.unknown(code === "deadline_exceeded" ? "deadline" : "response_superseded");
    try { this.#channel.replySDK(this.#ticket!, code, this); this.#queued = true; }
    catch { /* The original channel owns any failed fixed refusal. */ }
  }
  #fail(error: unknown): void {
    this.#diagnostic?.failure(error);
    const code: RPCSDKError = error instanceof TimeError && ["time_expired", "time_cancelled"].includes(error.code) ? "deadline_exceeded"
      : error instanceof ResourceError && error.code === "resource_exhausted" ? "resource_exhausted"
        : error instanceof RPCProtocolError && ["permission_denied", "resource_exhausted", "service_unavailable", "operation_conflict", "result_expired", "deadline_exceeded"].includes(error.code) ? error.code as RPCSDKError : "service_failed";
    this.#execution?.fail(code); this.#reply(code); this.close();
  }
  publicationPhysicalComplete(): void {
    this.#publicationPhysical = true;
    this.#publication?.physicalDone();
    if (!this.#working) this.#publication = undefined;
    this.#collect();
  }
  #detach(): void {
    if (this.#detached) return; this.#detached = true;
    this.#channel = undefined; this.#ticket = undefined; this.#interest?.unobserve();
    const callback = this.#onDetach; this.#onDetach = undefined; callback?.();
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#publication?.unknown("owner_unavailable");
    if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#execution?.fail("service_unavailable");
    this.#detach(); this.#session?.removeEventListener("abort", this.#sessionClosed); this.#session = undefined;
    this.#lease?.release(); this.#lease = undefined; this.#clock = undefined; this.#deadline = this.#runDeadline = undefined;
    this.#group = undefined; this.#authentication = undefined; this.#routes = undefined; this.#executionIdentity = undefined;
    this.#abort.abort(); this.#collect();
  }

  #collect(): void {
    if (this.#busy || this.#collecting || this.#working || this.#outputHeld || !this.#closed && !this.#workComplete) return;
    if (!this.#detached && this.#queued) return;
    this.#collecting = true;
    try {
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
      this.#detach(); this.#session?.removeEventListener("abort", this.#sessionClosed); this.#session = undefined;
      this.#interest?.endInvocation();
      if (!this.#bound) { this.#interest?.lose("owner_unavailable", true); this.#interest?.flush(); }
      this.#interest = undefined; this.#permit?.release(); this.#permit = undefined;
      this.#input?.close(); this.#input = undefined; this.#borrow?.release(); this.#borrow = undefined;
      this.#output?.close(); this.#output = undefined; this.#codec?.close(); this.#codec = undefined;
      this.#lease?.release(); this.#lease = undefined; this.#route?.close(); this.#route = undefined; this.#handler = undefined;
      this.#group = undefined; this.#authentication = undefined; this.#clock = undefined; this.#deadline = this.#runDeadline = undefined;
      this.#execution?.release(); this.#execution = undefined; this.#routes = undefined; this.#executionIdentity = undefined;
      this.#publication?.endHandler();
      if (!this.#queued) this.#publication?.physicalDone();
      if (!this.#queued || this.#publicationPhysical) this.#publication = undefined;
      if (this.#workComplete) this.#diagnostic?.event({ state: "ready", code: "ok" });
      this.#diagnostic?.close(); this.#diagnostic = undefined;
      this.#reference?.release(); this.#reference = undefined;
      if (this.#job) { this.#job = false; this.#cleanup!.finishJob(); } this.#cleanup = undefined;
    } finally { this.#collecting = false; }
  }
}
Object.freeze(RPCUnaryDispatch.prototype);
Object.freeze(RPCUnaryDispatch);
