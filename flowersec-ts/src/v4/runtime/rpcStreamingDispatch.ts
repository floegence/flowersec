import type * as ServiceHandlersTypes from "../serviceHandlers.js";
import { bindContentSave } from "../streamContent.js";
import type { CapturedByteEventSource } from "../eventSource.js";
import { RPCEventSource, eventSourceCharge } from "./rpcEventSource.js";
import { transportV4ApplicationHeaders } from "../../generated/transportV4Registry.js";
import { serviceError, type V4StreamWriter } from "../serviceHandlers.js";
import type { V4ApplicationContext, V4AuthenticatedContext } from "../streamHandlers.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import type { ApplicationGroup, ApplicationPermit } from "./applicationExecutor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import type { TrustedClock } from "./clock.js";
import type { CapturedContractRoute, ContractRoutes } from "./contractRoutes.js";
import type { RPCExecutionIdentity, VolatileExecutionAttempt } from "./volatileExecutions.js";
import { timerChunk, type TrustedDeadline } from "./deadline.js";
import { timeAdd } from "./timeArithmetic.js";
import { checkApplicationMessageOutput, messageInputBytes } from "./messageCodec.js";
import type { ReceiveDeliveryGate } from "./receiveDirection.js";
import { ResourceVector, type ResourceReference } from "./resources.js";
import type { RPCSDKError } from "./rpcCompletion.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { RPCRequestInput } from "./rpcInput.js";
import type { RPCNetwork, RPCNetworkTicket } from "./rpcNetwork.js";
import { RPCOutputInterest, rpcOutputInterestCharge } from "./rpcOutputInterest.js";
import { RPCPayload, rpcPayloadCharge, type RPCPayloadBorrow } from "./rpcPayload.js";
import type { RPCStreamMessages } from "./rpcStreamMessages.js";
import { encodeText } from "./rpcUnaryPreparation.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";
import type { ServiceInputs } from "./serviceInputs.js";
import type { SessionCleanup } from "./sessionCleanup.js";

export function rpcStreamingDispatchCharges(method: CapturedMethodDefinition, applicationBytes: bigint, runtimeBytes: bigint, source?: CapturedByteEventSource): readonly ResourceVector[] {
  let resultBytes = 0n;
  for (const codec of [method.response!, ...method.errors.map(error => error.codec)]) {
    const amount = BigInt(codec.maximum) + (codec.application?.applicationBytes ?? (codec.implementation === "utf8" ? BigInt(codec.maximum) * 3n : 0n));
    if (amount > resultBytes) resultBytes = amount;
  }
  const inputBytes = method.request.application?.applicationBytes ?? BigInt(method.requestMaxBytes) * 3n;
  return [new ResourceVector([12288n + runtimeBytes * 8n + inputBytes + resultBytes + applicationBytes, 0n, 0n, 24n, 2n, 5n, 2n, 0n, 0n, 0n, 0n]),
    rpcPayloadCharge(Math.max(method.maxResponseBytes, 256), runtimeBytes), rpcOutputInterestCharge(runtimeBytes),
    ...(source === undefined ? [] : [eventSourceCharge(source, runtimeBytes)])];
}
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const decodeUTF8 = TextDecoder.prototype.decode;
/** Original full-input handler and serial result writer. Arbitrary generators
 * keep the same ordinary invocation across every await and network write. */
export class RPCStreamingDispatch {
  #source: RPCEventSource | undefined;
  #sourceCleanupStarted = false;
  #sourceCleanupRunning = false;
  #reference: ResourceReference | undefined;
  #messages: RPCStreamMessages | undefined;
  #network: RPCNetwork | undefined;
  #ticket: RPCNetworkTicket | undefined;
  #inputs: ServiceInputs | undefined;
  #input: RPCRequestInput | undefined;
  #request: ApplicationHeader | undefined;
  #route: CapturedContractRoute | undefined;
  #routes: ContractRoutes | undefined;
  #executionIdentity: RPCExecutionIdentity | undefined;
  #execution: VolatileExecutionAttempt | undefined;
  #executionEntered = false;
  #output: RPCPayload | undefined;
  #interest: RPCOutputInterest | undefined;
  #lease: ReturnType<ReceiveDeliveryGate["retain"]> | undefined;
  #group: ApplicationGroup | undefined;
  #authentication: V4AuthenticatedContext | undefined;
  #cleanup: SessionCleanup | undefined;
  #clock: TrustedClock | undefined;
  #deadline: TrustedDeadline | undefined;
  #initialDeadline: TrustedDeadline | undefined;
  #runDeadline: TrustedDeadline | undefined;
  #terminalDeadline: TrustedDeadline | undefined;
  #contract: ServiceContractSnapshot | undefined;
  #releaseWork: (() => void) | undefined;
  #working = false;
  #callback = false;
  #started = false;
  #sending = false;
  #writeTask: Promise<void> | undefined;
  #acceptingWrites = false;
  #terminal: RPCSDKError | undefined;
  #terminalSent = false;
  #terminalTask = false;
  #closed = false;
  #collecting = false;
  #items = 0n;
  #bytes = 0n;
  #timer: ReturnType<typeof setTimeout> | undefined;
  readonly #abort = new AbortController();
  #finished: (() => void) | undefined;
  constructor(messages: RPCStreamMessages, network: RPCNetwork, ticket: RPCNetworkTicket, inputs: ServiceInputs,
    contract: ServiceContractSnapshot, method: CapturedMethodDefinition, applicationBytes: bigint, group: ApplicationGroup,
    authentication: V4AuthenticatedContext, clock: TrustedClock, deadline: TrustedDeadline, delivery: ReceiveDeliveryGate,
    cleanup: SessionCleanup, runtimeBytes: bigint, references: readonly ResourceReference[], routes?: ContractRoutes, identity?: RPCExecutionIdentity, source?: CapturedByteEventSource,
    reserveEvent?: (charge: ResourceVector) => ResourceReference) {
    const costs = rpcStreamingDispatchCharges(method, applicationBytes, runtimeBytes, source);
    this.#reference = references[0]!.take(costs[0]!); this.#messages = messages; this.#network = network; this.#ticket = ticket; this.#inputs = inputs;
    this.#group = group; this.#authentication = authentication; this.#clock = clock; this.#deadline = deadline; this.#routes = routes; this.#executionIdentity = identity;
    this.#cleanup = cleanup; cleanup.startJob(); this.#contract = contract.retain();
    try {
      this.#initialDeadline = deadline.forkAgeAt(clock.sample(), 30000n);
      this.#output = new RPCPayload(Math.max(method.maxResponseBytes, 256), runtimeBytes, references[1]!);
      this.#interest = new RPCOutputInterest(runtimeBytes, references[2]!);
      if (source !== undefined) {
        if (reserveEvent === undefined) throw new RPCProtocolError("event_source_owner");
        this.#source = new RPCEventSource(source, runtimeBytes, references[3]!, clock, reserveEvent, () => this.#check());
        this.#abort.signal.addEventListener("abort", () => this.#source?.close(), { once: true });
      }
      this.#lease = delivery.retain(this.#reference, () => this.close());
      this.#releaseWork = network.retainStream(ticket, messages);
      messages.onChange(() => { if ((messages.closed || messages.physicalComplete) && !this.#closed) this.close(); this.#collect(); }); Object.freeze(this);
    } catch (error) { this.close(); throw error; }
  }
  onCleanup(callback: () => void): void { if (this.#finished !== undefined) throw new RPCProtocolError("rpc_stream_owner"); this.#finished = callback; this.#collect(); }
  start(): void {
    if (this.#started || this.#closed) throw new RPCProtocolError("rpc_stream_owner"); this.#started = this.#working = true; this.#tick(); void this.#run();
  }
  #check(run = true): void {
    if (this.#closed) throw new RPCProtocolError("service_unavailable");
    this.#reference!.checkRetained(); this.#lease!.check();
    (run ? this.#deadline! : this.#terminalDeadline ?? this.#deadline!).check(); this.#route?.streaming?.check();
    this.#initialDeadline?.check();
    if (run) { if (this.#terminal !== undefined) throw new RPCProtocolError(this.#terminal); this.#runDeadline?.check(); }
    if (this.#closed) throw new RPCProtocolError("service_unavailable");
  }
  #beginRun(): void {
    if (this.#runDeadline === undefined) {
      const run = this.#contract!.uint(this.#contract!.semantics === "execution" ? 18 : 12);
      const cap = run < this.#contract!.uint(26) ? run : this.#contract!.uint(26);
      this.#runDeadline = this.#deadline!.forkAgeAt(this.#clock!.sample(), cap);
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#tick();
    }
    if (this.#execution !== undefined && !this.#executionEntered) { this.#execution.enter(); this.#executionEntered = true; }
  }
  readonly #tick = (): void => {
    this.#timer = undefined; if (this.#closed || this.#terminalSent) return;
    try {
      this.#check(); let remaining = this.#deadline!.remainingMS();
      if (this.#initialDeadline !== undefined) { const initial = this.#initialDeadline.remainingMS(); if (initial < remaining) remaining = initial; }
      if (this.#runDeadline !== undefined) { const run = this.#runDeadline.remainingMS(); if (run < remaining) remaining = run; }
      this.#timer = setTimeout(this.#tick, timerChunk(remaining));
    } catch { this.#requestTerminal("deadline_exceeded"); }
  };
  #requestTerminal(code: RPCSDKError): void {
    this.#terminal ??= code; this.#source?.close(); this.#execution?.fail(code); this.#abort.abort();
    if (!this.#sending && !this.#terminalTask && !this.#terminalSent && this.#request !== undefined && this.#messages?.eof) {
      this.#terminalTask = true; void this.#sendTerminal();
    } else if (this.#request === undefined || !this.#messages?.eof) this.close();
  }
  async #sendTerminal(): Promise<void> {
    try {
      this.#check(false);
      const bytes = new FixedCBORWriter(new Uint8Array(256)).map(1).uint(0).uint(transportV4ApplicationHeaders.sdk_error_codes[this.#terminal!]).result();
      const header = this.#messages!.codec().response(this.#request!, this.#request!.has(1) ? "execution_stream_sdk_error" : "transient_stream_sdk_error", bytes.length);
      await this.#messages!.send(header, bytes, () => this.#check(false)); await this.#messages!.closeWrite(); this.#terminalSent = true; await this.#messages!.finish();
    } catch { /* The original stream owns the failed publication and cleanup. */ }
    finally { this.#terminalTask = false; this.close(); this.#collect(); }
  }
  async #run(): Promise<void> {
    let unbindContent: (() => void) | undefined;
    let permit: ApplicationPermit | undefined, invocation: Readonly<{ context: V4ApplicationContext; release(): void }> | undefined, borrow: RPCPayloadBorrow | undefined;
    try {
      const header = await this.#messages!.read(request => {
        this.#check(); this.#contract!.checkRequest(request);
        if (request.kind !== "transient_stream_request" && request.kind !== "execution_stream_request") throw new RPCProtocolError("rpc_request_variant");
        this.#network!.bindIncomingStream(this.#ticket!, this.#messages!, request); this.#request = request;
        const terminalCap = timeAdd(request.uint(5), 5000n);
        this.#terminalDeadline = this.#deadline!.fork(terminalCap < this.#deadline!.cap ? terminalCap : this.#deadline!.cap);
        this.#deadline = this.#deadline!.fork(request.uint(5) < this.#deadline!.cap ? request.uint(5) : this.#deadline!.cap);
        const input = this.#inputs!.openInput(this.#ticket!, request); this.#input = input; return input;
      }, this.#abort.signal);
      if (header === undefined) throw new RPCProtocolError("rpc_stream_incomplete");
      this.#network!.completeStreamRequest(this.#ticket!, this.#messages!); this.#network!.inputComplete(this.#ticket!, this.#input!.state === "complete");
      this.#messages!.consume(); await this.#messages!.requireEOF(this.#abort.signal); this.#check();
      this.#initialDeadline = undefined;
      if (this.#timer !== undefined) clearTimeout(this.#timer); this.#tick();
      if (this.#input!.refusal !== undefined) throw new RPCProtocolError(this.#input!.refusal);
      this.#route = this.#input!.takeRoute(); const handler = this.#route.streaming;
      if (handler === undefined) throw new RPCProtocolError("service_unavailable");
      handler.admit();
      permit = header.uint(7) === 1n ? this.#group!.tryOrdinary(handler.options.workClass) : await this.#group!.acquire(handler.options.workClass, this.#abort.signal, () => this.#check());
      invocation = this.#group!.context(permit, this.#authentication!, this.#abort.signal);
      const enter = (): void => { if (!this.#callback) { this.#callback = true; this.#cleanup!.enterCallback(); } };
      if (handler.options.authorization !== "authenticated") {
        this.#beginRun(); enter(); const allowed = await (handler.options.authorization as (context: V4ApplicationContext) => boolean | Promise<boolean>)(invocation.context); this.#check();
        if (allowed !== true) throw new RPCProtocolError("permission_denied");
      }
      if (this.#contract!.semantics === "execution") {
        if (handler.execution === undefined || this.#routes === undefined || this.#executionIdentity === undefined) throw new RPCProtocolError("service_unavailable");
        this.#execution = handler.execution.admit(this.#input!, this.#route!, this.#routes, this.#authentication!, this.#executionIdentity,
          { check: () => this.#check(), current: () => !this.#closed && this.#route?.streaming?.current() === true }, () => this.#abort.abort());
        this.#routes = undefined; this.#executionIdentity = undefined;
        if (!this.#execution.created) {
          // Join observes the one original execution. No request decoder,
          // generator, application permit, or saved-item replay is created.
          invocation.release(); invocation = undefined; permit.release(); permit = undefined;
          if (this.#callback) { this.#callback = false; this.#cleanup!.exitCallback(); }
          await this.#execution.wait(this.#abort.signal); this.#check();
          this.#requestTerminal("service_unavailable"); return;
        }
      }
      borrow = this.#input!.borrow(); const definition = this.#route.definition, codec = definition.request;
      let request: unknown;
      if (codec.application === undefined) request = codec.implementation === "bytes" ? borrow.bytes : decodeUTF8.call(utf8, borrow.bytes);
      else { this.#beginRun(); enter(); request = codec.application.execution === "sync" ? codec.application.decode(invocation.context, borrow.bytes) : await codec.application.decode(invocation.context, borrow.bytes); }
      this.#check(); this.#beginRun(); enter();
      const context = invocation.context;
      unbindContent = bindContentSave(context, (position, payload) => {
        this.#check();
        if (this.#execution === undefined) throw new RPCProtocolError("service_unavailable");
        return this.#execution.saveContent(position, payload, this.#runDeadline!.cap, () => this.#check());
      });
      let sourceError: number | undefined;
      if (this.#source !== undefined) {
        const disposer = await this.#source.source.setup(context, request, this.#source.publisher); request = undefined;
        this.#source.setupFinished(disposer);
        // A pending setup cannot run a mapper or publish an item. Its actual
        // invocation exits before the one SDK pump can take queued input.
        unbindContent?.(); unbindContent = undefined;
        invocation.release(); invocation = undefined; permit.release(); permit = undefined; borrow.release(); borrow = undefined;
        if (this.#callback) { this.#callback = false; this.#cleanup!.exitCallback(); }
        this.#check(); sourceError = await this.#pumpEvents();
      } else {
        const writer: V4StreamWriter<unknown> = Object.freeze({ write: (value: unknown) => {
          if (this.#writeTask !== undefined || !this.#acceptingWrites || this.#closed) return Promise.reject(new RPCProtocolError("write_in_progress"));
          const task = this.#write(value, context); this.#writeTask = task;
          void task.then(() => { if (this.#writeTask === task) this.#writeTask = undefined; }, () => { if (this.#writeTask === task) this.#writeTask = undefined; });
          return task;
        } });
        this.#acceptingWrites = true;
        try {
        const generated = (handler.handler as ServiceHandlersTypes.V4StreamingHandler<unknown, unknown>)(context, request, writer); request = undefined;
        // Arbitrary generator execution is application work for the complete
        // production lifetime, including its iterator and network awaits.
        if (generated !== undefined && typeof (generated as AsyncIterable<unknown>)[Symbol.asyncIterator] === "function") {
          for await (const value of generated as AsyncIterable<unknown>) { this.#check(); await writer.write(value); }
        } else await generated;
        } finally { this.#acceptingWrites = false; unbindContent?.(); unbindContent = undefined; }
      }
      this.#check(); if (this.#sending) throw new RPCProtocolError("write_in_progress");
      if (sourceError === undefined) this.#execution?.finishStreaming(this.#runDeadline!.cap);
      await this.#messages!.closeWrite(); this.#terminalSent = true; await this.#messages!.finish(); this.close();
    } catch (error) {
      const business = serviceError(error);
      if (!this.#closed && this.#source?.failure !== undefined) this.#requestTerminal(this.#source.failure);
      else if (business !== undefined && !this.#closed && this.#terminal === undefined && invocation !== undefined) {
        try { await this.#write(business.value, invocation.context, business.code); await this.#messages!.closeWrite(); this.#terminalSent = true; await this.#messages!.finish(); this.close(); }
        catch { this.#requestTerminal("service_failed"); }
      } else if (!this.#closed) this.#requestTerminal(error instanceof RPCProtocolError && ["permission_denied", "resource_exhausted", "service_contract_mismatch", "response_limit_unsupported", "deadline_exceeded", "service_unavailable", "operation_conflict", "source_overflow"].includes(error.code) ? error.code as RPCSDKError : "service_failed");
    } finally {
      unbindContent?.();
      // A handler may return before an already-entered encoder/write does.
      // The same invocation and permit remain charged until that work exits.
      try { await this.#writeTask; } catch { /* Publication already owns failure. */ }
      this.#interest?.endInvocation(); invocation?.release(); permit?.release(); borrow?.release();
      if (this.#callback) { this.#callback = false; this.#cleanup!.exitCallback(); }
      if (this.#source === undefined) this.#execution?.exit();
      this.#working = false; this.#releaseWork?.(); this.#releaseWork = undefined; this.#collect();
    }
  }
  async #pumpEvents(): Promise<number | undefined> {
    const source = this.#source!, handler = this.#route!.streaming!;
    for (;;) {
      this.#check(); if (source.failure !== undefined) throw new RPCProtocolError(source.failure);
      if (this.#abort.signal.aborted) throw new RPCProtocolError("service_unavailable");
      let input = source.take();
      if (input === undefined) { if (source.ended) return; await source.wait(); continue; }
      let permit: ApplicationPermit | undefined, invocation: Readonly<{ context: V4ApplicationContext; release(): void }> | undefined;
      let unbindContent: (() => void) | undefined;
      const release = (): void => {
        unbindContent?.(); unbindContent = undefined;
        invocation?.release(); invocation = undefined; permit?.release(); permit = undefined;
        if (this.#callback) { this.#callback = false; this.#cleanup!.exitCallback(); }
        source.releaseCurrent(); input = undefined;
      };
      try {
        permit = await this.#group!.acquire(handler.options.workClass, this.#abort.signal, () => {
          this.#check(); if (source.failure !== undefined) throw new RPCProtocolError(source.failure);
        });
        this.#check(); if (source.failure !== undefined) throw new RPCProtocolError(source.failure);
        invocation = this.#group!.context(permit, this.#authentication!, this.#abort.signal);
        this.#callback = true; this.#cleanup!.enterCallback();
        unbindContent = bindContentSave(invocation.context, (position, payload) => {
          this.#check();
          if (this.#execution === undefined) throw new RPCProtocolError("service_unavailable");
          return this.#execution.saveContent(position, payload, this.#runDeadline!.cap, () => this.#check());
        });
        let value = await source.source.map(invocation.context, input);
        this.#check(); if (source.failure !== undefined) throw new RPCProtocolError(source.failure);
        // Once the complete encoded item is copied into the original output
        // owner, network backpressure is pure SDK work and holds no permit.
        const publication = this.#write(value, invocation.context, undefined, release); value = undefined;
        await publication;
      } catch (error) {
        const business = serviceError(error);
        if (business === undefined || invocation === undefined || this.#closed || this.#terminal !== undefined || source.failure !== undefined) throw error;
        source.close(); await this.#write(business.value, invocation.context, business.code, release); return business.code;
      } finally { release(); }
    }
  }
  async #write(value: unknown, context: V4ApplicationContext, errorCode?: number, encoded?: () => void): Promise<void> {
    this.#check(); if (this.#sending || this.#terminalSent) throw new RPCProtocolError("write_in_progress"); this.#sending = true;
    let borrow: RPCPayloadBorrow | undefined;
    try {
      const definition = this.#route!.definition, selected = errorCode === undefined ? undefined : definition.errors.find(error => error.code === errorCode);
      const codec = errorCode === undefined ? definition.response! : selected?.codec;
      if (codec === undefined) throw new RPCProtocolError("application_error_code");
      const limit = Math.min(Number(this.#request!.uint(8)), selected?.maximum ?? definition.maxResponseBytes);
      messageInputBytes(value, codec.implementation, codec.maximum);
      let result: unknown = codec.application === undefined ? codec.implementation === "bytes" ? value as Uint8Array : encodeText(value as string, limit)
        : codec.application.execution === "sync" ? codec.application.encode(context, value) : await codec.application.encode(context, value);
      let bytes: Uint8Array | undefined = checkApplicationMessageOutput(result, codec.maximum); this.#check();
      if (this.#source?.failure !== undefined) throw new RPCProtocolError(this.#source.failure);
      if (bytes.length > limit || errorCode === undefined && (this.#items >= this.#contract!.uint(24) || BigInt(bytes.length) > this.#contract!.uint(25) - this.#bytes)) throw new RPCProtocolError("service_failed");
      this.#output!.write(0, bytes); borrow = this.#output!.borrow(bytes.length);
      const kind = this.#request!.has(1) ? errorCode === undefined ? "execution_stream_item" : "execution_stream_application_error"
        : errorCode === undefined ? "transient_stream_item" : "transient_stream_application_error";
      const header = this.#messages!.codec().response(this.#request!, kind, bytes.length, errorCode);
      this.#contract!.checkResponse(this.#request!, header);
      // A terminal application error is already a complete outcome. Persist
      // its execution metadata after encoding validation and before publishing
      // any terminal bytes, including errors produced by an event source.
      if (errorCode !== undefined) this.#execution?.finishStreaming(this.#runDeadline!.cap, errorCode);
      const length = bytes.length; value = result = bytes = undefined; encoded?.();
      await this.#messages!.send(header, borrow.bytes, () => this.#check(false));
      if (errorCode === undefined) { this.#items++; this.#bytes += BigInt(length); }
    } finally {
      borrow?.release(); this.#sending = false;
      if (this.#terminal !== undefined) this.#requestTerminal(this.#terminal); this.#collect();
    }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true; this.#source?.close(); this.#abort.abort(); if (this.#timer !== undefined) clearTimeout(this.#timer); this.#timer = undefined;
    this.#execution?.fail(this.#terminal ?? "service_unavailable");
    this.#interest?.lose(this.#terminalSent ? "response_complete" : "owner_unavailable", true); this.#interest?.flush();
    this.#messages?.close(); this.#lease?.release(); this.#lease = undefined; this.#collect();
  }
  #collect(): void {
    if (this.#collecting || !this.#closed || this.#working || this.#sending || this.#terminalTask || this.#sourceCleanupRunning) return; this.#collecting = true;
    try {
      if (this.#source !== undefined) {
        if (!this.#sourceCleanupStarted) {
          this.#sourceCleanupStarted = this.#sourceCleanupRunning = true;
          void this.#source.dispose(this.#group!, this.#route?.streaming?.options.workClass ?? "resident", this.#cleanup!).then(() => {
            this.#sourceCleanupRunning = false; this.#collect();
          });
          return;
        }
        if (!this.#source.cleanupComplete()) return;
        this.#source = undefined;
      }
      this.#releaseWork?.(); this.#releaseWork = undefined;
      if (this.#messages?.cleanupComplete() === false) return;
      this.#messages = undefined; this.#network = undefined; this.#ticket = undefined; this.#inputs = undefined;
      this.#input?.close(); this.#input = undefined; this.#route?.close(); this.#route = undefined;
      this.#execution?.release(); this.#execution = undefined; this.#routes = undefined; this.#executionIdentity = undefined;
      this.#output?.close(); this.#output = undefined; this.#interest?.endInvocation(); this.#interest = undefined;
      this.#contract?.release(); this.#contract = undefined; this.#group = undefined; this.#authentication = undefined; this.#clock = undefined; this.#deadline = this.#initialDeadline = this.#runDeadline = this.#terminalDeadline = undefined;
      this.#reference?.release(); this.#reference = undefined; this.#cleanup?.finishJob(); this.#cleanup = undefined;
      const finished = this.#finished; this.#finished = undefined; finished?.();
    } finally { this.#collecting = false; }
  }
}
