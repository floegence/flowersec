import type { V4StreamOwner } from "./public.js";
import type { V4ResumeResult } from "./resume.js";
import { captureStreamingOptions, streamingOperation, type V4StreamingOptions, type V4StreamingOperation, type V4ExecutionStreamingOperation } from "./streamingOperation.js";
import { notifyOperation, type V4ExecutionNotifyOperation, type V4ObservationNotifyOperation, type V4NotifyOptions, type V4NotifyStatus } from "./notificationOperation.js";
import { applicationHasPermit } from "./runtime/applicationExecutor.js";
import { referenceSaveFailure, type V4OperationReferenceStore, type V4ReferenceSaveStatus, type V4ReferenceSaveFailure } from "./operationReferenceStore.js";
import type { V4OperationReference } from "./operationReference.js";
import type { V4CleanupStatus } from "../generated/transportV4APIResults.js";
import type { V4ApplicationContext } from "./streamHandlers.js";
import { serviceDefinition, type V4MethodDefinition, type V4ServiceDefinition, type V4ServiceMethods } from "./serviceDefinition.js";
import type { ServiceBinding, ServiceContractProgress, ServiceRefreshResult } from "./runtime/serviceBinding.js";
import type { ServiceBindingOptions } from "./runtime/serviceBindingConfig.js";
import { captureUnaryCallOptions, unaryOperation, type V4UnaryOperation, type V4ExecutionUnaryOperation, type V4UnaryOptions, type V4UnaryResult } from "./unaryOperation.js";

export interface V4ServiceRefreshOptions {
  readonly timeoutMS?: bigint;
  readonly signal?: AbortSignal;
  readonly context?: V4ApplicationContext;
}
export interface V4ServiceBindOptions extends ServiceBindingOptions, V4ServiceRefreshOptions {}
export type V4ServiceContract = ServiceContractProgress;
export type V4ServiceRefreshResult = ServiceRefreshResult;
export type V4ServiceInfo = Readonly<{ namespace: string; methodCount: number; offerRefresh: "explicit" | "managed" }>;
export type V4PrepareAndSaveResult<Value> = Readonly<{
  status: "prepared"; operation: V4ExecutionUnaryOperation<Value>; reference: V4OperationReference; save: V4ReferenceSaveStatus;
}> | Readonly<{
  status: "not_prepared"; reference?: V4OperationReference; save: V4ReferenceSaveStatus; reason: V4ReferenceSaveFailure; cleanup: V4CleanupStatus;
}>;
export type V4PrepareNotifyAndSaveResult = Readonly<{
  status: "prepared"; operation: V4ExecutionNotifyOperation; reference: V4OperationReference; save: V4ReferenceSaveStatus;
}> | Readonly<{
  status: "not_prepared"; reference?: V4OperationReference; save: V4ReferenceSaveStatus; reason: V4ReferenceSaveFailure; cleanup: V4CleanupStatus;
}>;
export type V4PrepareStreamAndSaveResult<Item> = Readonly<{
  status: "prepared"; operation: V4ExecutionStreamingOperation<Item>; reference: V4OperationReference; save: V4ReferenceSaveStatus;
}> | Exclude<V4PrepareAndSaveResult<never>, { status: "prepared" }>;
function saveStreamResult<Item>(value: V4PrepareStreamAndSaveResult<Item>): V4PrepareStreamAndSaveResult<Item> {
  Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
}
function saveNotifyResult(value: V4PrepareNotifyAndSaveResult): V4PrepareNotifyAndSaveResult {
  Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
}
function saveResult<Value>(value: V4PrepareAndSaveResult<Value>): V4PrepareAndSaveResult<Value> {
  Object.defineProperty(value, "then", { value: undefined }); return Object.freeze(value);
}
const capability = Symbol("original service client view");

/** One service root over the original method slots. A selector must belong
 * to this exact definition; missing snapshots never trigger implicit queries.
 * Closing the view closes its convenience calls, while explicitly transferred
 * operation handles keep their own independent lifecycle. */
export class V4ServiceClient<Methods extends V4ServiceMethods> {
  declare private readonly methodTypes: Methods;
  readonly #bindings: readonly ServiceBinding[];
  #closed = false;
  readonly #info: V4ServiceInfo;
  constructor(token: symbol, binding: ServiceBinding | readonly ServiceBinding[]) {
    if (token !== capability) throw new Error("service_binding_owner");
    const bindings = Array.isArray(binding) ? binding as readonly ServiceBinding[] : [binding as ServiceBinding];
    if (bindings.length < 1 || bindings.length > 2) throw new Error("service_binding_owner");
    this.#bindings = Object.freeze([...bindings]);
    const config = bindings[0]!.config;
    const routes = new Set<object>();
    for (const selected of bindings) {
      if (selected.config.definition !== config.definition || selected.config.offerRefresh !== config.offerRefresh) throw new Error("service_binding_owner");
      for (const method of selected.config.methods) {
        if (routes.has(method.method)) throw new Error("service_binding_owner"); routes.add(method.method);
      }
    }
    this.#info = Object.freeze({ namespace: config.namespace, methodCount: routes.size, offerRefresh: config.offerRefresh });
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  #select(method: object, observation = false): ServiceBinding {
    if (this.#closed && !observation) throw new Error("service_binding_closed");
    const binding = this.#bindings.find(binding => binding.ownsMethod(method)); if (binding === undefined) throw new Error("service_selector_invalid"); return binding;
  }
  info(): V4ServiceInfo { return this.#info; }
  contract(method: Methods[keyof Methods]): V4ServiceContract { return this.#select(method, true).contract(method); }
  refresh(methods: readonly Methods[keyof Methods][], options: V4ServiceRefreshOptions = {}): Promise<readonly V4ServiceRefreshResult[]> {
    const { timeoutMS = 90000n, context, signal } = options;
    if (this.#closed) return Promise.reject(new Error("service_binding_closed"));
    if (!Array.isArray(methods) || methods.length < 1 || methods.length > this.#info.methodCount || new Set(methods).size !== methods.length) return Promise.reject(new Error("service_selector_invalid"));
    const groups = new Map<ServiceBinding, object[]>();
    for (const method of methods) {
      const binding = this.#select(method), selected = groups.get(binding) ?? [];
      selected.push(method); groups.set(binding, selected);
    }
    // Capture every group's original deadline before starting any query.
    const work = [...groups].map(([binding, selected]) => ({ binding, selected, deadline: binding.deadline(timeoutMS) }));
    return Promise.all(work.map(({ binding, selected, deadline }) => binding.refresh(selected, deadline, context, signal))).then(results => {
      const entries = results.flat(), indexed = new Map(entries.map(entry => [entry.method, entry]));
      return Object.freeze(methods.map(method => indexed.get(method)!));
    });
  }

  updateContract(method: Methods[keyof Methods], approvedDigest: Uint8Array, options: V4ServiceRefreshOptions = {}): Promise<readonly V4ServiceRefreshResult[]> {
    const { timeoutMS = 90000n, context, signal } = options;
    return this.#select(method).update(method, approvedDigest, this.#select(method).deadline(timeoutMS), context, signal);
  }
  call<Request, Value>(method: V4MethodDefinition<Request, Value> & Methods[keyof Methods], value: Request,
    options?: V4UnaryOptions): Promise<V4UnaryResult<Value>> {
    try {
      const captured = captureUnaryCallOptions(options);
      return this.#select(method).callUnary(method, value, captured.preparation, captured.context, captured.signal) as Promise<V4UnaryResult<Value>>;
    } catch (error) { return Promise.reject(error); }
  }
  prepareResume(method: V4MethodDefinition<Uint8Array, Uint8Array, "unary", "execution"> & Methods[keyof Methods],
    targetStream: V4StreamOwner, checkpointToken: Uint8Array, options?: V4UnaryOptions): Promise<V4ExecutionUnaryOperation<V4ResumeResult>> {
    const captured = captureUnaryCallOptions(options);
    return this.#select(method).prepareResume(method, targetStream, checkpointToken, captured.preparation, captured.context, captured.signal).then(preparation => {
      try {
        const operation = unaryOperation<V4ResumeResult>(preparation) as V4ExecutionUnaryOperation<V4ResumeResult>;
        this.#select(method).checkDelivery(); preparation.checkReady();
        if (captured.signal?.aborted) throw new Error("canceled"); return operation;
      } catch (error) { preparation.close(); throw error; }
    });
  }
  prepareResumeAndSave(method: V4MethodDefinition<Uint8Array, Uint8Array, "unary", "execution"> & Methods[keyof Methods],
    targetStream: V4StreamOwner, checkpointToken: Uint8Array, store: V4OperationReferenceStore,
    options?: V4UnaryOptions): Promise<V4PrepareAndSaveResult<V4ResumeResult>> {
    const captured = captureUnaryCallOptions(options);
    return this.#select(method).prepareResumeAndSave(method, targetStream, checkpointToken, store, captured.preparation, captured.context, captured.signal).then(report => {
      const preparation = report.preparation;
      if (preparation === undefined) return saveResult<V4ResumeResult>({ status: "not_prepared", save: report.save, reason: report.failure ?? "preparation_failed",
        cleanup: report.cleanup, ...(report.reference === undefined ? {} : { reference: report.reference }) });
      try {
        const operation = unaryOperation<V4ResumeResult>(preparation) as V4ExecutionUnaryOperation<V4ResumeResult>;
        this.#select(method).checkDelivery(); preparation.checkReady();
        if (captured.signal?.aborted || captured.context?.signal.aborted) throw new Error("canceled");
        if (captured.context !== undefined) applicationHasPermit(captured.context);
        return saveResult<V4ResumeResult>({ status: "prepared", operation, reference: report.reference!, save: report.save });
      } catch (error) {
        preparation.close(); return saveResult<V4ResumeResult>({ status: "not_prepared", reference: report.reference!, save: report.save,
          reason: referenceSaveFailure(error), cleanup: preparation.cleanupStatus() });
      }
    });
  }
  async resume(method: V4MethodDefinition<Uint8Array, Uint8Array, "unary", "execution"> & Methods[keyof Methods],
    targetStream: V4StreamOwner, checkpointToken: Uint8Array, options?: V4UnaryOptions): Promise<V4ExecutionUnaryOperation<V4ResumeResult>> {
    const captured = captureUnaryCallOptions(options);
    const preparation = await this.#select(method).prepareResume(method, targetStream, checkpointToken, captured.preparation, captured.context, captured.signal);
    const operation = unaryOperation<V4ResumeResult>(preparation) as V4ExecutionUnaryOperation<V4ResumeResult>;
    try {
      this.#select(method).checkDelivery(); preparation.checkReady();
      const result = operation.start({ ...(captured.context === undefined ? {} : { context: captured.context }), ...(captured.signal === undefined ? {} : { signal: captured.signal }) });
      if (result.status !== "admitted") throw new Error(result.reason); return operation;
    } catch (error) { operation.close(); throw error; }
  }
  prepareStreamOperation<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming", "execution"> & Methods[keyof Methods], value: Request,
    options?: V4StreamingOptions): Promise<V4ExecutionStreamingOperation<Item>>;
  prepareStreamOperation<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming"> & Methods[keyof Methods], value: Request,
    options?: V4StreamingOptions): Promise<V4StreamingOperation<Item> | V4ExecutionStreamingOperation<Item>>;
  prepareStreamOperation<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming"> & Methods[keyof Methods], value: Request,
    options?: V4StreamingOptions): Promise<V4StreamingOperation<Item>> {
    const captured = captureStreamingOptions(options);
    return this.#select(method).prepareStream(method, value, captured.preparation, captured.context, captured.signal).then(preparation => {
      try {
        const operation = streamingOperation<Item>(preparation); this.#select(method).checkDelivery(); preparation.checkReady();
        if (captured.signal?.aborted) throw new Error("canceled"); return operation;
      } catch (error) { preparation.close(); throw error; }
    });
  }
  stream<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming", "execution"> & Methods[keyof Methods], value: Request,
    options?: V4StreamingOptions): Promise<V4ExecutionStreamingOperation<Item>>;
  stream<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming"> & Methods[keyof Methods], value: Request,
    options?: V4StreamingOptions): Promise<V4StreamingOperation<Item> | V4ExecutionStreamingOperation<Item>>;
  async stream<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming"> & Methods[keyof Methods], value: Request,
    options: V4StreamingOptions = {}): Promise<V4StreamingOperation<Item>> {
    const captured = captureStreamingOptions(options);
    const preparation = await this.#select(method).prepareStream(method, value, captured.preparation, captured.context, captured.signal);
    const operation = streamingOperation<Item>(preparation);
    try {
      this.#select(method).checkDelivery(); preparation.checkReady(); const result = operation.start({ ...(captured.context === undefined ? {} : { context: captured.context }), ...(captured.signal === undefined ? {} : { signal: captured.signal }) });
      if (result.status === "not_admitted") throw new Error(result.reason); return operation;
    } catch (error) { operation.close(); throw error; }
  }
  notify<Request>(method: V4MethodDefinition<Request, any, "notify"> & Methods[keyof Methods], value: Request, options: V4NotifyOptions = {}): Promise<V4NotifyStatus> {
    const { signal, context, ...settings } = options;
    return this.#select(method).notify(method, value, settings, context, signal);
  }
  prepareOperation<Request, Value>(method: V4MethodDefinition<Request, Value, "notify", "execution"> & Methods[keyof Methods], value: Request, options?: V4NotifyOptions): Promise<V4ExecutionNotifyOperation>;
  prepareOperation<Request, Value>(method: V4MethodDefinition<Request, Value, "notify", "observation"> & Methods[keyof Methods], value: Request, options?: V4NotifyOptions): Promise<V4ObservationNotifyOperation>;
  prepareOperation<Request, Value>(method: V4MethodDefinition<Request, Value, "notify"> & Methods[keyof Methods], value: Request, options?: V4NotifyOptions): Promise<V4ObservationNotifyOperation | V4ExecutionNotifyOperation>;
  prepareOperation<Request, Value>(method: V4MethodDefinition<Request, Value> & Methods[keyof Methods], value: Request, options?: V4UnaryOptions): Promise<V4UnaryOperation<Value> | V4ExecutionUnaryOperation<Value>>;
  prepareOperation<Request, Value>(method: V4MethodDefinition<Request, Value> & Methods[keyof Methods], value: Request,
    options?: V4UnaryOptions): Promise<V4UnaryOperation<Value> | V4ExecutionUnaryOperation<Value> | V4ObservationNotifyOperation> {
    if (method.shape === "notify") {
      const { timeoutMS, deadlineAtMS, context, signal, admission, admissionNotAfterMS, responseLimitBytes } = options ?? {};
      if (responseLimitBytes !== undefined) throw new Error("notify_options");
      return this.#select(method).prepareNotify(method, value, { ...(timeoutMS === undefined ? {} : { timeoutMS }), ...(deadlineAtMS === undefined ? {} : { deadlineAtMS }), ...(admission === undefined ? {} : { admission }), ...(admissionNotAfterMS === undefined ? {} : { admissionNotAfterMS }) }, context, signal).then(preparation => {
        try { this.#select(method).checkDelivery(); preparation.checkPublication(); if (signal?.aborted) throw new Error("canceled"); return notifyOperation(preparation); }
        catch (error) { preparation.close(); throw error; }
      });
    }
    const captured = captureUnaryCallOptions(options);
    return this.#select(method).prepareUnary(method, value, captured.preparation, captured.context, captured.signal).then(preparation => {
      try {
        const operation = unaryOperation<Value>(preparation);
        this.#select(method).checkDelivery(); preparation.checkReady();
        if (captured.signal?.aborted) throw new Error("canceled"); return operation;
      } catch (error) { preparation.close(); throw error; }
    });
  }
  prepareAndSave<Request>(method: V4MethodDefinition<Request, any, "notify"> & Methods[keyof Methods], value: Request,
    store: V4OperationReferenceStore, options?: V4NotifyOptions): Promise<V4PrepareNotifyAndSaveResult>;
  prepareAndSave<Request, Item>(method: V4MethodDefinition<Request, Item, "server_streaming", "execution"> & Methods[keyof Methods], value: Request,
    store: V4OperationReferenceStore, options?: V4StreamingOptions): Promise<V4PrepareStreamAndSaveResult<Item>>;
  prepareAndSave<Request, Value>(method: V4MethodDefinition<Request, Value, "unary"> & Methods[keyof Methods], value: Request,
    store: V4OperationReferenceStore, options?: V4UnaryOptions): Promise<V4PrepareAndSaveResult<Value>>;
  prepareAndSave<Request, Value>(method: V4MethodDefinition<Request, Value> & Methods[keyof Methods], value: Request,
    store: V4OperationReferenceStore, options?: V4UnaryOptions | V4StreamingOptions): Promise<V4PrepareAndSaveResult<Value> | V4PrepareNotifyAndSaveResult | V4PrepareStreamAndSaveResult<Value>> {
    if (method.shape === "server_streaming") {
      const captured = captureStreamingOptions(options);
      return this.#select(method).prepareAndSaveStream(method, value, store, captured.preparation, captured.context, captured.signal).then(report => {
        const preparation = report.preparation;
        if (preparation === undefined) return saveStreamResult<Value>({ status: "not_prepared", save: report.save, reason: report.failure ?? "preparation_failed",
          cleanup: report.cleanup, ...(report.reference === undefined ? {} : { reference: report.reference }) });
        try {
          const operation = streamingOperation<Value>(preparation) as V4ExecutionStreamingOperation<Value>;
          this.#select(method).checkDelivery(); preparation.checkReady();
          if (captured.signal?.aborted || captured.context?.signal.aborted) throw new Error("canceled");
          if (captured.context !== undefined) applicationHasPermit(captured.context);
          return saveStreamResult<Value>({ status: "prepared", operation, reference: report.reference!, save: report.save });
        } catch (error) {
          preparation.close(); return saveStreamResult<Value>({ status: "not_prepared", reference: report.reference!, save: report.save,
            reason: referenceSaveFailure(error), cleanup: preparation.cleanupStatus() });
        }
      });
    }
    if (method.shape === "notify") {
      const { context, signal, responseLimitBytes, ...settings } = (options ?? {}) as V4UnaryOptions;
      if (responseLimitBytes !== undefined) throw new Error("notify_options");
      return this.#select(method).prepareAndSaveNotify(method, value, store, settings, context, signal).then(report => {
        const preparation = report.preparation;
        if (preparation === undefined) return saveNotifyResult({ status: "not_prepared" as const, save: report.save, reason: report.failure ?? "preparation_failed",
          cleanup: report.cleanup, ...(report.reference === undefined ? {} : { reference: report.reference }) });
        try {
          this.#select(method).checkDelivery(); preparation.checkPublication(); if (signal?.aborted || context?.signal.aborted) throw new Error("canceled");
          if (context !== undefined) applicationHasPermit(context);
          const operation = notifyOperation(preparation) as V4ExecutionNotifyOperation;
          return saveNotifyResult({ status: "prepared" as const, operation, reference: report.reference!, save: report.save });
        } catch (error) {
          preparation.close(); return saveNotifyResult({ status: "not_prepared" as const, reference: report.reference!, save: report.save,
            reason: referenceSaveFailure(error), cleanup: preparation.cleanupStatus() });
        }
      });
    }
    const captured = captureUnaryCallOptions(options);
    return this.#select(method).prepareAndSaveUnary(method, value, store, captured.preparation, captured.context, captured.signal).then(report => {
      const preparation = report.preparation;
      if (preparation === undefined) return saveResult<Value>({ status: "not_prepared", save: report.save, reason: report.failure ?? "preparation_failed",
        cleanup: report.cleanup, ...(report.reference === undefined ? {} : { reference: report.reference }) });
      try {
        const operation = unaryOperation<Value>(preparation) as V4ExecutionUnaryOperation<Value>;
        this.#select(method).checkDelivery(); preparation.checkReady();
        if (captured.signal?.aborted || captured.context?.signal.aborted) throw new Error("canceled");
        if (captured.context !== undefined) applicationHasPermit(captured.context);
        return saveResult<Value>({ status: "prepared", operation, reference: report.reference!, save: report.save });
      } catch (error) {
        preparation.close(); return saveResult<Value>({ status: "not_prepared", reference: report.reference!, save: report.save,
          reason: referenceSaveFailure(error), cleanup: preparation.cleanupStatus() });
      }
    });
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const binding of this.#bindings) binding.seal();
    for (const binding of this.#bindings) binding.close();
  }
  toJSON(): object { return {}; }
}
export function serviceClient<Methods extends V4ServiceMethods>(definition: V4ServiceDefinition<Methods>, binding: ServiceBinding): V4ServiceClient<Methods> {
  if (binding.config.definition !== definition) throw new Error("service_binding_owner"); return new V4ServiceClient(capability, binding);
}
/** Internal composition of already admitted disjoint method owners. */
export function groupedServiceClient<Methods extends V4ServiceMethods>(definition: V4ServiceDefinition<Methods>, bindings: readonly ServiceBinding[]): V4ServiceClient<Methods> {
  const expected = serviceDefinition(definition).entries;
  if (bindings.length !== 2 || bindings.some(binding => binding.config.definition !== definition) ||
      bindings.reduce((count, binding) => count + binding.config.methods.length, 0) !== expected.length ||
      expected.some(entry => bindings.filter(binding => binding.config.methods.some(method => method.method === entry.method)).length !== 1)) throw new Error("service_binding_owner");
  return new V4ServiceClient(capability, bindings);
}
Object.freeze(V4ServiceClient.prototype); Object.freeze(V4ServiceClient);
