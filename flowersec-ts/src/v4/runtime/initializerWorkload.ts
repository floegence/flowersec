import type { ClientSessionAdmission } from "./sessionAdmission.js";
import type { RPCCallPosition, RPCCallReservation } from "./rpcCallCapacity.js";
import type { ApplicationWorkClass } from "./applicationExecutor.js";
import type { V4ApplicationContext } from "../streamHandlers.js";
import { sameServiceBindingTarget, type CapturedBindingMethod, type ServiceBindingTarget } from "./serviceBindingConfig.js";
import type { ResourceVector} from "./resources.js";
import { type ProtectedResourceReservation, type ResourceReference, type ResourceAccount } from "./resources.js";
import type { V4EnvironmentRuntime } from "./environment.js";
import { completionPositionCharge, type ApplicationGroup, type CompletionPosition, type CompletionReservation } from "./applicationExecutor.js";
import { rpcUnaryPreparationCharges } from "./rpcUnaryPreparation.js";
import { notifyPreparationCharges } from "./notifyPreparation.js";

export interface InitializerWorkloadConfig {
  /** Simultaneous preparations/results per declared method, including tails. */
  readonly callsPerMethod?: number;
  /** Maximum retained input backing for one child call. Defaults to codec limits. */
  readonly inputBytes?: number;
}
export interface InitializerMethodTarget {
  readonly method: CapturedBindingMethod;
  readonly namespace: string;
  readonly target: ServiceBindingTarget;
}
interface Position {
  readonly charges: readonly ResourceVector[];
  readonly parts: readonly ProtectedResourceReservation[];
  readonly completion: CompletionPosition | undefined;
  call: RPCCallPosition | undefined;
}
interface MethodPlan { readonly target: InitializerMethodTarget; readonly positions: readonly Position[] }
export interface InitializerCallBacking {
  readonly references: ResourceReference[];
  readonly completion: CompletionReservation | undefined;
  readonly call: RPCCallReservation | undefined;
}
const contexts = new WeakMap<V4ApplicationContext, { workload: InitializerWorkload; session: object }>();
export function initializerCallBacking(context: V4ApplicationContext | undefined, session: object, method: object, namespace: string,
  target: ServiceBindingTarget | undefined, charges: readonly ResourceVector[], accounts: readonly ResourceAccount[], sendAccounts: readonly ResourceAccount[]): InitializerCallBacking | undefined {
  if (context === undefined) return undefined;
  const original = contexts.get(context); if (original === undefined) return undefined;
  if (original.session !== session || target === undefined) throw new Error("dependency_unavailable");
  return original.workload.checkout(method, namespace, target, charges, accounts, sendAccounts);
}
/** Original root reservations admitted before source Acquire. Each complete
 * operation returns the same reusable positions only after all aliases exit. */
export class InitializerWorkload {
  readonly #methods: MethodPlan[] = [];
  #closed = false;
  #callsReserved = false;
  constructor(environment: V4EnvironmentRuntime, group: ApplicationGroup, targets: readonly InitializerMethodTarget[], config: InitializerWorkloadConfig = {}, private readonly parentClass: ApplicationWorkClass = "short") {
    const resources = environment.resources, count = config.callsPerMethod ?? 1;
    if (!Number.isSafeInteger(count) || count < 1 || count > 1024 || config.inputBytes !== undefined &&
        (!Number.isSafeInteger(config.inputBytes) || config.inputBytes < 0 || config.inputBytes > 1073741824)) throw new Error("configuration_capacity");
    // A dependency may expose one method through several compatible aliases.
    // The aliases share the candidate's actual binding and method owner, so
    // reserving the same triple twice would consume duplicate K/Completion/
    // codec positions and could make a valid multi-alias initializer fail at
    // Acquire. Keep the first captured declaration for each exact owner while
    // retaining distinct namespace/target combinations as independent work.
    const uniqueTargets: InitializerMethodTarget[] = [];
    for (const target of targets) {
      if (!uniqueTargets.some(existing => existing.method.method === target.method.method &&
          existing.namespace === target.namespace && sameServiceBindingTarget(existing.target, target.target))) uniqueTargets.push(target);
    }
    try {
      for (const target of uniqueTargets) {
        const method = target.method.facts;
        const input = config.inputBytes ?? Math.max(method.request.maximum * 2, Number(method.request.application?.applicationBytes ?? 0n));
        if (!Number.isSafeInteger(input) || input > 1073741824) throw new Error("configuration_capacity");
        const charges = method.shape === "notify" ? notifyPreparationCharges(method, method, input, resources.runtimeBytes)
          : rpcUnaryPreparationCharges(method, method, method.maxResponseBytes, input, resources.runtimeBytes);
        const positions: Position[] = []; this.#methods.push({ target, positions });
        for (let index = 0; index < count; index++) {
          const costs = method.shape === "notify" ? charges : [...charges, completionPositionCharge(resources.runtimeBytes)];
          const references = environment.reserveInitializerWorkload(costs);
          const parts: ProtectedResourceReservation[] = []; let completion: CompletionPosition | undefined;
          try {
            for (let part = 0; part < charges.length; part++) {
              const ref = references[part]!, aliases: ResourceReference[] = [];
              try {
                aliases.push(ref.borrow()); aliases.push(ref.borrow());
                // The selected ordinary channel retains the original request
                // backing in its send scopes through the real publisher tail.
                if (method.shape !== "notify" && part === 1) aliases.push(ref.borrow());
                parts.push(resources.root.protectScoped(ref, charges[part]!, aliases));
              }
              finally { for (const alias of aliases) alias.release(); }
            }
            if (method.shape !== "notify") completion = group.protectCompletion(resources.runtimeBytes, references[charges.length]!);
            positions.push({ charges, parts, completion, call: undefined });
          } catch (error) { completion?.close(); for (const part of parts) part.closeAfterUse(); throw error; }
          finally { for (const reference of references) reference.release(); }
        }
      }
    } catch (error) { this.close(); throw error; }
  }
  reserveCalls(admission: ClientSessionAdmission | undefined): void {
    if (this.#closed || this.#callsReserved) throw new Error("owner_unavailable"); this.#callsReserved = true;
    try {
      for (const method of this.#methods) if (method.target.method.facts.shape !== "notify") {
        if (admission === undefined) throw new Error("configuration_capacity");
        const workClass = this.parentClass === "resident" ? "resident" : method.target.method.workClass;
        for (const position of method.positions) position.call = admission.protectCall(workClass);
      }
    } catch (error) { this.close(); throw error; }
  }
  enter(context: V4ApplicationContext, session: object): () => void {
    if (this.#closed || contexts.has(context)) throw new Error("owner_unavailable");
    contexts.set(context, { workload: this, session }); return () => { contexts.delete(context); };
  }
  checkout(method: object, namespace: string, target: ServiceBindingTarget, charges: readonly ResourceVector[], accounts: readonly ResourceAccount[], sendAccounts: readonly ResourceAccount[]): InitializerCallBacking {
    if (this.#closed) throw new Error("invocation_closed");
    const plan = this.#methods.find(plan => plan.target.method.method === method && plan.target.namespace === namespace &&
      sameServiceBindingTarget(plan.target.target, target));
    if (plan === undefined) throw new Error("dependency_unavailable");
    const position = plan.positions.find(position => position.parts.every(part => part.available()) && (position.completion === undefined || position.completion.available()) && (plan.target.method.facts.shape === "notify" || position.call?.available() === true));
    if (position === undefined) throw new Error("resource_exhausted");
    if (charges.length !== position.charges.length || charges.some((charge, index) => !position.charges[index]!.contains(charge))) throw new Error("configuration_capacity");
    const references: ResourceReference[] = []; let completion: CompletionReservation | undefined, call: RPCCallReservation | undefined;
    try {
      for (let index = 0; index < position.parts.length; index++) references.push(position.parts[index]!.checkoutScoped(index === 1 ? sendAccounts : accounts));
      completion = position.completion?.checkout(); call = position.call?.checkout(); return { references, completion, call };
    } catch (error) { call?.close(); completion?.close(); for (const reference of references) reference.release(); throw error; }
  }
  close(): void {
    if (this.#closed) return; this.#closed = true;
    for (const method of this.#methods) for (const position of method.positions) {
      position.call?.close(); position.completion?.close(); for (const part of position.parts) part.closeAfterUse();
    }
  }
  cleanupComplete(): boolean {
    return this.#closed && this.#methods.every(method => method.positions.every(position => position.parts.every(part => part.cleanupComplete()) && (position.completion === undefined || position.completion.cleanupComplete()) && (position.call === undefined || position.call.cleanupComplete())));
  }
}
