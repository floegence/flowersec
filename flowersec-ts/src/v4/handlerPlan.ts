import type { V4TransportEnvironment } from "./public.js";
import type { V4RawStreamHandler, V4StreamOpenAuthorizer, V4StreamRegistrationOptions } from "./streamHandlers.js";
import type { V4MaintenanceOwner } from "./responsePublication.js";
import { originalEnvironment, type EnvironmentDependency, type V4EnvironmentRuntime } from "./runtime/environment.js";
import { captureRPCApplication, type RPCApplicationConfig, type RPCApplicationUnaryHandler, type RPCApplicationStreamingHandler, type RPCApplicationNotificationHandler } from "./runtime/rpcApplication.js";
import { ServiceContractSnapshot, AdmissionOffer, serviceContractCharge, serviceContractDecoderCharge } from "./runtime/serviceContract.js";
import { CBORDecoder, cborDecoderCharge } from "./runtime/cbor.js";
import { ResourceVector } from "./runtime/resources.js";
import { checkRawStreamKind, captureRegistration } from "./runtime/streamRegistration.js";
import type { CapturedRawStreamDeclaration } from "./runtime/rawStreamPreparation.js";

type EncodedHandler<T> = Omit<T, "contract" | "offer"> & Readonly<{ contract: Uint8Array; offer?: Uint8Array }>;
/** Trusted local contracts and implementations. Encoded contracts are copied
 * into bounded owners; peer payloads never supply these declarations. */
export interface HandlerServices extends Omit<RPCApplicationConfig, "unaryHandlers" | "streamingHandlers" | "notificationHandlers" | "maintenanceOwner"> {
  readonly profile: "services" | "execution";
  readonly unaryHandlers?: readonly EncodedHandler<RPCApplicationUnaryHandler>[];
  readonly streamingHandlers?: readonly EncodedHandler<RPCApplicationStreamingHandler>[];
  readonly notificationHandlers?: readonly EncodedHandler<RPCApplicationNotificationHandler>[];
}
export interface HandlerPlanOptions {
  readonly services?: HandlerServices;
  readonly streams?: readonly Readonly<{ kind: string; authorize?: V4StreamOpenAuthorizer; handler: V4RawStreamHandler; options: V4StreamRegistrationOptions }>[];
  readonly applicationBytes: bigint;
  readonly maintenanceOwner?: V4MaintenanceOwner;
}
interface PlanState {
  dependency: EnvironmentDependency | undefined;
  application: RPCApplicationConfig | undefined;
  profile: "transport" | "services" | "execution";
  raw: readonly CapturedRawStreamDeclaration[];
  contracts: ServiceContractSnapshot[];
  maintenanceOwner: V4MaintenanceOwner | undefined;
}
const token = Symbol("handler plan"), plans = new WeakMap<HandlerPlan, PlanState>();
/** Immutable reusable declaration. Closing seals future captures; existing
 * Sessions keep their own original handler and contract responsibilities. */
export class HandlerPlan {
  constructor(capability: symbol, state: PlanState) { if (capability !== token) throw new Error("owner_unavailable"); plans.set(this, state); Object.freeze(this); }
  close(): void {
    const state = plans.get(this)!; state.application = undefined; state.maintenanceOwner = undefined; state.raw = [];
    for (const contract of state.contracts) contract.release(); state.contracts = [];
    const dependency = state.dependency; state.dependency = undefined; dependency?.release();
  }
  toJSON(): object { return {}; }
}
export function captureHandlerPlan(plan: HandlerPlan, environment: V4EnvironmentRuntime, maintenanceOwner?: V4MaintenanceOwner) {
  const state = plans.get(plan);
  if (state?.dependency === undefined) throw new Error("owner_unavailable");
  state.dependency.check();
  const probe = environment.reserveConnectionWork("handler_plan_capture", new ResourceVector([environment.resources.runtimeBytes, 0n, 0n, 1n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  try { if (!probe.sameEnvironment(state.dependency.reference)) throw new Error("owner_unavailable"); }
  finally { probe.release(); }
  if (state.maintenanceOwner !== maintenanceOwner) throw new Error("configuration_capacity");
  state.dependency.check();
  const reference = state.dependency.reference.borrow(), contracts: ServiceContractSnapshot[] = [];
  try { for (const contract of state.contracts) contracts.push(contract.retain()); }
  catch (error) { for (const contract of contracts) contract.release(); reference.release(); throw error; }
  let released = false;
  return Object.freeze({ application: state.application, raw: state.raw, profile: state.profile, release: () => {
    if (released) return; released = true; for (const contract of contracts) contract.release(); contracts.length = 0; reference.release();
  } });
}
export function createHandlerPlan(environment: V4TransportEnvironment, options: HandlerPlanOptions): HandlerPlan {
  const runtime = originalEnvironment(environment), bytes = options.applicationBytes, raw = options.streams ?? [], services = options.services;
  if (typeof bytes !== "bigint" || bytes < 1n || bytes > 1n << 30n || !Array.isArray(raw) || raw.length > 128) throw new Error("configuration_capacity");
  const arrays = [services?.unaryHandlers ?? [], services?.streamingHandlers ?? [], services?.notificationHandlers ?? []];
  if (arrays.some(array => !Array.isArray(array) || array.length > 4096) || arrays.reduce((n, array) => n + array.length, 0) > 4096) throw new Error("configuration_capacity");
  const dependency = runtime.admitDependency("handler_plan", new ResourceVector([bytes + 16384n + BigInt(raw.length) * 16384n + runtime.resources.runtimeBytes, 0n, 0n, BigInt(raw.length + 1), 0n, 0n, 0n, 0n, 0n, 0n, 0n]));
  const state: PlanState = { dependency, application: undefined, profile: services?.profile ?? "transport", raw: [], contracts: [], maintenanceOwner: options.maintenanceOwner };
  const plan = new HandlerPlan(token, state); dependency.onClose(() => plan.close());
  try {
    const kinds = new Set<string>();
    state.raw = Object.freeze(raw.map(({ kind, authorize, handler, options }) => {
      checkRawStreamKind(kind); if (kinds.has(kind) || typeof handler !== "function" || authorize !== undefined && typeof authorize !== "function") throw new Error("configuration_capacity"); kinds.add(kind);
      return Object.freeze({ kind, ...(authorize === undefined ? {} : { authorize }), handler, options: captureRegistration(options) });
    }));
    if (services !== undefined) {
      if (services.profile !== "services" && services.profile !== "execution") throw new Error("configuration_capacity");
      const convert = <T extends { contract: Uint8Array; offer?: Uint8Array; maximumOfferWindowMS?: bigint }>(entry: T) => {
        const r = runtime.resources, offerConfig = { bytes: 256, nodes: 16, textBytes: 0, arrayItems: 8, runtimeBytes: r.runtimeBytes };
        const refs = r.root.reserveBatch([serviceContractCharge(r.runtimeBytes), serviceContractDecoderCharge(r.runtimeBytes), cborDecoderCharge(offerConfig)]
          .map((charge, i) => ({ charge, accounts: r.accounts, owner: { ...r.owner, kind: `handler_contract_${i}` } })));
        let decoder: CBORDecoder | undefined;
        try {
          const contract = new ServiceContractSnapshot(entry.contract, r.runtimeBytes, refs[0]!, refs[1]!); state.contracts.push(contract);
          let offer: AdmissionOffer | undefined;
          if (entry.offer !== undefined) {
            if (entry.maximumOfferWindowMS === undefined) throw new Error("configuration_capacity");
            decoder = new CBORDecoder(offerConfig, refs[2]!); const doc = decoder.decodeMap(entry.offer, "AdmissionOffer");
            try { offer = new AdmissionOffer(doc, contract, entry.maximumOfferWindowMS, new Uint8Array(256)); } finally { doc.release(); }
          }
          return { ...entry, contract, ...(offer === undefined ? {} : { offer }) } as Omit<T, "contract" | "offer"> & { contract: ServiceContractSnapshot; offer?: AdmissionOffer };
        } finally { decoder?.close(); for (const ref of refs) ref.release(); }
      };
      state.application = captureRPCApplication({ ...services, ...(options.maintenanceOwner === undefined ? {} : { maintenanceOwner: options.maintenanceOwner }),
        unaryHandlers: services.unaryHandlers?.map(convert) ?? [], streamingHandlers: services.streamingHandlers?.map(convert) ?? [], notificationHandlers: services.notificationHandlers?.map(convert) ?? [] });
    }
    dependency.check(); return plan;
  } catch (error) { plan.close(); throw error; }
}
