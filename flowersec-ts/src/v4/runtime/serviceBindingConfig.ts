import type { V4StaticServiceContracts } from "../staticServiceContracts.js";
import { serviceDefinition, type CapturedMethodDefinition } from "../serviceDefinition.js";
import type { V4AuthenticatedContext } from "../streamHandlers.js";
import { captureContractAcceptance, type ContractAcceptance } from "./contractAcceptance.js";
import type { ApplicationWorkClass } from "./applicationExecutor.js";
import { captureServiceOfferTiming, type ServiceOfferTiming } from "./serviceOfferPlan.js";
import { RPCProtocolError } from "./rpcFragment.js";

/** Trusted local mapping of a logical service authority to authenticated peers.
 * A remote contract body or its digest never supplies this mapping. */
export interface ServiceBindingTarget {
  readonly authority: string;
  readonly tenant: string;
  readonly audience: string;
  readonly localSubject: string;
  readonly peers: readonly Readonly<{ subject: string; identityDigest: string }>[];
}
export interface ServiceBindingMethodOptions {
  readonly method: object;
  readonly resumeKind?: string;
  readonly streamKind?: string;
  readonly streamMetadata?: Uint8Array;
  readonly preacceptStream?: boolean;
  readonly acceptance?: ContractAcceptance;
  readonly defaultResponseLimitBytes?: number;
  readonly workClass?: ApplicationWorkClass;
  readonly requiredForDispatch?: boolean;
}
export interface ServiceBindingOptions {
  /** Bounded advertisement checks share the original query slots; minimum 30s. */
  readonly contractCheckIntervalMS?: bigint;
  readonly contractSource?: V4StaticServiceContracts;
  readonly offerRefresh?: "explicit" | "managed";
  readonly offerTiming?: ServiceOfferTiming;
  readonly target: ServiceBindingTarget;
  readonly initialMethods?: readonly object[];
  readonly methods?: readonly ServiceBindingMethodOptions[];
  readonly maximumOfferWindowMS: bigint;
}
export interface CapturedBindingMethod {
  readonly method: object;
  readonly facts: CapturedMethodDefinition;
  readonly resumeKind: string | undefined;
  readonly streamKind: string | undefined;
  readonly streamMetadata: Uint8Array | undefined;
  readonly preacceptStream: boolean;
  readonly acceptance: ContractAcceptance;
  readonly defaultResponseLimitBytes: number | undefined;
  readonly workClass: ApplicationWorkClass;
  readonly required: boolean;
  readonly initial: boolean;
}
export interface CapturedServiceBinding {
  readonly contractCheckIntervalMS: bigint;
  readonly offerRefresh: "explicit" | "managed";
  readonly offerTiming: ServiceOfferTiming;
  readonly definition: object;
  readonly namespace: string;
  readonly preset: "full" | "constrained";
  readonly target: ServiceBindingTarget;
  readonly methods: readonly CapturedBindingMethod[];
  readonly maximumOfferWindowMS: bigint;
}
function identity(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 256 || !/^[\x21-\x7e]+$/u.test(value)) throw new RPCProtocolError("configuration_capacity");
  return value;
}
export function captureServiceBindingTarget(target: ServiceBindingTarget): ServiceBindingTarget {
  const { authority, tenant, audience, localSubject, peers } = target;
  if (!Array.isArray(peers) || peers.length < 1 || peers.length > 16) throw new RPCProtocolError("configuration_capacity");
  return Object.freeze({ authority: identity(authority), tenant: identity(tenant), audience: identity(audience), localSubject: identity(localSubject),
    peers: Object.freeze(peers.map(peer => {
      const { subject, identityDigest } = peer;
      if (typeof identityDigest !== "string" || !/^[0-9a-f]{64}$/u.test(identityDigest)) throw new RPCProtocolError("configuration_capacity");
      return Object.freeze({ subject: identity(subject), identityDigest });
    })) });
}
/** Stable logical identity used when compatible declarations were captured
 * independently. Object identity is only an implementation detail and must
 * not cause duplicate initializer or stream reservations. */
export function sameServiceBindingTarget(a: ServiceBindingTarget, b: ServiceBindingTarget): boolean {
  return a.authority === b.authority && a.tenant === b.tenant && a.audience === b.audience && a.localSubject === b.localSubject &&
    a.peers.length === b.peers.length && a.peers.every((peer, index) => {
      const other = b.peers[index]!; return peer.subject === other.subject && peer.identityDigest === other.identityDigest;
    });
}
export function captureServiceBinding(definition: object, options: ServiceBindingOptions, descriptorOnly = false): CapturedServiceBinding {
  const service = serviceDefinition(definition), { target, initialMethods, methods = [], maximumOfferWindowMS, offerRefresh = "explicit", offerTiming, contractCheckIntervalMS = 60000n } = options;
  if (typeof contractCheckIntervalMS !== "bigint" || contractCheckIntervalMS < 30000n || contractCheckIntervalMS >= 1n << 64n) throw new RPCProtocolError("configuration_capacity");
  if (offerRefresh !== "explicit" && offerRefresh !== "managed") throw new RPCProtocolError("configuration_capacity");
  const timing = captureServiceOfferTiming(offerTiming);
  if (!Array.isArray(methods) || methods.length > service.entries.length ||
      typeof maximumOfferWindowMS !== "bigint" || maximumOfferWindowMS < 1n || maximumOfferWindowMS >= 1n << 64n) throw new RPCProtocolError("configuration_capacity");
  const capturedTarget = captureServiceBindingTarget(target);
  const declared = new Set(service.entries.map(entry => entry.method));
  const selected = initialMethods ?? service.entries.map(entry => entry.method);
  if (!Array.isArray(selected) || selected.length < (descriptorOnly ? 0 : 1) || selected.length > declared.size || new Set(selected).size !== selected.length ||
      selected.some(method => !declared.has(method))) throw new RPCProtocolError("configuration_capacity");
  const initial = new Set(selected), configured = new Map<object, Omit<CapturedBindingMethod, "facts" | "initial">>();
  for (const entry of methods) {
    const { method, resumeKind, streamKind, streamMetadata, preacceptStream = false, acceptance = { mode: "exact" }, defaultResponseLimitBytes, workClass: configuredClass, requiredForDispatch = false } = entry;
    const streaming = service.entries.find(entry => entry.method === method)?.facts.shape === "server_streaming";
    const workClass = configuredClass ?? (streaming ? "resident" : "short");
    if (!declared.has(method) || configured.has(method) || workClass !== "short" && workClass !== "resident" || typeof requiredForDispatch !== "boolean" ||
        requiredForDispatch && !initial.has(method) || defaultResponseLimitBytes !== undefined &&
        (!Number.isSafeInteger(defaultResponseLimitBytes) || defaultResponseLimitBytes < 0 || defaultResponseLimitBytes > 1048576)) throw new RPCProtocolError("configuration_capacity");
    if (resumeKind !== undefined) {
      checkStreamingTarget(resumeKind, new Uint8Array());
      const facts = service.entries.find(entry => entry.method === method)!.facts;
      if (facts.shape !== "unary" || facts.semantics !== "execution" || facts.request.implementation !== "bytes" || facts.response?.implementation !== "bytes") throw new RPCProtocolError("resume_binding");
    }
    if (streamKind !== undefined) checkStreamingTarget(streamKind, streamMetadata ?? new Uint8Array());
    if (typeof preacceptStream !== "boolean" || !streaming && (streamKind !== undefined || streamMetadata !== undefined || preacceptStream) ||
        streamMetadata !== undefined && streamKind === undefined || streaming && (preacceptStream || requiredForDispatch) && (streamKind === undefined || !initial.has(method))) throw new RPCProtocolError("configuration_capacity");
    configured.set(method, Object.freeze({ method, resumeKind, streamKind, streamMetadata: streamKind === undefined ? undefined : streamMetadata === undefined ? new Uint8Array() : new Uint8Array(streamMetadata), preacceptStream: streaming && (preacceptStream || requiredForDispatch), acceptance: captureContractAcceptance(acceptance), defaultResponseLimitBytes, workClass, required: requiredForDispatch }));
  }
  return Object.freeze({ definition, contractCheckIntervalMS, offerRefresh, offerTiming: timing, namespace: service.namespace, preset: service.preset, target: capturedTarget, maximumOfferWindowMS,
    methods: Object.freeze(service.entries.map(entry => Object.freeze({ method: entry.method, facts: entry.facts,
      resumeKind: undefined, streamKind: undefined, streamMetadata: undefined, preacceptStream: false, acceptance: Object.freeze({ mode: "exact" as const }), defaultResponseLimitBytes: undefined, workClass: entry.facts.shape === "server_streaming" ? "resident" as const : "short" as const, required: false,
      ...configured.get(entry.method), initial: initial.has(entry.method) }))) });
}
export function checkServiceBindingTarget(target: ServiceBindingTarget, authentication: V4AuthenticatedContext): void {
  if (target.tenant !== authentication.tenant || target.audience !== authentication.audience || target.localSubject !== authentication.localSubject ||
      !target.peers.some(peer => peer.subject === authentication.peerSubject && peer.identityDigest === authentication.peerIdentityDigest)) throw new RPCProtocolError("service_target_mismatch");
}

export function checkStreamingTarget(kind: string, metadata: Uint8Array): void {
  if (typeof kind !== "string" || kind.length < 1 || kind.length > 128 || kind.normalize("NFC") !== kind ||
      new TextEncoder().encode(kind).length > 128 || kind.startsWith("flowersec/") || kind.startsWith("flowersec.") ||
      !(metadata instanceof Uint8Array) || metadata.length > 4096) throw new RPCProtocolError("configuration_capacity");
}
