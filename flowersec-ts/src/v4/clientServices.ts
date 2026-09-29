import type * as ServiceDefinitionTypes from "./serviceDefinition.js";
import type { ServiceBindingTarget } from "./runtime/serviceBindingConfig.js";
import type { V4ServiceDefinition, V4ServiceMethods } from "./serviceDefinition.js";
import { captureRPCApplication, type RPCApplicationConfig, type RPCExecutionDelegation } from "./runtime/rpcApplication.js";

/** Trusted declarations for a services client. The query tuple is supplied by
 * the deployment's built-in contract and is never learned from the peer. */
export interface V4ClientServicesConfig {
  readonly profile?: "services" | "execution";
  readonly query: Readonly<{ typeID: number; contractDigest: Uint8Array }>;
  readonly resultRead?: Readonly<{ typeID: number; contractDigest: Uint8Array }>;
  readonly definitions: readonly V4ServiceDefinition<V4ServiceMethods>[];
  readonly maxMethods: number;
  readonly maxCaptureBytes: number;
  readonly localExecutionAuthority?: string;
  readonly referenceTargets?: readonly ServiceBindingTarget[];
  readonly executionDelegations?: readonly RPCExecutionDelegation[];
  /** Trusted incoming observation contracts. Registration sends no frame. */
  readonly notificationMethods?: readonly Readonly<{ namespace: string; method: ServiceDefinitionTypes.V4MethodDefinition<any, any, "notify">;
    contract: Uint8Array; permission: "allowed" | "denied" | "unavailable" }>[];
  readonly queryAcquisitions?: 2 | 4;
}
export function captureClientServices(input: V4ClientServicesConfig | undefined): Readonly<{ profile: "services" | "execution"; application: RPCApplicationConfig }> | undefined {
  if (input === undefined) return undefined;
  const { profile = "services", query, resultRead, definitions, maxMethods, maxCaptureBytes, queryAcquisitions, localExecutionAuthority, referenceTargets, executionDelegations, notificationMethods } = input;
  if (profile !== "services" && profile !== "execution") throw new Error("configuration_capacity");
  return Object.freeze({ profile, application: captureRPCApplication({ query, definitions, maxMethods, maxCaptureBytes, ...(localExecutionAuthority === undefined ? {} : { localExecutionAuthority }),
    ...(notificationMethods === undefined ? {} : { notificationMethods }), ...(resultRead === undefined ? {} : { resultRead }), ...(referenceTargets === undefined ? {} : { referenceTargets }), ...(executionDelegations === undefined ? {} : { executionDelegations }),
    ...(queryAcquisitions === undefined ? {} : { queryAcquisitions }) }) });
}
