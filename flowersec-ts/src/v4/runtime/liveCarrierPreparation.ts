import type { ClientPreparationFields } from "./credentialVerifier.js";
import type { V4EnvironmentRuntime } from "./environment.js";
import type { V4LiveAuthorizationConfig, V4LiveAuthorizationProvider } from "./liveAuthorization.js";
import { requireCredential } from "./credentialSupport.js";
type Announce = (fields: ClientPreparationFields, signal: AbortSignal) => Promise<void>;
const pending = new WeakMap<ClientPreparationFields, Promise<void>>();
const providers = new WeakMap<V4LiveAuthorizationProvider, Readonly<{ environment: V4EnvironmentRuntime; announce: Announce }>>();
/** The built-in registered provider retains this continuation in its original
 * Environment. Listener readiness is metadata; it cannot produce an allow. */
export function bindOriginalLiveCarrierPreparation(environment: V4EnvironmentRuntime, config: V4LiveAuthorizationConfig, announce: Announce): V4LiveAuthorizationConfig {
  requireCredential(!providers.has(config.requestAuthorization), "credential_binding"); providers.set(config.requestAuthorization, Object.freeze({ environment, announce })); return config;
}
export async function announceOriginalLiveCarrierPreparation(environment: V4EnvironmentRuntime, config: V4LiveAuthorizationConfig | undefined, fields: ClientPreparationFields, signal: AbortSignal): Promise<void> {
  if (config === undefined || fields.source !== "live_authority" || fields.pathKind !== 1) return;
  const original = providers.get(config.requestAuthorization); if (original === undefined) return;
  requireCredential(original.environment === environment && !signal.aborted, "credential_binding");
  let continuation = pending.get(fields); if (continuation === undefined) { fields.preparationDeadline.check(); continuation = original.announce(fields, signal); pending.set(fields, continuation); }
  await continuation; fields.preparationDeadline.check(); requireCredential(!signal.aborted, "credential_closed");
}
