import type { OperationOptions } from "../public/contract.js";
import type { V4ConnectionRequirements } from "../generated/transportV4APIResults.js";
import { V4TransportEnvironment, type V4ConnectionMaterial, type V4ConnectionMaterialSource, type V4Session } from "./public.js";
import { originalEnvironment } from "./runtime/environment.js";
import type { V4ConnectionController} from "./controller.js";
import { createV4ConnectionController, type V4ControllerConfig } from "./controller.js";
import type { V4ServiceDependencies } from "./serviceDependencies.js";
import type { ServeHandle, ServeOptions } from "./serve.js";

/** Current transport entry point. Source acquisition and all admission work
 * remain owned by the original Environment; this helper only projects its
 * public Connect operation. */
export function connect(
  environment: V4TransportEnvironment,
  source: V4ConnectionMaterialSource,
  request: Partial<V4ConnectionRequirements> = {},
  options?: OperationOptions,
): Promise<V4Session> {
  if (!(environment instanceof V4TransportEnvironment) || source === null || typeof source !== "object") {
    return Promise.reject(new Error("owner_unavailable"));
  }
  try { originalEnvironment(environment); } catch (error) { return Promise.reject(error); }
  return environment.connect(source, request, options);
}

/** Explicit static-material entry point. Consumed material is never returned
 * to the caller after this transfer, including failed admission. */
export function connectMaterial(
  environment: V4TransportEnvironment,
  material: V4ConnectionMaterial,
  options?: OperationOptions,
): Promise<V4Session> {
  if (!(environment instanceof V4TransportEnvironment) || material === null || typeof material !== "object") {
    return Promise.reject(new Error("owner_unavailable"));
  }
  try { originalEnvironment(environment); } catch (error) { return Promise.reject(error); }
  return environment.connectMaterial(material, options);
}

/** Current replacement controller factory. The source and requirement snapshot
 * are captured as part of one immutable controller plan. */
export function createConnectionController<Dependencies extends V4ServiceDependencies = {}>(
  environment: V4TransportEnvironment,
  config: V4ControllerConfig<Dependencies>,
): V4ConnectionController<Dependencies> {
  return createV4ConnectionController(environment, config);
}

/** Current server entry point. A listener is single-use and is consumed by
 * Serve; no implicit legacy acceptor or protocol downgrade is selected. */
export function serve<Plan extends object>(
  environment: V4TransportEnvironment,
  options: ServeOptions<Plan>,
  operation?: OperationOptions,
): Promise<ServeHandle> {
  if (!(environment instanceof V4TransportEnvironment)) return Promise.reject(new Error("owner_unavailable"));
  try { originalEnvironment(environment); } catch (error) { return Promise.reject(error); }
  return environment.serve(options, operation);
}
