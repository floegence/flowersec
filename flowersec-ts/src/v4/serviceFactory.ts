import type * as ServiceBindingTypes from "./runtime/serviceBinding.js";
import { captureServiceBinding, captureServiceBindingTarget, type ServiceBindingTarget } from "./runtime/serviceBindingConfig.js";
import { createV4ConnectionController, prepareControllerService, type V4ConnectionController, type V4ControllerConfig } from "./controller.js";
import type { V4TransportEnvironment } from "./public.js";
import { groupedServiceClient, type V4ServiceBindOptions, type V4ServiceClient } from "./serviceClient.js";
import { serviceDefinition, type V4ServiceDefinition, type V4ServiceMethods } from "./serviceDefinition.js";
import type { V4ServiceDependencies } from "./serviceDependencies.js";
import { applicationHasPermit } from "./runtime/applicationExecutor.js";
import { timerChunk } from "./runtime/deadline.js";

/** Ownership is explicit. An Environment is always borrowed; only an owned
 * configuration authorizes this factory to initialize and close a Controller. */
export type V4ServiceClientSource<Dependencies extends V4ServiceDependencies = {}> =
  | Readonly<{ ownership: "owned"; environment: V4TransportEnvironment; controller: V4ControllerConfig<Dependencies> }>
  | Readonly<{ ownership: "borrowed"; controller: V4ConnectionController<Dependencies> }>;

/** Return the ordinary typed service, with one initialization deadline and
 * one original acquisition path. Borrowed sources only observe progress. */
export async function createV4ServiceClient<Methods extends V4ServiceMethods, Dependencies extends V4ServiceDependencies = {}>(
  definition: V4ServiceDefinition<Methods>, source: V4ServiceClientSource<Dependencies> | V4ServiceClientGroups<Methods, Dependencies>, options: V4ServiceBindOptions,
): Promise<V4ServiceClient<Methods>> {
  if ("groups" in source) return createGroupedService(definition, source, options);
  const ownership = source.ownership;
  if (ownership === "borrowed") return prepareControllerService(source.controller, definition, options).initialize();
  if (ownership !== "owned") throw new Error("configuration_capacity");
  if (applicationHasPermit(options.context)) throw new Error("admission_mode_incompatible");
  const cancellation = new AbortController(), callerSignal = options.signal;
  if (callerSignal?.aborted) throw new Error("canceled");
  const signal = callerSignal === undefined ? cancellation.signal : AbortSignal.any([callerSignal, cancellation.signal]);
  const controller = createV4ConnectionController(source.environment, source.controller);
  let prepared: ReturnType<typeof prepareControllerService<Methods>> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    // These are the actual binding slots and snapshot positions subsequently
    // transferred to ServiceBinding, not an estimate or a second reservation.
    prepared = prepareControllerService(controller, definition, { ...options, signal });
    const deadline = prepared.deadline;
    const tick = (): void => {
      timer = undefined;
      try { deadline.check(); timer = setTimeout(tick, timerChunk(deadline.remainingMS())); }
      catch (error) { cancellation.abort(error); }
    };
    tick(); if (signal.aborted) throw new Error("canceled");
    prepared.prepareConnection();
    const connection = prepared.connect();
    const binding = prepared.initialize(() => { void controller.close(); });
    const [client] = await Promise.all([binding, connection]);
    deadline.check(); if (signal.aborted) throw new Error("canceled");
    return client;
  } catch (error) {
    cancellation.abort(error); prepared?.close(); await controller.close(); throw error;
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

export type V4ServiceSourceGroup = "interactive" | "bulk";
/** Complete local method routing. Peer mappings may differ physically; the
 * logical authority, tenant, audience and caller must remain identical. */
export interface V4ServiceClientGroups<Methods extends V4ServiceMethods, Dependencies extends V4ServiceDependencies = {}> {
  readonly groups: Readonly<Record<V4ServiceSourceGroup, V4ServiceClientSource<Dependencies> & { readonly target?: ServiceBindingTarget }>>;
  readonly routes: readonly Readonly<{ method: Methods[keyof Methods]; group: V4ServiceSourceGroup }>[];
}

async function createGroupedService<Methods extends V4ServiceMethods, Dependencies extends V4ServiceDependencies>(
  definition: V4ServiceDefinition<Methods>, source: V4ServiceClientGroups<Methods, Dependencies>, options: V4ServiceBindOptions,
): Promise<V4ServiceClient<Methods>> {
  const original = serviceDefinition(definition), captured = captureServiceBinding(definition, options, true);
  const names = ["interactive", "bulk"] as const, routes = new Map<object, V4ServiceSourceGroup>();
  if (!Array.isArray(source.routes) || source.routes.length !== original.entries.length ||
      source.groups === null || typeof source.groups !== "object" || Object.keys(source.groups).length !== 2 ||
      !Object.hasOwn(source.groups, "interactive") || !Object.hasOwn(source.groups, "bulk")) throw new Error("configuration_capacity");
  for (const route of source.routes) {
    const { method, group } = route;
    if (!names.includes(group) || routes.has(method) || !original.entries.some(entry => entry.method === method)) throw new Error("configuration_capacity");
    routes.set(method, group);
  }
  // Capture both complete trusted targets before allocating or binding either
  // group. A peer set never grants a different logical service authority.
  const configurations = names.map(name => {
    const group = source.groups[name], ownership = group.ownership;
    if (ownership !== "owned" && ownership !== "borrowed") throw new Error("configuration_capacity");
    const target = captureServiceBindingTarget(group.target ?? captured.target);
    for (const key of ["authority", "tenant", "audience", "localSubject"] as const) {
      if (target[key] !== captured.target[key]) throw new Error("service_target_mismatch");
    }
    const binding = Object.freeze({ ...captured, target, methods: Object.freeze(captured.methods.filter(method => routes.get(method.method) === name)) });
    return { name, group, binding };
  });
  if (configurations.some(item => item.group.ownership === "owned") && applicationHasPermit(options.context)) throw new Error("admission_mode_incompatible");
  const cancellation = new AbortController(), callerSignal = options.signal;
  if (callerSignal?.aborted) throw new Error("canceled");
  const signal = callerSignal === undefined ? cancellation.signal : AbortSignal.any([callerSignal, cancellation.signal]);
  const owned: V4ConnectionController<Dependencies>[] = [], prepared: ReturnType<typeof prepareControllerService<Methods>>[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  const publicRoot = Object.freeze({});
  try {
    const groups = configurations.map(({ group, binding }) => {
      const controller = group.ownership === "owned" ? createV4ConnectionController(group.environment, group.controller) : group.controller;
      if (group.ownership === "owned") owned.push(controller);
      const reservation = prepareControllerService(controller, definition, { ...options, signal }, binding, publicRoot);
      prepared.push(reservation);
      if (prepared.length > 1) reservation.limitDeadline(prepared[0]!.deadline);
      return { controller, reservation, ownership: group.ownership };
    });
    const check = (): void => { for (const item of prepared) item.deadline.check(); if (signal.aborted) throw new Error("canceled"); };
    const tick = (): void => {
      timer = undefined;
      try {
        check(); const remaining = prepared.map(item => item.deadline.remainingMS()).reduce((a, b) => a < b ? a : b);
        timer = setTimeout(tick, timerChunk(remaining));
      } catch (error) { cancellation.abort(error); }
    };
    tick(); check();
    // Both groups reserve their actual Session/preauth/initializer/query vectors
    // before the first source call. Borrowed Controllers retain external owners.
    for (const item of groups) if (item.ownership === "owned") item.reservation.prepareConnection();
    check();
    const bindings: ServiceBindingTypes.ServiceBinding[] = [];
    // Reuse a bounded acquisition slot even when both Controllers borrow the
    // same Environment. Joint reservations remain held throughout both starts.
    for (const item of groups) {
      check();
      const connection = item.ownership === "owned" ? item.reservation.connect() : Promise.resolve();
      const binding = item.reservation.initializeBinding(item.ownership === "owned" ? () => { void item.controller.close(); } : undefined);
      const [ready] = await Promise.all([binding, connection]); bindings.push(ready);
    }
    check(); return groupedServiceClient(definition, bindings);
  } catch (error) {
    cancellation.abort(error); for (const item of prepared) item.close();
    await Promise.all(owned.map(controller => controller.close())); throw error;
  } finally { if (timer !== undefined) clearTimeout(timer); }
}
