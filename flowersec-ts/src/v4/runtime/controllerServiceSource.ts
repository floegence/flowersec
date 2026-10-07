import type { ControllerUnaryRoute, ControllerUnaryRouteRequest } from "./controllerUnaryRoute.js";
import { controllerUnaryPreparation } from "../unaryOperation.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type * as QueryRenewalPositionTypes from "./queryRenewalPosition.js";
import { resumeStreamSession } from "./resumeStream.js";
import type { V4ApplicationContext } from "../streamHandlers.js";
import type { TrustedClock } from "./clock.js";
import { TrustedDeadline } from "./deadline.js";
import type { ResourceReference } from "./resources.js";
import type { ServiceBindingLease, ServiceBindingSource } from "./serviceBinding.js";
import { checkServiceBindingTarget, type CapturedServiceBinding } from "./serviceBindingConfig.js";
import type { V4AuthenticatedSessionRuntime } from "./session.js";

export interface ControllerServiceHost {
  readonly clock: TrustedClock;
  readonly group: object;
  check(): void;
  capture(): V4AuthenticatedSessionRuntime;
  current(runtime: V4AuthenticatedSessionRuntime): boolean;
  target(session: object): V4AuthenticatedSessionRuntime;
  wait(deadline: TrustedDeadline, context?: V4ApplicationContext, signal?: AbortSignal): Promise<void>;
  retain(reference: ResourceReference, closed: () => void): ServiceBindingLease;
  observe(reference: ResourceReference, wake: () => void): () => void;
  observeCurrent(reference: ResourceReference, wake: () => void): () => void;
}

/** One immutable logical group, borrowing only published Sessions. Capturing
 * a fixed source never binds again, queries, acquires, or starts a Controller. */
export function controllerServiceSource(host: ControllerServiceHost, config: CapturedServiceBinding, preparation?: () => QueryRenewalPositionTypes.ContractQueryPreparation | undefined): ServiceBindingSource {
  let runtime: V4AuthenticatedSessionRuntime | undefined, source: ServiceBindingSource | undefined;
  const select = (): ServiceBindingSource => {
    host.check(); const selected = host.capture();
    if (selected !== runtime) { source = selected.rpcApplication().bindingSource(config, preparation); runtime = selected; }
    const fixed = source!;
    fixed.check(); checkServiceBindingTarget(config.target, fixed.authentication());
    if (host.capture() !== selected) throw new Error("source_unavailable");
    return fixed;
  };
  const resumeSource = (stream: Parameters<ServiceBindingSource["prepareResume"]>[4]): ServiceBindingSource => {
    host.check(); const selected = host.target(resumeStreamSession(stream));
    const fixed = selected.rpcApplication().bindingSource(config);
    fixed.check(); checkServiceBindingTarget(config.target, fixed.authentication());
    // Reenter Controller ownership after any trusted host clock sample.
    if (host.target(resumeStreamSession(stream)) !== selected) throw new Error("source_unavailable");
    return fixed;
  };
  return Object.freeze<ServiceBindingSource>({
    clock: host.clock, group: host.group,
    check: () => { select().check(); },
    current: () => { try { return select().current(); } catch { return false; } },
    incarnation: () => { select(); return runtime!; },
    observeCurrent: (reference, changed) => host.observeCurrent(reference, changed),
    authentication: () => select().authentication(),
    deadline: duration => {
      host.check();
      return TrustedDeadline.ageAt(host.clock, host.clock.sample(), duration, (1n << 64n) - 1n);
    },
    waitForCurrent: async (deadline, context, signal) => {
      await host.wait(deadline, context, signal);
      select(); const selected = runtime!;
      await selected.prepareServiceChannels(config.methods.some(method => method.facts.shape === "notify"), deadline, context, signal);
      // Never continue a wait on another Session after selecting this one.
      if (host.capture() !== selected) throw new Error("source_unavailable");
    },
    retain: (reference, closed) => host.retain(reference, closed),
    observeAvailability: (reference, wake) => host.observe(reference, wake),
    checkDependency: (method, contract) => select().checkDependency(method, contract),
    protectRenewal: reference => select().protectRenewal(reference),
    query: (targets, deadline, windows, context, delivery, renewal) => {
      const fixed = select(), sessionDeadline = fixed.deadline(90000n);
      const bounded = deadline.fork(deadline.cap < sessionDeadline.cap ? deadline.cap : sessionDeadline.cap);
      bounded.tightenFrom(sessionDeadline);
      return fixed.query(targets, bounded, windows, context, delivery, renewal);
    },
    preacceptStreams: (...args) => select().preacceptStreams(...args),
    prepare: (...args) => select().prepare(...args).then(prepared => controllerUnaryPreparation(prepared, host.group)),
    prepareDispatch: (method, namespace, contract, offer, value, settings, invocation, cancellation) => {
      const fixed = select(); let selected = runtime!, selections = 1;
      const originalAuthority = selected.rpcApplication().unaryRouteAuthority();
      const route: ControllerUnaryRoute = Object.freeze({
        get selections() { return selections; },
        current: () => host.current(selected),
        check: () => { host.check(); host.capture(); },
        observe: (reference: ResourceReference, changed: () => void) => host.observeCurrent(reference, changed),
        reserve: (request: ControllerUnaryRouteRequest) => {
          host.check(); const next = host.capture();
          if (next === selected || selections >= 3 || cancellation?.aborted || invocation?.signal.aborted) return undefined;
          const nextSource = next.rpcApplication().bindingSource(config);
          nextSource.check(); checkServiceBindingTarget(config.target, nextSource.authentication());
          nextSource.checkDependency(method, request.contract);
          if (host.capture() !== next) throw new RPCProtocolError("source_unavailable");
          // Consume a choice before entering resource/clock/provider callbacks.
          // A failed allocation cannot restore the revoked route's authority.
          selections++; selected = next;
          return next.rpcApplication().adoptControllerUnary(request, method, config.target, method.workClass, route, originalAuthority);
        },
      });
      return selected.rpcApplication().prepareUnary(method.method, namespace, contract, offer, value, settings,
        { check: () => fixed.check(), current: () => fixed.current() }, method.workClass, invocation, cancellation, config.target, undefined, route)
        .then(prepared => controllerUnaryPreparation(prepared, host.group));
    },
    prepareNotify: (...args) => select().prepareNotify(...args),
    prepareStream: (...args) => select().prepareStream(...args),
    resumeSource,
    // Selection uses the target's original owner, including an explicitly
    // retained Session, and never consults another current as a fallback.
    prepareResume: (...args) => resumeSource(args[4]).prepareResume(...args),
  });
}
