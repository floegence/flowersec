import type { OperationOptions } from "../public/contract.js";
import type { V4AuthenticatedTransport, V4NativeApplicationStream } from "../v4/runtime/session.js";
import type { CarrierPreparationFields } from "../v4/runtime/credentialVerifier.js";
/** Keep physical provider custody and native objects unchanged while presenting
 * the signed endpoint's logical role to end-to-end admission and Noise. */
export function endpointTransport(physical: V4AuthenticatedTransport, endpointRole: 0 | 1): V4AuthenticatedTransport & { readonly checkAcceptedRoute?: (fields: CarrierPreparationFields, endpointRole?: 0 | 1) => void } {
  const role = endpointRole === 0 ? "client" : "server";
  if (physical.role === role) return physical;
  const streamView = (stream: V4NativeApplicationStream): V4NativeApplicationStream => Object.freeze({ ...view(stream), mode: "stream" as const, origin: stream.origin,
    closeWrite: stream.closeWrite.bind(stream), stopSending: stream.stopSending.bind(stream), resetWrite: stream.resetWrite.bind(stream), observeWriteFailure: stream.observeWriteFailure.bind(stream), cleanupComplete: stream.cleanupComplete.bind(stream) });
  const view = (owner: V4AuthenticatedTransport): V4AuthenticatedTransport => Object.freeze({ role, mode: owner.mode,
    ...(owner.nativeStreams === undefined ? {} : { nativeStreams: Object.freeze({ capacity: owner.nativeStreams.capacity, enable: owner.nativeStreams.enable.bind(owner.nativeStreams), open: async (options?: OperationOptions) => streamView(await owner.nativeStreams!.open(options)), accept: async (options?: OperationOptions) => streamView(await owner.nativeStreams!.accept(options)) }) }),
    ...(owner.nativeDatagrams === undefined ? {} : { nativeDatagrams: owner.nativeDatagrams }),
    ...(typeof (owner as V4AuthenticatedTransport & { checkAcceptedRoute?: (fields: CarrierPreparationFields, endpointRole?: 0 | 1) => void }).checkAcceptedRoute === "function" ?
      { checkAcceptedRoute: (owner as V4AuthenticatedTransport & { checkAcceptedRoute: (fields: CarrierPreparationFields, endpointRole?: 0 | 1) => void }).checkAcceptedRoute.bind(owner) } : {}),
    ...(owner.authenticateHop === undefined ? {} : { authenticateHop: owner.authenticateHop.bind(owner) }), ...(owner.checkPreparation === undefined ? {} : { checkPreparation: owner.checkPreparation.bind(owner) }),
    ...(owner.activate === undefined ? {} : { activate: owner.activate.bind(owner) }), ...(owner.exportBinding === undefined ? {} : { exportBinding: owner.exportBinding.bind(owner) }),
    read: owner.read.bind(owner), write: owner.write.bind(owner), submit: owner.submit.bind(owner), close: owner.close.bind(owner), waitTermination: owner.waitTermination.bind(owner) });
  return view(physical);
}
