export {
  AcceptedSessionV3 as AcceptedSession,
  AcceptorV3 as Acceptor,
  createAcceptorV3 as createAcceptor,
} from "./acceptorV3.js";
export type {
  AcceptorListenerV3 as AcceptorListener,
  AcceptorAuthorizationDecisionV3 as AcceptorAuthorizationDecision,
  AcceptorAuthorizerV3 as AcceptorAuthorizer,
  AcceptorOptionsV3 as AcceptorOptions,
} from "./acceptorV3.js";
/** @deprecated Use the corresponding unversioned acceptor exports. */
export { AcceptedSessionV3, AcceptorV3, createAcceptorV3 } from "./acceptorV3.js";
/** @deprecated Use the corresponding unversioned acceptor types. */
export type {
  AcceptorListenerV3,
  AcceptorAuthorizationDecisionV3,
  AcceptorAuthorizerV3,
  AcceptorOptionsV3,
} from "./acceptorV3.js";
export {
  TunnelRuntimeV3 as TunnelRuntime,
  createTunnelRuntimeV3 as createTunnelRuntime,
} from "./tunnelRuntimeV3.js";
export type {
  TunnelAuthorizationDecisionV3 as TunnelAuthorizationDecision,
  TunnelRuntimeListenerV3 as TunnelRuntimeListener,
  TunnelRuntimeOptionsV3 as TunnelRuntimeOptions,
} from "./tunnelRuntimeV3.js";
/** @deprecated Use TunnelRuntime and createTunnelRuntime. */
export { TunnelRuntimeV3, createTunnelRuntimeV3 } from "./tunnelRuntimeV3.js";
/** @deprecated Use the corresponding unversioned tunnel runtime types. */
export type {
  TunnelAuthorizationDecisionV3,
  TunnelRuntimeListenerV3,
  TunnelRuntimeOptionsV3,
} from "./tunnelRuntimeV3.js";
export {
  RuntimeAuthorizationRequestV3 as RuntimeAuthorizationRequest,
  TunnelAuthorizationGrantV3 as TunnelAuthorizationGrant,
  verifyTunnelAuthorizationGrantV3 as verifyTunnelAuthorizationGrant,
} from "./runtimeAuthorizationV3.js";
export type {
  TunnelAuthorizationGrantOptionsV3 as TunnelAuthorizationGrantOptions,
} from "./runtimeAuthorizationV3.js";
/** @deprecated Use the corresponding unversioned runtime-authorization exports. */
export {
  RuntimeAuthorizationRequestV3,
  TunnelAuthorizationGrantV3,
  verifyTunnelAuthorizationGrantV3,
} from "./runtimeAuthorizationV3.js";
/** @deprecated Use TunnelAuthorizationGrantOptions. */
export type { TunnelAuthorizationGrantOptionsV3 } from "./runtimeAuthorizationV3.js";
export * from "../facade.js";
export * as v2 from "./v2.js";
import type { NodeTLSRootsV3 as NodeTLSRoots } from "./connectSessionV3.js";
export {
  connectV3 as connect,
  createConnectionControllerV3 as createConnectionController,
} from "./connectSessionV3.js";
/** @deprecated Use connect and createConnectionController. */
export { connectV3, createConnectionControllerV3 } from "./connectSessionV3.js";
export type {
  ConnectionControllerOptionsV3 as ConnectionControllerOptions,
  NodeTLSRootsV3 as NodeTLSRoots,
  SessionOptionsV3 as SessionOptions,
} from "./connectSessionV3.js";
/** @deprecated Use ConnectionControllerOptions, SessionTLSOptions, and SessionOptions. */
export type {
  ConnectionControllerOptionsV3,
  NodeTLSRootsV3,
  SessionOptionsV3,
} from "./connectSessionV3.js";
export type SessionTLSOptions = Readonly<{
  ca?: NodeTLSRoots;
}>;
export {
  HandlerRegistrationError,
  RPCHandlers,
  SessionHandlersV3 as SessionHandlers,
} from "./acceptor.js";
export type {
  NotificationHandler,
  RPCHandler,
  RPCHandlerResult,
  SessionHandlerOptions,
} from "./acceptor.js";
