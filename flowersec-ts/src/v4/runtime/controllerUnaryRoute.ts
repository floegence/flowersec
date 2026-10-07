import type { V4AuthenticatedContext } from "../streamHandlers.js";
import type { ApplicationHeader } from "./applicationHeader.js";
import type { TrustedDeadline } from "./deadline.js";
import type { ResourceReference } from "./resources.js";
import type { RPCPublicationGuard } from "./rpcPublisher.js";
import type { RPCUnaryExchange } from "./rpcUnaryExchange.js";
import type { CapturedMethodDefinition } from "../serviceDefinition.js";
import type { ServiceContractSnapshot } from "./serviceContract.js";

/** Original encoded operation facts. These bytes are private prepaid backing;
 * replacing a route cannot run an encoder, make an ID or renew a deadline. */
export interface ControllerUnaryRouteRequest {
  readonly header: ApplicationHeader;
  readonly contract: ServiceContractSnapshot;
  readonly method: CapturedMethodDefinition;
  readonly bytes: Uint8Array;
  readonly authentication: V4AuthenticatedContext;
  readonly deadline: TrustedDeadline;
  readonly publication: RPCPublicationGuard;
}

/** SDK-local source selection. reserve uses only the already published current
 * and returns its fully admitted request/result/Completion owner. */
export interface ControllerUnaryRoute {
  readonly selections: number;
  current(): boolean;
  check(): void;
  observe(reference: ResourceReference, changed: () => void): () => void;
  reserve(request: ControllerUnaryRouteRequest): RPCUnaryExchange | undefined;
}
