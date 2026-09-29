import type * as ResponsePublicationTypes from "./responsePublication.js";
import type * as CheckpointTypes from "./checkpoint.js";
import type * as EventSourceTypes from "./eventSource.js";
import type { OperationOptions } from "../public/contract.js";
import type { V4ApplicationContext } from "./streamHandlers.js";

export type V4OutputInterestReason = "response_output_stopped" | "response_complete" | "owner_unavailable";
export interface V4OutputInterestProgress { readonly interested: boolean; readonly reason?: V4OutputInterestReason; }
/** Borrowed observation of this invocation's original response path. */
export interface V4OutputInterest {
  readonly interested: boolean;
  progress(): V4OutputInterestProgress;
  waitLost(options?: OperationOptions): Promise<V4OutputInterestProgress>;
}
export interface V4UnaryContext extends V4ApplicationContext { readonly outputInterest: V4OutputInterest;
  readonly responsePublication: ResponsePublicationTypes.V4ResponsePublication;
  readonly maintenanceOwner: ResponsePublicationTypes.V4MaintenanceOwner | undefined; }
export type V4NotificationHandler<Request> = (context: V4ApplicationContext, request: Request) => void | Promise<void>;
export interface V4NotificationHandlerOptions {
  readonly workClass: "short" | "resident";
  readonly applicationBytes: bigint;
  readonly applicationTimeoutMS?: bigint;
  readonly authorization: "authenticated" | ((context: V4ApplicationContext) => boolean | Promise<boolean>);
}
export type V4UnaryHandler<Request, Response> = (context: V4UnaryContext, request: Request) => Response | CheckpointTypes.V4CheckpointResult | Promise<Response | CheckpointTypes.V4CheckpointResult>;
export type V4UnaryAuthorizer = (context: V4UnaryContext) => boolean | Promise<boolean>;
export interface V4UnaryHandlerOptions {
  readonly workClass: "short" | "resident";
  readonly maxConcurrentCalls: number;
  readonly applicationBytes: bigint;
  /** Explicit permission for this exact method on the authenticated Session,
   * or an application authorizer run before its request decoder. */
  readonly authorization: "authenticated" | V4UnaryAuthorizer;
}
const errors = new WeakMap<object, Readonly<{ code: number; value: unknown }>>();
/** Throw from the handler to select its declared typed application error. */
export class V4ServiceError<T> extends Error {
  constructor(code: number, value: T) {
    super("application_error"); this.name = "V4ServiceError";
    if (!Number.isSafeInteger(code) || code < 1 || code > 0xffffffff) throw new Error("application_error_code");
    errors.set(this, Object.freeze({ code, value })); Object.freeze(this);
  }
}
export function serviceError(value: unknown): Readonly<{ code: number; value: unknown }> | undefined {
  return typeof value === "object" && value !== null ? errors.get(value) : undefined;
}

/** One serial writer on the invocation's original dedicated result Stream. */
export interface V4StreamWriter<Item> {
  write(item: Item): Promise<void>;
}
export type V4StreamingHandler<Request, Item> = (context: V4ApplicationContext, request: Request, writer: V4StreamWriter<Item>) =>
  void | Promise<void> | AsyncIterable<Item>;
export interface V4StreamingHandlerOptions extends Omit<V4UnaryHandlerOptions, "authorization"> {
  readonly authorization: "authenticated" | ((context: V4ApplicationContext) => boolean | Promise<boolean>);
}

export type V4StreamingImplementation<Request, Item> = V4StreamingHandler<Request, Item> | EventSourceTypes.V4ByteEventSource<Request, Item>;
