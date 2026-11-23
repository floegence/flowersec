import type { JsonValue, RPCHandlers, Session } from "@floegence/flowersec-core/node";

type Registry = Pick<RPCHandlers, "handleRPC" | "handleNotification">;
type HandlerRequest = Parameters<Parameters<RPCHandlers['handleRPC']>[1]>[1];
type Permission = (id: number, request: HandlerRequest) => boolean;
export function parityRegistrations(handlers: Registry, permitted: Permission, mayDisclose?: Permission): Registry;
export function verifyParity(session: Session, signal?: AbortSignal): Promise<void>;
export class ParityEndpoint {
  session: Session | undefined;
  constructor(permitted: (id: number) => boolean);
  bind(session: Session, signal: AbortSignal): Promise<void>;
  allows(id: number): boolean;
  echo(payload: JsonValue, request: HandlerRequest): Promise<{ error: { code: number; message: string } } | { payload: JsonValue }>;
  stop(): void;
}
export function registerParityEndpoints<T extends RPCHandlers>(registry: T): T;
