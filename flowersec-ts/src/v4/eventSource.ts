import type { V4ApplicationContext } from "./streamHandlers.js";

export type V4EventPublishResult = "accepted" | "overflow" | "closed";
/** A synchronous SDK copy accepts only a real, non-shared Uint8Array. The
 * producer keeps its input; accepted bytes become an independent snapshot. */
export interface V4ByteEventPublisher {
  tryPublish(input: Uint8Array): V4EventPublishResult;
  complete(): void;
}
export type V4EventSourceDisposer = () => void | Promise<void>;
export interface V4ByteEventSourceOptions<Request, Item> {
  readonly maxEventInputBytes: number;
  readonly maxPendingItems?: number;
  /** Includes the queued/current input backing and its SDK runtime charge. */
  readonly maxPendingBytes?: bigint;
  readonly setup: (context: V4ApplicationContext, request: Request, publisher: V4ByteEventPublisher) =>
    void | V4EventSourceDisposer | Promise<void | V4EventSourceDisposer>;
  /** Input is borrowed through the actual mapper and response encoder exit. */
  readonly map: (context: V4ApplicationContext, input: Uint8Array) => Item | Promise<Item>;
}
export interface CapturedByteEventSource {
  readonly maxEventInputBytes: number;
  readonly maxPendingItems: number;
  readonly maxPendingBytes: bigint | undefined;
  readonly setup: V4ByteEventSourceOptions<unknown, unknown>["setup"];
  readonly map: V4ByteEventSourceOptions<unknown, unknown>["map"];
}
const capability = Symbol("SDK byte event source"), sources = new WeakMap<object, CapturedByteEventSource>();
/** Opaque service implementation, sharing the method's original Stream and
 * operation. Arbitrary iterators cannot opt into the SDK-controlled pump. */
export class V4ByteEventSource<Request, Item> {
  declare private readonly types: (request: Request) => Item;
  constructor(token: symbol, options: V4ByteEventSourceOptions<Request, Item>) {
    if (token !== capability) throw new Error("event_source_owner");
    const { maxEventInputBytes, maxPendingItems = 8, maxPendingBytes, setup, map } = options;
    if (!Number.isSafeInteger(maxEventInputBytes) || maxEventInputBytes < 1 || maxEventInputBytes > 1048576 ||
        !Number.isSafeInteger(maxPendingItems) || maxPendingItems < 1 || maxPendingItems > 8 ||
        maxPendingBytes !== undefined && (typeof maxPendingBytes !== "bigint" || maxPendingBytes < 1n || maxPendingBytes >= 1n << 63n) ||
        typeof setup !== "function" || typeof map !== "function") throw new Error("configuration_capacity");
    sources.set(this, Object.freeze({ maxEventInputBytes, maxPendingItems, maxPendingBytes,
      setup: setup as CapturedByteEventSource["setup"], map: map as CapturedByteEventSource["map"] }));
    Object.defineProperty(this, "then", { value: undefined }); Object.freeze(this);
  }
  toJSON(): object { return {}; }
}
export function v4ByteEventSource<Request, Item>(options: V4ByteEventSourceOptions<Request, Item>): V4ByteEventSource<Request, Item> {
  return new V4ByteEventSource(capability, options);
}
export function byteEventSource(value: unknown): CapturedByteEventSource | undefined {
  return typeof value === "object" && value !== null ? sources.get(value) : undefined;
}
Object.freeze(V4ByteEventSource.prototype); Object.freeze(V4ByteEventSource);
