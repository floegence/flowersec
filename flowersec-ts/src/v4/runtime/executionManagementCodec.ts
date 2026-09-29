import type { ApplicationHeaderCodec} from "./applicationHeader.js";
import { type ApplicationHeader } from "./applicationHeader.js";
import { CBORDecoder, cborDecoderCharge, type CBORDocument } from "./cbor.js";
import { FixedCBORWriter } from "./cborWriter.js";
import { RPCProtocolError } from "./rpcFragment.js";
import type { ResourceReference } from "./resources.js";
import { transportV4ApplicationHeaders as registry } from "../../generated/transportV4Registry.js";

export const managementSpec = registry.management;
export const hex = (bytes: Uint8Array): string => Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
export const unhex = (value: string): Uint8Array => Uint8Array.from(value.match(/../gu) ?? [], value => Number.parseInt(value, 16));
export interface ExecutionTarget {
  readonly tenant: string;
  readonly audience: string;
  readonly namespace: string;
  readonly subject: string;
  readonly authority: string;
  readonly operation: string;
  readonly requestDigest: string;
  readonly contractDigest: string;
}
export interface ExecutionObservation {
  readonly found: boolean;
  readonly reason: "none" | "cancelled" | "dispatch_unavailable" | "work_outcome_unknown" | "deadline_exceeded" | "not_registered" | "history_unknown";
  readonly state?: "accepted" | "executing" | "completed" | "failed" | "unknown";
  readonly cancelRequested?: boolean;
  readonly dispatched?: boolean;
  readonly workActive?: boolean;
  readonly historyNotBeforeGCMS?: bigint;
  readonly resultNotAfterMS?: bigint;
  readonly resultAvailable?: boolean;
  readonly resultDeleted?: boolean;
  readonly resultBytes?: number;
  readonly applicationErrorCode?: number;
  readonly resultDigest?: string;
}
export interface ExecutionManagementResult {
  readonly status: "ok" | "unavailable" | "unauthorized" | "operation_conflict" | "unsupported" | "deadline_exceeded" | "result_expired" | "not_found" | "history_unknown";
  readonly observation?: ExecutionObservation;
  readonly cancelResult?: "requested" | "terminal" | "not_registered" | "history_unknown";
}
const statuses = ["ok", "unavailable", "unauthorized", "operation_conflict", "unsupported", "deadline_exceeded", "result_expired", "not_found", "history_unknown"] as const;
const reasons = ["none", "cancelled", "dispatch_unavailable", "work_outcome_unknown", "deadline_exceeded", "not_registered", "history_unknown"] as const;
const states = ["accepted", "executing", "completed", "failed", "unknown"] as const;
const cancels = ["requested", "terminal", "not_registered", "history_unknown"] as const;
const settings = (runtimeBytes: bigint) => ({ bytes: 1024, nodes: 64, textBytes: 512, arrayItems: 16, runtimeBytes });
export const executionManagementDecoderCharge = (runtimeBytes: bigint) => cborDecoderCharge(settings(runtimeBytes));
function invalid(): never { throw new RPCProtocolError("management_binding"); }
export function captureExecutionTarget(input: ExecutionTarget): ExecutionTarget {
  const { tenant, audience, namespace, subject, authority, operation, requestDigest, contractDigest } = input;
  if (![tenant, audience, namespace, subject].every(value => typeof value === "string" && /^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(value)) ||
      ![authority, operation, requestDigest, contractDigest].every(value => typeof value === "string" && /^[0-9a-f]{64}$/u.test(value))) invalid();
  return Object.freeze({ tenant, audience, namespace, subject, authority, operation, requestDigest, contractDigest });
}
/** The same target fields are nested in local references and sent on M/RPC. */
export function readExecutionTarget(doc: CBORDocument, node: number): ExecutionTarget {
  const digest = new Uint8Array(32);
  try {
    const read = (id: number): string => { doc.copyPayload(doc.field(node, id), digest); return hex(digest); };
    return captureExecutionTarget({ tenant: doc.text(doc.field(node, 0)), audience: doc.text(doc.field(node, 1)), namespace: doc.text(doc.field(node, 2)), subject: doc.text(doc.field(node, 3)),
      authority: read(4), operation: read(5), requestDigest: read(6), contractDigest: read(7) });
  } finally { digest.fill(0); }
}
export function writeExecutionTarget(writer: FixedCBORWriter, target: ExecutionTarget): FixedCBORWriter {
  writer.map(8); const encoder = new TextEncoder();
  [target.tenant, target.audience, target.namespace, target.subject].forEach((value, id) => writer.uint(id).data(encoder.encode(value), true));
  [target.authority, target.operation, target.requestDigest, target.contractDigest].forEach((value, id) => writer.uint(id + 4).data(unhex(value)));
  return writer;
}
/** Shared canonical registry and fixed reusable SDK parser. No application codec. */
export class ExecutionManagementCodec {
  readonly #decoder: CBORDecoder;
  constructor(runtimeBytes: bigint, reference: ResourceReference) { this.#decoder = new CBORDecoder(settings(runtimeBytes), reference); }
  target(bytes: Uint8Array): ExecutionTarget {
    const doc = this.#decoder.decodeMap(bytes, "ExecutionManagementTarget");
    try { return readExecutionTarget(doc, 0); } finally { doc.release(); }
  }
  encodeTarget(target: ExecutionTarget, destination: Uint8Array): Uint8Array {
    const bytes = writeExecutionTarget(new FixedCBORWriter(destination), target).result(); this.target(bytes); return bytes;
  }
  result(bytes: Uint8Array, cancel: boolean): ExecutionManagementResult {
    const doc = this.#decoder.decodeMap(bytes, cancel ? "RequestCancelResponse" : "QueryOperationResponse");
    try {
      const status = statuses[Number(doc.uint(doc.field(0, 0)))]; if (status === undefined) invalid();
      const has = ["ok", "result_expired", "not_found", "history_unknown"].includes(status), node = doc.field(0, 1), cancelNode = doc.field(0, 2);
      if (has !== (node >= 0) || (has && cancel) !== (cancelNode >= 0)) invalid();
      if (!has) return Object.freeze({ status });
      const found = doc.boolean(doc.field(node, 0)), reason = reasons[Number(doc.uint(doc.field(node, 1)))];
      if (reason === undefined || doc.size(node) !== (found ? 13 : 2)) invalid();
      let observation: ExecutionObservation = { found, reason };
      if (found) {
        const state = states[Number(doc.uint(doc.field(node, 2))) - 1]; if (state === undefined) invalid();
        const digest = new Uint8Array(32); doc.copyPayload(doc.field(node, 12), digest);
        observation = { ...observation, state, cancelRequested: doc.boolean(doc.field(node, 3)), dispatched: doc.boolean(doc.field(node, 4)), workActive: doc.boolean(doc.field(node, 5)),
          historyNotBeforeGCMS: doc.uint(doc.field(node, 6)), resultNotAfterMS: doc.uint(doc.field(node, 7)), resultAvailable: doc.boolean(doc.field(node, 8)),
          resultDeleted: doc.boolean(doc.field(node, 9)), resultBytes: Number(doc.uint(doc.field(node, 10))), applicationErrorCode: Number(doc.uint(doc.field(node, 11))), resultDigest: hex(digest) };
        digest.fill(0);
      }
      const cancelResult = cancel ? cancels[Number(doc.uint(cancelNode))] : undefined;
      if (cancel && cancelResult === undefined || status === "not_found" && (found || reason !== "not_registered") || status === "history_unknown" && (found || reason !== "history_unknown")) invalid();
      return Object.freeze({ status, observation: Object.freeze(observation), ...(cancelResult === undefined ? {} : { cancelResult }) });
    } finally { doc.release(); }
  }
  encodeResult(result: ExecutionManagementResult, cancel: boolean, destination: Uint8Array): Uint8Array {
    const observation = result.observation, writer = new FixedCBORWriter(destination).map(observation === undefined ? 1 : cancel ? 3 : 2);
    writer.uint(0).uint(statuses.indexOf(result.status));
    if (observation !== undefined) {
      writer.uint(1).map(observation.found ? 13 : 2).uint(0).bool(observation.found).uint(1).uint(reasons.indexOf(observation.reason));
      if (observation.found) writer.uint(2).uint(states.indexOf(observation.state!) + 1).uint(3).bool(observation.cancelRequested!).uint(4).bool(observation.dispatched!)
        .uint(5).bool(observation.workActive!).uint(6).uint(observation.historyNotBeforeGCMS!).uint(7).uint(observation.resultNotAfterMS!)
        .uint(8).bool(observation.resultAvailable!).uint(9).bool(observation.resultDeleted!).uint(10).uint(observation.resultBytes!)
        .uint(11).uint(observation.applicationErrorCode!).uint(12).data(unhex(observation.resultDigest!));
      if (cancel) writer.uint(2).uint(cancels.indexOf(result.cancelResult!));
    }
    const bytes = writer.result(); this.result(bytes, cancel); return bytes;
  }
  close(): void { this.#decoder.close(); }
}
export function managementBinding(header: ApplicationHeader): boolean {
  const cancel = header.kind === "request_cancel_request" || header.kind === "request_cancel_response", spec = managementSpec.methods[cancel ? "cancel" : "query"];
  const digest = new Uint8Array(32); header.copyBytes(6, digest);
  if (header.kind !== (header.isResponse() ? spec.response_kind : spec.request_kind) || header.typeID !== spec.type || hex(digest) !== spec.contract_digest_hex ||
      header.payloadBytes > (header.isResponse() ? 512 : 1024)) invalid();
  return cancel;
}
export function managementHeader(codec: ApplicationHeaderCodec, cancel: boolean, response: boolean, serial: bigint, length: number, deadline: bigint): ApplicationHeader {
  const spec = managementSpec.methods[cancel ? "cancel" : "query"];
  return codec.create({ kind: response ? spec.response_kind : spec.request_kind, typeID: spec.type, payloadBytes: length,
    contractDigest: unhex(spec.contract_digest_hex), controlSerial: serial, ...(response ? {} : { deadlineAtMS: deadline }) });
}
Object.freeze(ExecutionManagementCodec.prototype);
