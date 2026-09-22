import { VectorError } from "./transport-v4-codec.mjs";
import { captureApplicationBytes, decodeApplicationHeader, matchApplicationRequestContractReference, verifyApplicationResponse, verifyExecutionRequest } from "./transport-v4-application-headers.mjs";
import { classifyApplicationErrorReference } from "./transport-v4-application-errors.mjs";
import { verifyApplicationSDKErrorReference } from "./transport-v4-application-sdk-errors.mjs";
import { decodeFragment } from "./transport-v4-fragments.mjs";
import { FragmentState } from "./transport-v4-fragment-state.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const fieldID = (schema, name, key) => BigInt(Object.entries(schema.frame_maps[name].fields).find(([, field]) => field.name === key)[0]);
const field = (schema, name, map, key) => map.get(fieldID(schema, name, key));

// Test-only composition for already routed execution/transient unary methods.
// Each request BEGIN takes its trusted exact contract, never peer-selected code
// or a callback. Other channel kinds and local rejection/discard paths are not
// modeled. This consumes complete fragments, not provider/record chunks.
//
// The supplied requestCapacity is a share of the original Session reservation.
// At most 2 * capacity payload buffers coexist, each <= the wire payload cap:
// request backing is released before any response can start. Header/contract,
// fragment scratch, parser/hash copies, runtime work and actual backing/GC costs
// remain separate and do not acquire production qualification from that bound.
// A failed transcript is permanently closed; errors here do not classify local
// setup/resource failures as peer faults or choose any real transport scope.
export class UnaryFragmentReference {
  #schema;
  #state;
  #messages = [new Map(), new Map()];
  #payloadLimit;

  constructor(schema, { requestCapacity }) {
    this.#schema = structuredClone(schema);
    this.#state = new FragmentState(this.#schema, { requestCapacity });
    this.#payloadLimit = 2 * requestCapacity * schema.resource_caps.max_payload_length;
  }

  snapshot() {
    const state = this.#state.snapshot();
    const payloadBytes = this.#messages.reduce((sum, messages) => sum + [...messages.values()].reduce((n, message) => n + (message.payload?.length ?? 0), 0), 0);
    return Object.freeze({ ...state, highwater: Object.freeze(state.highwater), requests: Object.freeze(state.requests), indexed_messages: Object.freeze(state.indexed_messages), payload_bytes: payloadBytes, payload_bound: this.#payloadLimit });
  }

  #unary(kind) {
    const shape = this.#schema.application_headers.contract_variants[kind];
    const id = fieldID(this.#schema, "ServiceContract", "call_shape");
    return shape?.[id] === this.#schema.frame_maps.ServiceContract.fields[id].enum.unary;
  }

  accept(trafficDirection, input, contract) {
    try {
      requireThat(trafficDirection === 0 || trafficDirection === 1, "direction");
      requireThat(!this.#state.snapshot().closed, "channel_closed");
      const bytes = captureApplicationBytes(input, this.#schema.fragment_registry.max_fragment_bytes);
      const fragment = decodeFragment(this.#schema.fragment_registry, bytes);
      const kinds = this.#schema.fragment_registry.kinds;
      if (fragment.kind === kinds.BEGIN.value) return this.#begin(trafficDirection, fragment, bytes, contract);
      requireThat(contract === undefined, "unexpected_contract");
      const result = this.#state.accept(trafficDirection, bytes);
      if (fragment.kind === kinds.STOP_OUTPUT.value) {
        const original = this.#messages[trafficDirection].get(fragment.request_serial);
        if (original) original.stopped = true;
        return Object.freeze(result);
      }
      const message = this.#messages[trafficDirection].get(fragment.message_serial);
      if (fragment.kind === kinds.DATA.value) fragment.payload_bytes.copy(message.payload, message.offset);
      message.status = result.status;
      message.offset = result.offset;
      if (result.status === "complete") return this.#complete(message);
      if (result.status === "aborted") {
        // No application bytes escape; incomplete input never reaches a codec.
        message.payload = undefined;
        if (message.type === "response") this.#retire(message);
      }
      return Object.freeze({ type: message.type, ...result });
    } catch (error) {
      this.close();
      throw error;
    }
  }

  #begin(dir, fragment, bytes, contract) {
    const schema = this.#schema, header = decodeApplicationHeader(schema, fragment.canonical_header);
    const variant = schema.application_message_kinds[header.kind];
    const length = Number(field(schema, "ApplicationHeader", header.map, "payload_length"));
    const type = variant.request ? "response" : "request";
    requireThat(this.#unary(variant.request ?? header.kind), "unary_fragment_kind");
    let original, contractBytes, responseKind, context;
    if (type === "request") {
      // This is a reference precondition, not an unknown-contract refusal path.
      requireThat(contract !== undefined, "reference_contract_required");
      contractBytes = matchApplicationRequestContractReference(schema, header.bytes, contract).bytes;
      context = { type, payload_length: length };
    } else {
      requireThat(contract === undefined, "unexpected_contract");
      original = this.#messages[1 - dir].get(fragment.reply_to_serial);
      requireThat(original?.type === "request", "response_binding");
      verifyApplicationResponse(schema, original.header.bytes, header.bytes);
      responseKind = "normal";
      if (variant.sdk_error) {
        responseKind = original.status === "aborted" ? "request_message_aborted" : "normal";
      }
      context = { type, payload_length: length, request: original.token, response_kind: responseKind };
    }
    const result = this.#state.accept(dir, bytes, context);
    // Header, contract, reply and state limits all precede full payload backing.
    const message = { dir, serial: fragment.message_serial, type, header, contract: contractBytes,
      original, responseKind, token: result.request, stopped: false,
      status: result.status, offset: 0, payload: Buffer.alloc(length) };
    this.#messages[dir].set(fragment.message_serial, message);
    if (message.status === "complete") return this.#complete(message);
    return Object.freeze({ type, status: message.status, offset: 0 });
  }

  #complete(message) {
    const schema = this.#schema;
    let result;
    if (message.type === "request") {
      if (schema.application_headers.execution_requests.includes(message.header.kind)) {
        verifyExecutionRequest(schema, message.header.bytes, message.contract, message.payload);
      }
      // Includes the empty payload path at BEGIN. No caller-supplied flag can
      // mark execution input valid, and no dispatch/Offer/time/authority follows.
      this.#state.validateRequestInput(message.dir, message.serial, message.token);
      message.payload = undefined;
    } else {
      const variant = schema.application_message_kinds[message.header.kind], original = message.original;
      if (variant.sdk_error) {
        result = verifyApplicationSDKErrorReference(schema, original.header.bytes, message.header.bytes, message.payload);
        if (message.responseKind === "request_message_aborted") {
          requireThat(result.code === "request_message_aborted", "response_stop_code");
        } else {
          requireThat(result.code !== "request_message_aborted", "response_stop_code");
          if (result.code === "response_output_stopped") requireThat(original.stopped, "response_stop_boundary");
          else requireThat(schema.application_sdk_errors.refusal_codes.includes(result.code), "application_sdk_error_code");
        }
      } else if (variant.application_error) {
        result = classifyApplicationErrorReference(schema, original.header.bytes, message.header.bytes, original.contract, message.payload);
      }
      this.#retire(message);
    }
    // Metadata events only. No typed success value, incomplete bytes, retry,
    // execution, admission, delivery or real resource-release fact is exposed.
    return Object.freeze({ type: message.type, status: "complete", offset: message.offset, ...(result === undefined ? {} : { result }) });
  }

  #retire(response) {
    this.#messages[response.original.dir].delete(response.original.serial);
    this.#messages[response.dir].delete(response.serial);
    response.payload = undefined;
  }

  close() {
    this.#state.close();
    for (const messages of this.#messages) messages.clear();
  }
}
