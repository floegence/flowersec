import { decodeMap, VectorError } from "./transport-v4-codec.mjs";
import { captureApplicationBytes, decodeApplicationHeader, matchApplicationRequestContractReference, verifyApplicationResponse, verifyExecutionRequest } from "./transport-v4-application-headers.mjs";
import { classifyApplicationErrorReference } from "./transport-v4-application-errors.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };
const field = (schema, name, value, key) => value.get(BigInt(Object.entries(schema.frame_maps[name].fields).find(([, entry]) => entry.name === key)[0]));
import { verifyApplicationSDKErrorReference } from "./transport-v4-application-sdk-errors.mjs";

const MAX = 0xffffffffffffffffn;

// Test-only transcript for one already routed dedicated server-streaming call.
// Headers are complete canonical candidates; chunks are already authenticated,
// correctly ordered application bytes. Native length-prefix/record parsing,
// actual Stream ownership, current authorization, Offer/execution/dispatch,
// production clocks and cleanup remain external.
//
// At most one assembly/current-result payload is retained. A pending candidate
// must be handed off before supplying another response header: real receivers
// must backpressure here, not treat a slow consumer as a protocol fault. This
// bound excludes headers, schema/contract, input/parser/hash scratch, transient
// copies, real backing and GC. Reference failure assigns no transport scope.
export class StreamingMessageReference {
  #schema; #contract; #contractMap; #chunkLimit; #request;
  #current; #candidate; #requestValidated = false; #requestEOF = false;
  #responseEOF = false; #terminal = "open"; #closed = false;
  #receivedItems = 0n; #receivedBytes = 0n; #deliveredItems = 0n; #deliveredBytes = 0n;

  constructor(schema, { contract, inputChunkBytes }) {
    this.#schema = structuredClone(schema);
    requireThat(Number.isSafeInteger(inputChunkBytes) && inputChunkBytes > 0 && inputChunkBytes <= schema.resource_caps.max_payload_length, "streaming_chunk_capacity");
    this.#chunkLimit = inputChunkBytes;
    this.#contract = captureApplicationBytes(contract, schema.frame_maps.ServiceContract.max_encoded_bytes);
    this.#contractMap = decodeMap(this.#schema, "ServiceContract", this.#contract);
    const shape = schema.frame_maps.ServiceContract.fields[2].enum.server_streaming;
    requireThat(this.#contractMap.get(2n) === BigInt(shape), "streaming_contract_shape");
  }

  #limit(name) { return field(this.#schema, "ServiceContract", this.#contractMap, name); }
  #guard(action) {
    try { requireThat(!this.#closed, "streaming_reference_closed"); return action(); }
    catch (error) { this.close(); throw error; }
  }

  beginRequest(header) {
    return this.#guard(() => {
      requireThat(this.#request === undefined, "streaming_second_request");
      const candidate = decodeApplicationHeader(this.#schema, header);
      const expected = this.#schema.application_headers.contract_variants[candidate.kind];
      requireThat(expected?.[2] === this.#schema.frame_maps.ServiceContract.fields[2].enum.server_streaming, "streaming_request_kind");
      matchApplicationRequestContractReference(this.#schema, candidate.bytes, this.#contract);
      this.#request = candidate;
      return this.#begin("request", candidate);
    });
  }

  beginResponse(header) {
    return this.#guard(() => {
      requireThat(this.#requestValidated, "streaming_request_incomplete");
      requireThat(this.#terminal === "open" && !this.#responseEOF, "streaming_terminal");
      requireThat(!this.#current && !this.#candidate, "streaming_candidate_pending");
      const response = verifyApplicationResponse(this.#schema, this.#request.bytes, header);
      const variant = this.#schema.application_message_kinds[response.kind];
      const length = response.map.get(3n);
      if (!variant.sdk_error) requireThat(length <= MAX - this.#receivedBytes && length <= this.#limit("max_stream_payload_bytes") - this.#receivedBytes, "streaming_payload_total");
      if (!variant.application_error && !variant.sdk_error) {
        requireThat(this.#receivedItems < this.#limit("max_item_count"), "streaming_item_count");
      }
      return this.#begin("response", response);
    });
  }

  #begin(direction, header) {
    this.#current = { direction, header, bytes: Buffer.alloc(Number(header.map.get(3n))), offset: 0 };
    return this.#current.bytes.length === 0 ? this.#complete() : this.snapshot();
  }

  payload(direction, input) {
    return this.#guard(() => {
      requireThat(this.#current?.direction === direction && ["request", "response"].includes(direction), "streaming_payload_owner");
      const chunk = captureApplicationBytes(input, this.#chunkLimit), current = this.#current;
      requireThat(chunk.length > 0 && chunk.length <= current.bytes.length - current.offset, "streaming_payload_length");
      chunk.copy(current.bytes, current.offset); current.offset += chunk.length;
      return current.offset === current.bytes.length ? this.#complete() : this.snapshot();
    });
  }

  #complete() {
    const current = this.#current;
    if (current.direction === "request") {
      if (this.#schema.application_headers.execution_requests.includes(current.header.kind)) {
        verifyExecutionRequest(this.#schema, this.#request.bytes, this.#contract, current.bytes);
      }
      this.#requestValidated = true;
    } else {
      const variant = this.#schema.application_message_kinds[current.header.kind];
      if (variant.sdk_error) {
        const result = verifyApplicationSDKErrorReference(this.#schema, this.#request.bytes, current.header.bytes, current.bytes);
        this.#candidate = { type: "sdk_error", bytes: current.bytes, result };
        this.#terminal = "sdk_error";
      } else if (variant.application_error) {
        const result = classifyApplicationErrorReference(this.#schema, this.#request.bytes, current.header.bytes, this.#contract, current.bytes);
        this.#candidate = { type: "application_error", bytes: current.bytes, result };
        this.#terminal = "application_error";
      } else {
        this.#receivedItems++; this.#receivedBytes += BigInt(current.bytes.length);
        this.#candidate = { type: "item", bytes: current.bytes };
      }
    }
    this.#current = undefined;
    return this.snapshot();
  }

  eof(direction) {
    return this.#guard(() => {
      requireThat(["request", "response"].includes(direction), "streaming_direction");
      if (direction === "request") {
        requireThat(this.#requestValidated && !this.#requestEOF, "streaming_request_eof");
        this.#requestEOF = true;
      } else {
        requireThat(this.#requestValidated && !this.#responseEOF, "streaming_response_eof");
        requireThat(this.#current === undefined, "streaming_partial_eof");
        this.#responseEOF = true;
        if (this.#terminal === "open") this.#terminal = "normal";
      }
      // Normal EOF preserves the one complete, still-undelivered candidate.
      return this.snapshot();
    });
  }

  // Record an actual original owner's irrevocable delivery. This method does
  // not authenticate a caller assertion, decode a value, transfer bytes or
  // implement the host handoff gate. Peer EOF/error never calls it implicitly.
  observeDelivery() {
    return this.#guard(() => {
      requireThat(this.#candidate !== undefined, "streaming_no_candidate");
      const candidate = this.#candidate;
      if (candidate.type === "item") {
        this.#deliveredItems++; this.#deliveredBytes += BigInt(candidate.bytes.length);
      }
      const result = Object.freeze({ type: candidate.type, payload_bytes: candidate.bytes.length, ...candidate.result });
      this.#candidate = undefined;
      return result;
    });
  }

  wait({ canceled = false } = {}) {
    requireThat(typeof canceled === "boolean", "streaming_wait_parameters");
    return Object.freeze({ wait_status: this.#terminal !== "open" || this.#closed ? "ready" : canceled ? "wait_canceled" : "blocked", progress: this.snapshot() });
  }

  snapshot() {
    return Object.freeze({ closed: this.#closed, request_validated: this.#requestValidated,
      request_eof: this.#requestEOF, response_eof: this.#responseEOF, terminal: this.#terminal,
      received_items: this.#receivedItems, received_bytes: this.#receivedBytes,
      delivered_items: this.#deliveredItems, delivered_bytes: this.#deliveredBytes,
      current_offset: this.#current?.offset ?? 0, candidate: this.#candidate?.type ?? "none",
      payload_bytes: this.#current?.bytes.length ?? this.#candidate?.bytes.length ?? 0 });
  }

  close() {
    this.#closed = true; this.#current = undefined; this.#candidate = undefined;
  }
}
