import assert from "node:assert/strict";
import { FragmentError, decodeFragment, verifyFragmentRegistry } from "./transport-v4-fragments.mjs";

// Reference transitions only. BEGIN context and validateRequestInput represent
// an external, trusted header/content validator, not peer assertions or proof.
// Real Session-wide reservation, authentication, dispatch and physical cleanup
// must surround these transitions. No application bytes are retained here.
export function verifyFragmentStateRegistry(registry) {
  assert.deepEqual(registry, {
    first_serial: 1, serial_max: "18446744073709551615", max_payload_bytes: 1048576,
    retention: "live_request_reply_associations_only",
    data_offset: "exact_next_offset", abort: "incomplete_message_only",
    stop_output: "validated_live_request_coalesce_or_stale_ignore",
    capacity: "explicit_share_of_original_session_request_budget",
  }, "fragment state registry drift");
}

function fail(code) { throw new FragmentError(code); }
function direction(value) { if (value !== 0 && value !== 1) fail("direction"); return value; }

// This pure boundary helper exercises uint64 exhaustion without allowing a
// constructor to skip the initial serial or restore channel state.
export function advanceBeginSerial(registry, highwater, received) {
  const max = BigInt(registry.serial_max), first = BigInt(registry.first_serial);
  if (typeof highwater !== "bigint" || highwater < 0n || highwater > max) fail("highwater_range");
  if (highwater === max) fail("serial_exhausted");
  if (typeof received !== "bigint" || received < first || received > max) fail("serial_range");
  if (received !== highwater + 1n) fail(received <= highwater ? "serial_replay" : "serial_gap");
  return received;
}

export class FragmentState {
  #wire;
  #registry;
  #limit;
  #highwater = [0n, 0n];
  #messages = [new Map(), new Map()];
  #requests = [0, 0];
  #closed = false;

  constructor(schema, {requestCapacity}) {
    verifyFragmentRegistry(schema.fragment_registry);
    verifyFragmentStateRegistry(schema.fragment_state_registry);
    const cap = Object.values(schema.frame_maps.SessionContract.fields).find(field => field.name === "rpc_max_general_outstanding");
    if (!Number.isInteger(requestCapacity) || requestCapacity < cap.min || requestCapacity > cap.max) fail("capacity_range");
    // Capture the caller's already reserved Session share. An instance does
    // not reserve another free per-channel allowance.
    this.#wire = structuredClone(schema.fragment_registry);
    this.#registry = structuredClone(schema.fragment_state_registry);
    this.#limit = requestCapacity;
  }

  snapshot() {
    return {highwater:[...this.#highwater], requests:[...this.#requests],
      indexed_messages:this.#messages.map(map => map.size), closed:this.#closed};
  }

  accept(trafficDirection, bytes, context) {
    const dir = direction(trafficDirection);
    if (this.#closed) fail("channel_closed");
    const fragment = decodeFragment(this.#wire, bytes);
    if (fragment.kind === this.#wire.kinds.BEGIN.value) return this.#begin(dir, fragment, context);
    if (context !== undefined) fail("unexpected_context");
    if (fragment.kind === this.#wire.kinds.STOP_OUTPUT.value) return this.#stop(dir, fragment.request_serial);
    const message = this.#messages[dir].get(fragment.message_serial);
    if (!message || message.status !== "open") fail("message_not_open");
    if (fragment.kind === this.#wire.kinds.ABORT.value) {
      if (fragment.next_offset !== message.offset || message.offset >= message.length) fail("abort_offset");
      message.status = "aborted";
    } else {
      if (fragment.payload_offset !== message.offset) fail("offset_mismatch");
      const next = message.offset + fragment.payload_bytes.length;
      if (next > message.length) fail("payload_overrun");
      message.offset = next;
      if (next === message.length) message.status = "complete";
    }
    const result = {status:message.status, offset:message.offset};
    if (message.status !== "open" && message.type === "response") this.#retire(message.request);
    return result;
  }

  #begin(dir, fragment, context) {
    const next = advanceBeginSerial(this.#registry, this.#highwater[dir], fragment.message_serial);
    if (!context || !["request", "response"].includes(context.type)) fail("begin_context");
    const expectedKeys = context.type === "request" ? ["payload_length", "type"] : ["payload_length", "request", "response_kind", "type"];
    if (Object.keys(context).sort().join(",") !== expectedKeys.sort().join(",")) fail("begin_context");
    const length = context.payload_length;
    if (!Number.isInteger(length) || length < 0 || length > this.#registry.max_payload_bytes) fail("payload_length");
    let request;
    if (context.type === "request") {
      if (fragment.reply_to_serial !== 0n) fail("request_reply_to");
      if (this.#requests[dir] >= this.#limit) fail("state_capacity");
      request = {dir, serial:fragment.message_serial, token:Object.freeze({}), validated:false, stopped:false, response:undefined};
    } else {
      const original = this.#messages[1 - dir].get(fragment.reply_to_serial);
      if (!original || original.type !== "request" || original.request.token !== context.request) fail("response_binding");
      request = original.request;
      if (request.response !== undefined) fail("response_duplicate");
      if (context.response_kind === "request_message_aborted") {
        if (original.status !== "aborted") fail("response_boundary");
      } else if (["normal", "response_output_stopped"].includes(context.response_kind)) {
        if (original.status !== "complete" || !request.validated) fail("response_boundary");
      } else fail("response_kind");
    }
    const message = {type:context.type, request, length, offset:0, status:length === 0 ? "complete" : "open"};
    this.#messages[dir].set(next, message);
    this.#highwater[dir] = next;
    if (context.type === "request") this.#requests[dir] += 1;
    else request.response = {dir, serial:next};
    const result = {status:message.status, offset:0, request:request.token};
    if (context.type === "response" && message.status === "complete") this.#retire(request);
    return result;
  }

  validateRequestInput(trafficDirection, messageSerial, token) {
    const dir = direction(trafficDirection), message = this.#messages[dir].get(messageSerial);
    if (this.#closed || !message || message.type !== "request" || message.request.token !== token) fail("request_owner");
    if (message.status !== "complete") fail("request_incomplete");
    message.request.validated = true;
  }

  #stop(dir, value) {
    if (value > this.#highwater[dir]) fail("stop_future");
    const message = this.#messages[dir].get(value);
    if (!message) return {status:"ignored"};
    if (message.type !== "request" || message.status !== "complete" || !message.request.validated) fail("stop_ineligible");
    const request = message.request, status = request.stopped ? "coalesced" : "stop_requested";
    request.stopped = true;
    return {status};
  }

  #retire(request) {
    this.#messages[request.dir].delete(request.serial);
    this.#messages[request.response.dir].delete(request.response.serial);
    this.#requests[request.dir] -= 1;
  }

  close() {
    this.#closed = true;
    for (const map of this.#messages) map.clear();
    this.#requests = [0, 0];
    // Logical retirement does not prove physical cleanup; the channel cannot
    // reopen, and real provider/application references remain on their owners.
  }
}
