import assert from "node:assert/strict";
import { types } from "node:util";
import { referenceByteView } from "./transport-v4-bytes.mjs";

// Native result reference validation, not a public SDK or ownership engine.
// ReadContext must come from the original trusted owner at the result gate.
// Accepting this input cannot prove authentication, handoff, release or cleanup.
export class ApiResultError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new ApiResultError(code); };
const requireThat = (condition, code) => { if (!condition) fail(code); };
const MAX = 0xffffffffffffffffn;
const primitives = new Set(["uint64", "bytes", "bool"]);
const ruleNames = new Set(["registered_error_projection", "read_progress_bounds", "read_result_matrix", "reader_cursor_snapshot_matrix", "read_method_failure_matrix", "cleanup_result_matrix", "write_progress_matrix", "transfer_progress_matrix", "duplex_send_matrix", "duplex_direction_matrix", "duplex_result_matrix", "publication_result_matrix"]);
const has = (object, name) => Object.hasOwn(object, name);
function byteView(value) {
  try { return referenceByteView(value); } catch { fail("api_bytes"); }
}

export function apiEnumValues(schema, definition) {
  if (definition.enum) return [...definition.enum];
  const registry = schema[definition.registry];
  assert.ok(registry && typeof registry === "object", "unknown API enum registry");
  const values = definition.select === "keys" ? Object.keys(registry) : Object.values(registry).map(entry => entry[definition.select]);
  return [...new Set(values)].filter(value => !definition.exclude.includes(value));
}

export function verifyApiSchema(schema) {
  const api = schema.api_schema;
  assert.equal(api.status, "draft_native_io_result_subset");
  assert.equal(api.representation, "native_public_objects_not_wire_maps");
  const definitions = {...api.types, ...api.contexts};
  assert.equal(Object.keys(definitions).length, Object.keys(api.types).length + Object.keys(api.contexts).length, "context shadows public type");
  const edges = new Map();
  for (const [name, definition] of Object.entries(definitions)) {
    assert.match(name, /^[A-Z][a-zA-Z0-9]*$/u);
    assert.equal(["enum", "registry", "fields"].filter(key => has(definition, key)).length, 1, "ambiguous API type");
    const keys = definition.fields ? ["fields", "rules", "context_type"] : definition.enum ? ["enum"] : ["registry", "select", "exclude"];
    for (const key of Object.keys(definition)) assert.ok(keys.includes(key), "unknown API definition attribute");
    edges.set(name, []);
    if (!definition.fields) {
      if (definition.registry) {
        assert.ok(["keys", "scope", "retry"].includes(definition.select));
        assert.ok(Array.isArray(definition.exclude));
      }
      const values = apiEnumValues(schema, definition);
      assert.ok(values.length > 0 && new Set(values).size === values.length, "empty or duplicate API enum");
      for (const value of values) assert.match(value, /^[a-z][a-z0-9_]*$/u);
      continue;
    }
    assert.ok(Object.keys(definition.fields).length > 0);
    if (definition.context_type !== undefined) assert.ok(has(api.contexts, definition.context_type), "unresolved private result context");
    for (const [field, descriptor] of Object.entries(definition.fields)) {
      assert.match(field, /^[a-z][a-z0-9_]*$/u);
      assert.ok(Object.keys(descriptor).every(key => ["type", "optional", "context_field"].includes(key)));
      if (descriptor.optional !== undefined) assert.equal(descriptor.optional, true);
      assert.ok(primitives.has(descriptor.type) || has(definitions, descriptor.type), "unresolved API type");
      if (!primitives.has(descriptor.type)) {
        edges.get(name).push(descriptor.type);
        if (has(api.types, name)) assert.ok(has(api.types, descriptor.type), "public type exposes private context");
      }
      const childContext = definitions[descriptor.type]?.context_type;
      if (descriptor.context_field !== undefined || childContext !== undefined) {
        assert.ok(typeof descriptor.context_field === "string" && definition.context_type !== undefined, "missing nested context binding");
        const selected = api.contexts[definition.context_type].fields?.[descriptor.context_field];
        assert.ok(selected && !selected.optional && selected.type === childContext, "nested context type mismatch");
      }
    }
    for (const rule of definition.rules ?? []) assert.ok(ruleNames.has(rule), "unknown API rule");
    assert.equal(new Set(definition.rules ?? []).size, (definition.rules ?? []).length, "duplicate API rule");
  }
  const visit = (name, stack) => {
    assert.ok(!stack.includes(name), "recursive API type");
    for (const next of edges.get(name)) visit(next, [...stack, name]);
  };
  for (const name of edges.keys()) visit(name, []);
}

function shape(schema, name, value) {
  if (name === "uint64") { requireThat(typeof value === "bigint" && value >= 0n && value <= MAX, "api_uint64"); return; }
  if (name === "bytes") { byteView(value); return; }
  if (name === "bool") { requireThat(typeof value === "boolean", "api_bool"); return; }
  const definition = schema.api_schema.types[name] ?? schema.api_schema.contexts[name];
  requireThat(definition !== undefined, "api_type_unresolved");
  if (!definition.fields) { requireThat(apiEnumValues(schema, definition).includes(value), "api_enum"); return; }
  requireThat(value !== null && typeof value === "object" && !types.isProxy(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)), "api_object");
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    requireThat(typeof key === "string" && has(definition.fields, key), "api_unknown_field");
    requireThat(has(descriptors[key], "value") && descriptors[key].enumerable, "api_data_property");
  }
  for (const [field, descriptor] of Object.entries(definition.fields)) {
    requireThat(has(descriptors, field) || descriptor.optional, "api_missing_field");
    if (has(descriptors, field)) shape(schema, descriptor.type, descriptors[field].value);
  }
}

function readContext(schema, context) {
  shape(schema, "ReadContext", context);
  const ordinary = context.method === "read" || context.method === "read_chunk";
  if (ordinary) {
    requireThat(has(context, "max_bytes") && context.max_bytes > 0n, "read_parameters");
    requireThat(!has(context, "cursor_kind") && !has(context, "target") && !has(context, "delimiter") && !has(context, "target_cause"), "read_parameters");
    requireThat(context.transferred <= context.max_bytes, "read_parameters");
  } else {
    requireThat(has(context, "cursor_kind") && has(context, "target") && !has(context, "max_bytes"), "read_parameters");
    requireThat(context.method === "take_prefix" || !has(context, "target_cause"), "read_parameters");
    requireThat(context.transferred <= context.target, "read_parameters");
    if (context.cursor_kind === "exact") {
      requireThat(!has(context, "delimiter") && ["read_exactly", "take_prefix"].includes(context.method), "read_parameters");
    } else {
      requireThat(["read_until", "read_line", "take_prefix"].includes(context.method), "read_parameters");
      requireThat(has(context, "delimiter"), "read_parameters");
      const delimiter=byteView(context.delimiter);
      requireThat(delimiter.length >= 1 && delimiter.length <= 32 && BigInt(delimiter.length) <= context.target, "read_parameters");
      if (context.method === "read_line") requireThat(delimiter.length === 1 && delimiter[0] === 10, "read_parameters");
    }
    if (context.target_cause === "delimiter_not_found") requireThat(context.cursor_kind === "until" && context.transferred === context.target, "read_parameters");
    if (context.target_cause === "unexpected_eof") requireThat(context.stream_status === "eof" && context.transferred < context.target, "read_parameters");
  }
  requireThat(context.start_offset <= MAX - context.transferred, "read_offset_overflow");
  return ordinary;
}

function readGoal(value, context) {
  const {data, cause, stream_status: status} = value;
  let match = false;
  if (context.cursor_kind === "until") {
    const source=byteView(data), delimiter=byteView(context.delimiter);
    const index = source.indexOf(delimiter);
    if (index >= 0) {
      requireThat(index + delimiter.length === source.length, "read_delimiter_suffix");
      match = true;
    }
  }
  const completed = context.cursor_kind === "exact" ? context.transferred === context.target : match;
  if (!completed && context.cursor_kind === "until" && context.transferred === context.target) requireThat(cause === "delimiter_not_found", "read_cause");
  if (context.method === "take_prefix") {
    requireThat(cause === context.target_cause, "read_cause");
  } else if (completed) {
    requireThat(cause === undefined, "read_cause");
  } else if (context.transferred === context.target) {
    requireThat(cause === "delimiter_not_found", "read_cause");
  } else if (status === "eof") {
    requireThat(cause === "unexpected_eof", "read_cause");
  } else {
    requireThat(status === "aborted" || status === "error", "read_goal_incomplete");
    requireThat(cause === undefined, "read_cause");
  }
  if (cause !== undefined) {
    requireThat(!completed, "read_cause");
    if (cause === "delimiter_not_found") requireThat(context.cursor_kind === "until" && context.transferred === context.target, "read_cause");
    else requireThat(status === "eof" && context.transferred < context.target, "read_cause");
  }
}

function rules(schema, name, value, context) {
  const definition = schema.api_schema.types[name] ?? schema.api_schema.contexts[name];
  if (!definition?.fields) return;
  // Contexts are private original-owner facts, never public result fields. Shape
  // checking before selecting children rejects accessors and proxies without
  // invoking them. The schema owns every nested context association.
  if (definition.context_type !== undefined) shape(schema, definition.context_type, context);
  for (const [field, descriptor] of Object.entries(definition.fields)) if (has(value, field)) {
    rules(schema, descriptor.type, value[field], descriptor.context_field === undefined ? undefined : context[descriptor.context_field]);
  }
  for (const rule of definition.rules ?? []) {
    if (rule === "registered_error_projection") {
      const entry = schema.error_code_metadata[value.code];
      requireThat(entry && value.scope === entry.scope && value.retry_disposition === entry.retry, "api_error_projection");
    } else if (rule === "read_progress_bounds") {
      requireThat(value.filled <= value.offset && (!has(value, "target") || value.filled <= value.target), "read_progress");
    } else if (rule === "read_result_matrix") {
      const ordinary = readContext(schema, context);
      const {data, progress, wait_status: wait, stream_status: status} = value;
      const dataLength=byteView(data).length;
      requireThat(progress.filled === BigInt(dataLength), "read_filled");
      requireThat(progress.offset === context.start_offset + context.transferred, "read_offset");
      requireThat(status === context.stream_status, "read_terminal_fact");
      requireThat(has(value, "error") === (status === "error"), "read_error_presence");
      requireThat(has(context, "stream_error") === (status === "error"), "read_error_fact");
      if (status === "error") requireThat(value.error.code===context.stream_error.code && value.error.scope===context.stream_error.scope && value.error.retry_disposition===context.stream_error.retry_disposition, "read_error_fact");
      requireThat(ordinary ? !has(progress, "target") : progress.target === context.target, "read_target");
      if (ordinary) requireThat(progress.filled === context.transferred, "read_transfer");
      else if (wait === "ready") requireThat(progress.filled === context.transferred, "read_transfer");
      if (wait === "ready") {
        const emptyGoal = !ordinary && (context.method === "take_prefix" || context.cursor_kind === "exact" && context.target === 0n);
        requireThat(dataLength > 0 || status !== "open" || emptyGoal, "read_empty_ready");
        if (!ordinary) readGoal(value, context);
      } else {
        requireThat(dataLength === 0 && status === "open", "read_wait_matrix");
        requireThat(!has(value, "cause"), "read_cause");
      }
      if (has(value, "cause")) requireThat(!ordinary && wait === "ready", "read_cause");
    } else if (rule === "reader_cursor_snapshot_matrix") {
      requireThat(value.transferred_bytes <= value.target && value.transferred_bytes <= value.offset, "cursor_progress");
      requireThat(has(value, "stream_error") === (value.stream_status === "error"), "cursor_error_presence");
      requireThat(!(value.delivered && value.closed), "cursor_lifecycle");
      requireThat(!value.delivered || value.complete || value.frozen, "cursor_lifecycle");
      if (value.target_cause === "unexpected_eof") requireThat(value.complete && value.stream_status === "eof" && value.transferred_bytes < value.target, "cursor_target_cause");
      if (value.target_cause === "delimiter_not_found") requireThat(value.complete && value.transferred_bytes === value.target && value.target > 0n, "cursor_target_cause");
    } else if (rule === "read_method_failure_matrix") {
      if (has(context, "stream_error")) rules(schema,"TypedError",context.stream_error);
      requireThat(value.reason === context.reason && has(value, "cursor") === context.cursor_exists, "read_failure_owner");
      if (!context.cursor_exists) {
        requireThat(value.reason === "invalid_argument" || value.reason === "read_in_progress" || value.reason === "owner_unavailable", "read_failure_creation");
      } else {
        requireThat(context.start_offset <= MAX-context.transferred_bytes, "read_offset_overflow");
        requireThat(value.cursor.offset === context.start_offset+context.transferred_bytes, "read_failure_offset");
        for (const field of ["transferred_bytes","target","stream_status","target_cause","complete","frozen","delivered","closed"]) requireThat(value.cursor[field] === context[field], "read_failure_owner");
        const a=value.cursor.stream_error, b=context.stream_error;
        requireThat(a === undefined ? b === undefined : b !== undefined && a.code===b.code && a.scope===b.scope && a.retry_disposition===b.retry_disposition, "read_failure_owner");
        if (value.reason === "already_delivered") requireThat(context.delivered, "read_failure_gate");
        if (value.reason === "closed") requireThat(context.closed && !context.delivered, "read_failure_gate");
        if (value.reason === "prefix_frozen") requireThat(context.frozen && !context.closed && !context.delivered, "read_failure_gate");
        if (value.reason === "read_in_progress") requireThat(context.waiting && !context.delivered, "read_failure_gate");
        if (["time_pending","time_unavailable"].includes(value.reason)) requireThat(!context.closed && !context.delivered, "read_failure_gate");
        if (value.reason === "authorization_denied") requireThat(context.closed && !context.delivered, "read_failure_gate");
      }
    } else if (rule === "cleanup_result_matrix") {
      const complete = value.core_cleanup === "complete" && value.pending_callbacks === 0n;
      requireThat((value.status === "complete") === complete, "cleanup_progress");
    } else if (rule === "write_progress_matrix") {
      requireThat(value.accepted_bytes <= value.requested_bytes, "write_progress_bounds");
      requireThat((value.phase === "terminal") === (value.terminal_reason !== "none"), "write_terminal_reason");
      if (value.phase === "prepared" || value.terminal_reason === "queue_full") requireThat(value.accepted_bytes === 0n, "write_preacceptance");
      if (value.terminal_reason === "complete") requireThat(value.accepted_bytes === value.requested_bytes, "write_incomplete_acceptance");
      requireThat(value.phase === "terminal" || value.cleanup_status.status !== "complete", "write_live_cleanup");
      // No relationship to record tickets, peer ACK or send_drained is inferred.
    } else if (rule === "transfer_progress_matrix") {
      shape(schema, "TransferContext", context);
      requireThat(context.chunk_bytes > 0n, "transfer_chunk");
      requireThat(value.destination_accepted_bytes <= value.source_read_bytes, "transfer_progress_bounds");
      const remainder = value.source_read_bytes - value.destination_accepted_bytes;
      requireThat(remainder <= context.chunk_bytes, "transfer_chunk");
      const returned = BigInt(byteView(value.unaccepted_tail).length);
      if (context.tail_retained_by_source) {
        requireThat(returned === 0n && context.retained_tail_bytes === remainder, "transfer_tail_ownership");
      } else {
        requireThat(context.retained_tail_bytes === 0n && returned === remainder, "transfer_tail_ownership");
      }
    } else if (rule === "duplex_send_matrix") {
      requireThat(value.endpoint_kind === context.endpoint_kind, "duplex_endpoint_binding");
      const flowersec = value.endpoint_kind === "flowersec_stream";
      requireThat(has(value, "send_drained") === flowersec && has(value, "native_send_finished") !== flowersec, "duplex_send_variant");
      const finished = flowersec ? value.send_drained : value.native_send_finished;
      requireThat(finished === context.finished, "duplex_send_fact");
    } else if (rule === "duplex_direction_matrix") {
      requireThat(value.source_status === context.source_status, "duplex_source_fact");
      requireThat(value.progress.source_read_bytes === context.source_read_bytes && value.progress.destination_accepted_bytes === context.destination_accepted_bytes, "duplex_progress_fact");
    } else if (rule === "duplex_result_matrix") {
      requireThat([value.a_to_b, value.b_to_a].some(direction => direction.send_result.endpoint_kind === "flowersec_stream"), "duplex_flowersec_endpoint");
      requireThat(value.outcome === context.outcome, "duplex_outcome_fact");
      if (value.outcome === "normal") {
        requireThat(!has(value, "first_error"), "duplex_normal_error");
        for (const direction of [value.a_to_b, value.b_to_a]) {
          const send = direction.send_result;
          const finished = send.endpoint_kind === "flowersec_stream" ? send.send_drained : send.native_send_finished;
          requireThat(direction.source_status === "eof" && finished && direction.progress.source_read_bytes === direction.progress.destination_accepted_bytes, "duplex_normal_incomplete");
        }
      }
      // Transfer outcome and actual cleanup are independent. Normal transfer
      // does not itself establish overall success, peer business completion,
      // ownership transfer or a right to replay a partial source prefix.
    } else if (rule === "publication_result_matrix") {
      const failed = has(context, "failure_cause");
      if (!context.applicable) {
        requireThat(!context.original_selected && !context.provider_handoff_complete && !failed, "publication_not_applicable");
      }
      requireThat(!context.provider_handoff_complete || context.original_selected && !failed, "publication_handoff_fact");
      const expected = !context.applicable ? "not_applicable" : failed ? "unknown" : context.provider_handoff_complete ? "flushed" : "pending";
      requireThat(value.state === expected, "publication_state_fact");
      requireThat(has(value, "cause") === failed && (!failed || value.cause === context.failure_cause), "publication_cause_fact");
    } else fail("api_rule_unresolved");
  }
}

export function validateApiResult(schema, name, value, context) {
  requireThat(has(schema.api_schema.types, name), "api_type_unresolved");
  shape(schema, name, value);
  rules(schema, name, value, context);
  // Validation deliberately returns no payload or transferable owner.
}

export function apiFixture(value) {
  if (Array.isArray(value)) return value.map(apiFixture);
  if (!value || typeof value !== "object") return value;
  if (has(value, "$bigint")) {
    assert.deepEqual(Object.keys(value), ["$bigint"]);
    assert.match(value.$bigint, /^-?(?:0|[1-9][0-9]*)$/u);
    return BigInt(value.$bigint);
  }
  if (has(value, "$bytes")) {
    assert.deepEqual(Object.keys(value), ["$bytes"]);
    assert.match(value.$bytes, /^(?:[0-9a-f]{2})*$/u);
    return new Uint8Array(Buffer.from(value.$bytes, "hex"));
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, apiFixture(item)]));
}

export function buildApiCorpus(schema) {
  verifyApiSchema(schema);
  const vectors = structuredClone(schema.api_vector_plan);
  assert.ok(Array.isArray(vectors) && vectors.length > 0);
  const ids = new Set();
  for (const vector of vectors) {
    assert.ok(Object.keys(vector).every(key => ["id", "type", "input", "context", "accept", "expected_error"].includes(key)), "unknown API vector attribute");
    if (has(vector, "accept")) assert.equal(vector.accept, true, "positive API oracle must be true");
    if (has(vector, "expected_error")) assert.match(vector.expected_error, /^[a-z][a-z0-9_]*$/u);
    assert.ok(!ids.has(vector.id)); ids.add(vector.id);
    assert.match(vector.id, /^[a-z][a-z0-9_]*$/u);
    assert.notEqual(vector.accept === true, has(vector, "expected_error"), "explicit API oracle required");
    let error;
    try { validateApiResult(schema, vector.type, apiFixture(vector.input), apiFixture(vector.context)); }
    catch (caught) { error = caught; }
    if (vector.accept) { if (error) throw error; }
    else assert.ok(error instanceof ApiResultError && error.code === vector.expected_error, `${vector.id}: expected ${vector.expected_error}, got ${error?.code ?? "accepted"}`);
  }
  return {schema_revision:schema.schema_revision, design_sha256:schema.design_sha256, representation:"native_reference_json_tags_not_wire_encoding", coverage:"draft_native_io_results_only", vectors};
}
