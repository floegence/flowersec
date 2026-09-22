import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ApiResultError, apiFixture, buildApiCorpus, validateApiResult, verifyApiSchema } from "./transport-v4-api-results.mjs";
import { generateApiTypes } from "./transport-v4-api-types.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const base = () => {
  const vector = schema.api_vector_plan.find(entry => entry.id === "api_duplex_normal_native");
  return { result: apiFixture(vector.input), context: apiFixture(vector.context) };
};
const check = ({ result, context }) => validateApiResult(schema, "DuplexResult", result, context);
const invalid = (candidate, code) => assert.throws(() => check(candidate), error => error instanceof ApiResultError && error.code === code);
const endpoint = (candidate, key, kind) => {
  candidate.result[key].send_result = { endpoint_kind: kind, ...(kind === "flowersec_stream" ? { send_drained: true } : { native_send_finished: true }) };
  candidate.context[key].send_result.endpoint_kind = kind;
};
const terminal = (candidate, key, source, finished) => {
  const target = candidate.result[key].send_result;
  target[target.endpoint_kind === "flowersec_stream" ? "send_drained" : "native_send_finished"] = finished;
  candidate.context[key].send_result.finished = finished;
  candidate.result[key].source_status = candidate.context[key].source_status = source;
};

// v4.duplex_results.terminal_matrix
test("normal requires two EOFs and actual target completion independently of cleanup", () => {
  let cases = 0;
  for (const kinds of [["flowersec_stream", "flowersec_stream"], ["flowersec_stream", "native_duplex"], ["native_duplex", "flowersec_stream"]]) {
    for (const left of ["open", "eof", "aborted", "error"]) for (const right of ["open", "eof", "aborted", "error"]) {
      for (const leftFinished of [false, true]) for (const rightFinished of [false, true]) {
        for (const outcome of ["normal", "failed", "aborted"]) for (const cleanup of ["pending", "cleanup_incomplete", "complete"]) {
          const candidate = base(); endpoint(candidate, "a_to_b", kinds[0]); endpoint(candidate, "b_to_a", kinds[1]);
          terminal(candidate, "a_to_b", left, leftFinished); terminal(candidate, "b_to_a", right, rightFinished);
          candidate.result.outcome = candidate.context.outcome = outcome;
          candidate.result.cleanup_status = { status: cleanup, core_cleanup: cleanup === "complete" ? "complete" : "pending", pending_callbacks: 0n };
          if (outcome === "normal" && !(left === "eof" && right === "eof" && leftFinished && rightFinished)) invalid(candidate, "duplex_normal_incomplete");
          else check(candidate);
          cases++;
        }
      }
    }
  }
  assert.equal(cases, 1728);
  for (const cleanup of ["pending", "cleanup_incomplete"]) {
    const candidate = base(); candidate.result.cleanup_status = { status: cleanup, core_cleanup: "complete", pending_callbacks: 1n };
    check(candidate); assert.equal(candidate.result.outcome, "normal"); assert.notEqual(candidate.result.cleanup_status.status, "complete");
  }
});

// v4.duplex_results.native_guarantees
test("native half-close cannot claim Flowersec authentication or change the original endpoint kind", () => {
  const mixed = base(); mixed.result.a_to_b.send_result.send_drained = true; invalid(mixed, "duplex_send_variant");
  const absent = base(); delete absent.result.a_to_b.send_result.native_send_finished; invalid(absent, "duplex_send_variant");
  const substitution = base(); substitution.result.a_to_b.send_result = { endpoint_kind: "flowersec_stream", send_drained: true }; invalid(substitution, "duplex_endpoint_binding");
  const native = base(); endpoint(native, "b_to_a", "native_duplex"); invalid(native, "duplex_flowersec_endpoint");
  const falseFact = base(); falseFact.result.a_to_b.send_result.native_send_finished = false; invalid(falseFact, "duplex_send_fact");
  const source = base(); source.result.b_to_a.source_status = "eof"; source.context.b_to_a.source_status = "open"; invalid(source, "duplex_source_fact");
});

// v4.duplex_results.partial_progress
test("partial counts and exactly one owned tail survive failed or aborted operations", () => {
  const max = 0xffffffffffffffffn;
  for (const outcome of ["failed", "aborted"]) for (const retained of [false, true]) for (const read of [1n, 8n, max]) {
    const candidate = base(), direction = candidate.result.a_to_b, context = candidate.context.a_to_b;
    candidate.result.outcome = candidate.context.outcome = outcome;
    direction.progress = { source_read_bytes: read, destination_accepted_bytes: read - 1n, unaccepted_tail: retained ? new Uint8Array() : new Uint8Array([123]) };
    Object.assign(context, { source_read_bytes: read, destination_accepted_bytes: read - 1n });
    Object.assign(context.transfer, { tail_retained_by_source: retained, retained_tail_bytes: retained ? 1n : 0n });
    terminal(candidate, "a_to_b", outcome === "failed" ? "error" : "aborted", false);
    const before = structuredClone(candidate); check(candidate); assert.deepEqual(candidate, before);
    const lost = structuredClone(candidate); lost.result.a_to_b.progress.unaccepted_tail = new Uint8Array(); lost.context.a_to_b.transfer.retained_tail_bytes = 0n;
    invalid(lost, "transfer_tail_ownership");
    const moved = structuredClone(candidate); moved.context.a_to_b.destination_accepted_bytes = read;
    invalid(moved, "duplex_progress_fact");
  }
  const excess = base(); excess.result.a_to_b.progress.source_read_bytes = excess.context.a_to_b.source_read_bytes = 20n;
  invalid(excess, "transfer_chunk");
  const forged = base(); forged.result.a_to_b.progress.destination_accepted_bytes = forged.context.a_to_b.destination_accepted_bytes = max + 1n;
  invalid(forged, "api_uint64");
});

// v4.duplex_results.private_contexts
test("nested owner contexts cannot be replaced by public flags, accessors or raw identities", () => {
  const candidate = base(); candidate.result.outcome = "aborted"; invalid(candidate, "duplex_outcome_fact");
  const missing = base(); delete missing.context.a_to_b.transfer; invalid(missing, "api_missing_field");
  for (const path of [[], ["a_to_b"], ["a_to_b", "send_result"], ["b_to_a", "transfer"]]) {
    const candidate = base(); let target = candidate.context;
    for (const key of path) target = target[key];
    const key = Object.keys(target)[0]; let calls = 0;
    Object.defineProperty(target, key, { enumerable: true, get() { calls++; throw Error("getter must not execute"); } });
    invalid(candidate, "api_data_property"); assert.equal(calls, 0);
  }
  const proxy = base(); let calls = 0;
  proxy.context.a_to_b = new Proxy(proxy.context.a_to_b, { getPrototypeOf() { calls++; throw Error("proxy must not execute"); } });
  invalid(proxy, "api_object"); assert.equal(calls, 0);
  for (const tail of [new Uint8Array(), Buffer.alloc(0)]) {
    const candidate = base(); let calls = 0;
    const original = Object.getPrototypeOf(tail);
    Object.setPrototypeOf(tail, new Proxy({}, { getPrototypeOf() {
      calls++; Object.setPrototypeOf(tail, original); return original;
    } }));
    candidate.result.a_to_b.progress.unaccepted_tail = tail;
    invalid(candidate, "api_bytes"); assert.equal(calls, 0, "tail prototype trap ran");
  }
  for (const extra of [{ endpoint: { url: "private" } }, { success: true }, { context: base().context }, { cause: new Error("private") }]) {
    const candidate = base(); Object.assign(candidate.result, extra); invalid(candidate, "api_unknown_field");
  }
});

// v4.duplex_results.schema_binding
test("single schema owns contextual field wiring and four generated result projections", () => {
  verifyApiSchema(schema);
  const mutations = [
    s => { s.api_schema.types.DuplexResult.context_type = "DuplexResult"; },
    s => { delete s.api_schema.types.DuplexResult.fields.a_to_b.context_field; },
    s => { s.api_schema.types.DuplexResult.fields.a_to_b.context_field = "outcome"; },
    s => { s.api_schema.types.DuplexDirectionResult.fields.progress.context_field = "send_result"; },
    s => { s.api_schema.types.DuplexResult.fields.outcome.context_field = "outcome"; },
    s => { s.api_schema.types.DuplexResult.fields.a_to_b.type = "DuplexDirectionContext"; },
  ];
  for (const mutate of mutations) { const changed = structuredClone(schema); mutate(changed); assert.throws(() => verifyApiSchema(changed)); }
  const files = generateApiTypes(schema, "ab".repeat(32)); assert.equal(files.size, 4);
  for (const source of files.values()) {
    for (const name of ["DuplexResult", "DuplexDirectionResult", "DuplexSendResult", "DuplexEndpointKind", "DuplexOutcome"]) assert.ok(source.includes(`V4${name}`));
    for (const name of Object.keys(schema.api_schema.contexts)) {
      assert.doesNotMatch(source, new RegExp(`\\bV4${name}\\b`, "u"), `${name} leaked to generated SDK declarations`);
    }
    assert.ok(!source.includes("context_field") && !source.includes("context_type"));
  }
  const corpus = buildApiCorpus(schema).vectors.filter(entry => entry.id.startsWith("api_duplex_"));
  assert.equal(corpus.length, 28); assert.equal(corpus.filter(entry => entry.accept).length, 8);
});
