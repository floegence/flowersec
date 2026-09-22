import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { decodeMap, encodeCBOR } from "./transport-v4-codec.mjs";
import { ApiResultError, apiFixture, buildApiCorpus, validateApiResult } from "./transport-v4-api-results.mjs";
import { PublicationStateReference } from "./transport-v4-publication-state.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const corpus = JSON.parse(fs.readFileSync(new URL("../testdata/transport_v4/corpus.json", import.meta.url)));
const MAX = 0xffffffffffffffffn;
function contract(enabled = true, timeout = 30n) {
  const map = decodeMap(schema, "ServiceContract", Buffer.from(corpus.vectors.find(v => v.id === "service_unary_transient").hex, "hex"));
  map.set(21n, enabled); if (enabled) map.set(22n, timeout);
  return encodeCBOR(map);
}
const model = (options = {}) => new PublicationStateReference(schema, { contract: contract(), createdAt: 100n, hardDeadline: 1000n, providerFrontier: 10n, ...options });
const causes = schema.api_schema.types.ResponsePublicationCause.enum;

// v4.publication.result_matrix
test("publication states and finite causes match original publisher facts", () => {
  let count = 0;
  for (const applicable of [false, true]) for (const selected of [false, true]) for (const handoff of [false, true]) for (const cause of [undefined, ...causes]) {
    const context = { applicable, original_selected: selected, provider_handoff_complete: handoff, ...(cause === undefined ? {} : { failure_cause: cause }) };
    const expected = !applicable ? "not_applicable" : cause ? "unknown" : handoff ? "flushed" : "pending";
    const result = { state: expected, ...(cause === undefined ? {} : { cause }) };
    const legal = (applicable || !selected && !handoff && cause === undefined) && (!handoff || selected && cause === undefined);
    if (legal) validateApiResult(schema, "ResponsePublicationStatus", result, context);
    else assert.throws(() => validateApiResult(schema, "ResponsePublicationStatus", result, context), ApiResultError);
    count++;
  }
  assert.equal(count, 48);
  for (const vector of schema.api_vector_plan.filter(v => v.id.startsWith("api_publication_"))) {
    const check = () => validateApiResult(schema, vector.type, apiFixture(vector.input), apiFixture(vector.context));
    if (vector.accept) check(); else assert.throws(check, error => error instanceof ApiResultError && error.code === vector.expected_error);
  }
  assert.equal(buildApiCorpus(schema).vectors.filter(v => v.id.startsWith("api_publication_")).length, 27);
});

// v4.publication.actual_handoff
test("internal response acceptance and prefix handoff cannot flush the original response", () => {
  const state = model(); assert.deepEqual(state.state(), { state: "pending" });
  state.observeTime(200n); state.bindOriginalResponse(30n);
  assert.equal(state.snapshot().publication_deadline, 230n);
  state.internalAcceptThrough(30n); assert.equal(state.state().state, "pending");
  state.providerHandoffThrough(29n); assert.equal(state.state().state, "pending");
  assert.deepEqual(state.providerHandoffThrough(30n), { state: "flushed" });
  for (const cause of causes) assert.deepEqual(state.fail(cause), { state: "flushed" });
  assert.deepEqual(state.observeTime(1000n), { state: "flushed" });
  assert.equal(state.wait({ canceled: true }).wait_status, "ready");
  assert.throws(() => state.bindOriginalResponse(40n), /publication_selection_closed/);
});

// v4.publication.first_terminal
test("replacement, ABORT and first failure seal unknown despite later handoff", () => {
  for (const first of causes) for (const later of causes) {
    const state = model(); state.bindOriginalResponse(20n); state.internalAcceptThrough(20n);
    assert.deepEqual(state.fail(first), { state: "unknown", cause: first });
    state.providerHandoffThrough(20n); state.fail(later); state.observeTime(1000n);
    assert.deepEqual(state.state(), { state: "unknown", cause: first });
    assert.equal(state.wait().wait_status, "ready");
  }
  const replaced = model(); replaced.fail("response_superseded");
  assert.throws(() => replaced.bindOriginalResponse(20n), /publication_selection_closed/);
  assert.equal(replaced.state().state, "unknown");
});

// v4.publication.deadline
test("publication timer starts once at response binding and never extends its hard limit", () => {
  const state = model(); state.observeTime(500n); assert.equal(state.state().state, "pending");
  state.bindOriginalResponse(20n); assert.equal(state.snapshot().publication_deadline, 530n);
  state.internalAcceptThrough(20n); state.observeTime(529n); assert.equal(state.state().state, "pending");
  for (let i = 0; i < 3; i++) assert.equal(state.wait({ canceled: true }).wait_status, "wait_canceled");
  assert.equal(state.snapshot().publication_deadline, 530n);
  assert.deepEqual(state.observeTime(530n), { state: "unknown", cause: "deadline" });
  assert.equal(state.providerHandoffThrough(20n).state, "unknown");
  const hard = model({ hardDeadline: 115n }); hard.bindOriginalResponse(20n);
  assert.equal(hard.snapshot().publication_deadline, 115n); hard.observeTime(115n);
  assert.deepEqual(hard.state(), { state: "unknown", cause: "deadline" });
  const before = model(); before.observeTime(1000n);
  assert.throws(() => before.bindOriginalResponse(20n), /publication_selection_closed/);
  const wide = model({ createdAt: MAX - 3n, hardDeadline: MAX, providerFrontier: MAX - 2n });
  wide.bindOriginalResponse(MAX); assert.equal(wide.snapshot().publication_deadline, MAX);
  wide.internalAcceptThrough(MAX); wide.providerHandoffThrough(MAX); assert.equal(wide.state().state, "flushed");
});

test("all provider prefixes obey the original response frontier without wrap or premature completion", () => {
  for (let accepted = 10n; accepted <= 20n; accepted++) for (let handed = 10n; handed <= accepted; handed++) {
    const state = model(); state.bindOriginalResponse(20n); state.internalAcceptThrough(accepted); state.providerHandoffThrough(handed);
    assert.equal(state.state().state, handed === 20n ? "flushed" : "pending");
  }
  const state = model(); state.bindOriginalResponse(20n);
  for (const value of [9n, 21n, -1n, MAX + 1n, 11]) assert.throws(() => state.internalAcceptThrough(value), /publication_acceptance_frontier/);
  assert.throws(() => state.providerHandoffThrough(11n), /publication_provider_frontier/);
  state.internalAcceptThrough(20n); state.providerHandoffThrough(15n);
  assert.throws(() => state.providerHandoffThrough(14n), /publication_provider_frontier/);
  assert.throws(() => state.observeTime(99n), /publication_time_continuity/);
  assert.throws(() => state.fail("restart_failed"), /publication_failure_cause/);
  assert.equal(state.state().state, "pending");
});

// v4.publication.observer
test("non-restart methods have no publication owner and status waits preserve the same state", () => {
  const state = model({ contract: contract(false) });
  assert.deepEqual(state.state(), { state: "not_applicable" });
  for (const cause of causes) assert.deepEqual(state.fail(cause), { state: "not_applicable" });
  assert.equal(state.observeTime(1000n).state, "not_applicable");
  assert.equal(state.wait().wait_status, "ready");
  assert.throws(() => state.bindOriginalResponse(20n), /publication_selection_closed/);
  const pending = model(), before = pending.snapshot();
  for (let i = 0; i < 16; i++) {
    assert.equal(pending.wait({ canceled: true }).wait_status, "wait_canceled");
    assert.deepEqual(pending.snapshot(), before);
  }
  assert.ok(Object.isFrozen(pending.state())); assert.deepEqual(Object.keys(pending.state()), ["state"]);
});

test("original contract and context cannot be replaced by mutable caller state or accessors", () => {
  const bytes = contract(), state = model({ contract: bytes }); bytes.fill(0);
  state.bindOriginalResponse(20n); state.internalAcceptThrough(20n); state.providerHandoffThrough(20n);
  assert.equal(state.state().state, "flushed");
  let calls = 0;
  const context = { applicable: true, original_selected: false, get provider_handoff_complete() { calls++; return true; } };
  assert.throws(() => validateApiResult(schema, "ResponsePublicationStatus", { state: "pending" }, context), ApiResultError);
  assert.equal(calls, 0);
});
