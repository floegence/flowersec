import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { buildResourceCostCorpus, knownResourceCosts, verifyResourceFormulaRegistry } from "./transport-v4-resource-costs.mjs";

const schema = JSON.parse(fs.readFileSync(new URL("../stability/transport_v4_schema.json", import.meta.url)));
const solve = input => knownResourceCosts(schema, input);
const base = () => ({ max_frame_bytes: 131072, small_auth_slots: 2, application_profile: "services", rpc_max_general_outstanding: 1024 });

test("known resource corpus pins ordinary, large-frame, constrained and invalid configurations", () => {
  const corpus = buildResourceCostCorpus(schema);
  assert.equal(corpus.vectors.length, 18);
  for (const vector of corpus.vectors) {
    if (vector.expected_error) assert.throws(() => solve(vector.input), { message: vector.expected_error });
    else assert.deepEqual(solve(vector.input), vector.expected);
  }
  assert.deepEqual(solve(base()), {
    codec_body_bytes: { full_slots: "524288", small_slots: "524288", total: "1048576" },
    permanent_bitmap_bytes: "524292",
    application_counts: { internal_active: 10, management_active: 0, reply_slots: 1026, fragment_associations: 2048 },
    application_bytes: { reply_slots: "1050624", fragment_associations: "262144", query_reserve: "524288",
      rpc_error_output: "16384", internal_receive: "163840", internal_send: "163840", total: "2181120" },
  });
});

test("codec costs equal independently enumerated contiguous input and output buffers", () => {
  for (const frame of [1, 255, 65536, 131071, 131072, 131073, 1048576]) {
    for (let small = 0; small <= 32; small++) {
      const buffers = [frame, frame, frame, frame];
      for (let slot = 0; slot < small; slot++) buffers.push(Math.min(frame, 131072), Math.min(frame, 131072));
      const actual = solve({ max_frame_bytes: frame, small_auth_slots: small, application_profile: "transport" });
      assert.equal(BigInt(actual.codec_body_bytes.total), buffers.reduce((a, b) => a + BigInt(b), 0n));
      assert.equal(actual.application_bytes.total, "0");
      assert.deepEqual(actual.application_counts, { internal_active: 0, management_active: 0, reply_slots: 0, fragment_associations: 0 });
    }
  }
});

test("all signed K values preserve fixed queries, channel promises and separate management cost", () => {
  for (let k = 1; k <= 1024; k++) {
    const services = solve({ ...base(), rpc_max_general_outstanding: k });
    const execution = solve({ ...base(), application_profile: "execution", rpc_max_general_outstanding: k });
    assert.equal(BigInt(services.application_bytes.total), BigInt(k) * 1280n + 870400n);
    assert.equal(BigInt(execution.application_bytes.total), BigInt(services.application_bytes.total) + 32768n);
    assert.equal(services.application_counts.reply_slots, k + 2);
    assert.equal(execution.application_counts.internal_active, 10);
    assert.equal(execution.application_counts.management_active, 1);
    assert.equal(services.application_bytes.query_reserve, "524288");
    assert.equal(services.application_bytes.rpc_error_output, "16384");
  }
});

test("bitmap accounts for both complete encoding domains including unavailable server tail", () => {
  const result = solve(base());
  const clientBits = 1048576 + 1048576 + 16;
  assert.equal(BigInt(result.permanent_bitmap_bytes) * 8n, BigInt(clientBits * 2));
  assert.notEqual(BigInt(result.permanent_bitmap_bytes) * 8n, BigInt(clientBits + 2097152));
});

test("partial costs never claim ready_min or a complete reservation", () => {
  const input = base(), before = structuredClone(input), result = solve(input);
  assert.deepEqual(Object.keys(result), ["codec_body_bytes", "permanent_bitmap_bytes", "application_counts", "application_bytes"]);
  assert.deepEqual(input, before);
  result.application_bytes.total = "0";
  assert.equal(solve(input).application_bytes.total, "2181120");
  // This legal arithmetic parameter is deliberately not a qualified provider
  // configuration; computing its costs cannot admit it under any Session cap.
  assert.ok(BigInt(solve({ ...input, small_auth_slots: 4294967295 }).codec_body_bytes.total) > 64n * 1048576n);
});

test("cost inputs reject coercion, missing fields and caller hooks before execution", () => {
  for (const name of ["max_frame_bytes", "small_auth_slots", "rpc_max_general_outstanding"]) {
    for (const value of ["1", 1n, 0.5, NaN, Infinity, null, undefined, {}, [], true, Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => solve({ ...base(), [name]: value }));
    }
  }
  for (const name of ["max_frame_bytes", "small_auth_slots", "application_profile"]) {
    const input = base(); delete input[name];
    assert.throws(() => solve(input), /resource_missing_field/u);
  }
  for (const profile of [null, 0, {}, "__proto__", "constructor"]) {
    assert.throws(() => solve({ ...base(), application_profile: profile }), /resource_application_profile/u);
  }
  let calls = 0;
  const fail = () => { calls++; throw new Error("caller hook"); };
  const accessor = base(); Object.defineProperty(accessor, "max_frame_bytes", { get: fail, enumerable: true });
  assert.throws(() => solve(accessor), /resource_data_property/u);
  assert.throws(() => solve(new Proxy(base(), { get: fail, ownKeys: fail, getPrototypeOf: fail })), /resource_object/u);
  const inherited = Object.create(new Proxy({}, { get: fail, ownKeys: fail, getPrototypeOf: fail }));
  assert.throws(() => solve(inherited), /resource_object/u);
  assert.throws(() => solve({ ...base(), small_auth_slots: { valueOf: fail } }), /resource_auth_slots/u);
  assert.throws(() => solve({ ...base(), unexpected: 1 }), /resource_field/u);
  assert.equal(calls, 0);
});

test("resource formula allocation drift fails the schema gate", () => {
  for (const path of [["codec", "buffers_per_slot"], ["bitmap", "roles"], ["application", "query_slots"]]) {
    const altered = structuredClone(schema); altered.resource_formula_registry[path[0]][path[1]]++;
    assert.throws(() => verifyResourceFormulaRegistry(altered));
  }
  const altered = structuredClone(schema);
  altered.frame_maps.SessionContract.fields[5].enum.other = 3;
  assert.throws(() => verifyResourceFormulaRegistry(altered));
});
