import assert from "node:assert/strict";
import test from "node:test";
import { buildArtifacts } from "./generate-transport-v4-vectors.mjs";
import { rekeyCreditReference, verifyRekeyCreditRegistry } from "./transport-v4-rekey-credit.mjs";
import { VectorError } from "./transport-v4-codec.mjs";

const { schema, files, manifest } = buildArtifacts();
const profiles = Object.keys(schema.crypto_usage_registry.profiles), profile = profiles[0];
const fail = (fn, code) => assert.throws(fn, error => error instanceof VectorError && error.code === code);
const service = { burst_rounds: "2", refill_period_ms: "30000", request_start_budget_ms: "5000",
  issued_at_ms: "0", session_not_after_ms: "86400000", rate_numerator: "1", rate_denominator: "10000", quantization_ms: "2" };
const credit = { burst_rounds: "2", refill_period_ms: "30000", base_credit: "30000", delta_ms: "0",
  rate_numerator: "0", rate_denominator: "1", quantization_ms: "0" };
const run = (op, input) => rekeyCreditReference(schema, profile, op, input);

test("v4.rekey_credit.vectors: complete generated service and credit corpus", () => {
  verifyRekeyCreditRegistry(schema);
  const corpus = JSON.parse(files.get("testdata/transport_v4/rekey_credit.json"));
  assert.equal(corpus.vectors.length, 48); assert.equal(manifest.rekey_credit_vectors.length, 48);
  for (const vector of corpus.vectors) {
    const invoke = () => rekeyCreditReference(schema, vector.profile, vector.operation, vector.input);
    if (vector.expected_error) fail(invoke, vector.expected_error); else assert.deepEqual(invoke(), vector.expected);
  }
  const altered = structuredClone(schema); altered.rekey_credit_registry.additional_authorization_tolerance_ms = "1";
  assert.throws(() => verifyRekeyCreditRegistry(altered));
  for (const path of ["flowersec-go/internal/protocolv4/registry_generated.go", "flowersec-rust/src/protocol_v4_registry_generated.rs",
    "flowersec-swift/Sources/Flowersec/TransportV4Registry.generated.swift", "flowersec-ts/src/generated/transportV4Registry.ts"]) {
    assert.match(files.get(path), /rekey_full_session_service|floor\(\(B\*R\+B\*/u);
  }
});

test("v4.rekey_credit.service: exact rational upper count includes error and initial epoch", () => {
  // Small-integer oracle uses unbounded exact arithmetic independently of the
  // implementation's admission-before-multiplication sequence.
  for (let d = 1n; d <= 6n; d++) for (let n = 0n; n < d; n++) for (let q = 0n; q <= 3n; q++) {
    for (const B of [1n, 2n, 7n]) for (const R of [1n, 18n, 30n, 100n]) for (const T of [1n, 20n, 65535n]) {
      const e = (2n * q * d + d - n - 1n) / (d - n) + 1n;
      const denominator = (R - B * e) * (d - n);
      const numerator = B * R * (d - n) + B * (d + n) * T;
      const N = denominator > 0n ? numerator / denominator : 0n;
      const input = { ...service, burst_rounds: String(B), refill_period_ms: String(R), rate_numerator: String(n),
        rate_denominator: String(d), quantization_ms: String(q), session_not_after_ms: String(T) };
      if (denominator <= 0n || N === 0n || N >= 65536n) fail(() => run("service", input), "configuration_capacity");
      else {
        const result = run("service", input);
        assert.equal(result.max_rounds, String(N)); assert.equal(result.required_epochs, String(N + 1n));
        assert.equal(result.error_allowance_ms, String(e));
        assert.ok(N * denominator <= numerator && (N + 1n) * denominator > numerator);
      }
    }
  }
});

test("v4.rekey_credit.retention: peeks retain original base and ACK carries partial post-charge", () => {
  const source = { ...credit, base_credit: "10000", delta_ms: "20000" };
  const before = structuredClone(source), first = run("client_credit", source);
  assert.equal(first.available_credit, "50000"); assert.equal(first.post_charge_credit, "20000");
  for (let i = 0; i < 100; i++) assert.deepEqual(run("client_credit", source), first);
  assert.deepEqual(source, before); assert.ok(Object.isFrozen(first));
  // A completed ACK carries exactly this balance into a new idle interval.
  const afterAck = { ...credit, base_credit: first.post_charge_credit, delta_ms: "4999" };
  assert.equal(run("client_credit", afterAck).post_charge_credit, null);
  afterAck.delta_ms = "5000"; assert.equal(run("client_credit", afterAck).post_charge_credit, "0");
  // Repeated 20-second idle intervals remain affordable, retaining every unit.
  let base = run("initial_credit", { burst_rounds: "2", refill_period_ms: "30000" }).post_charge_credit;
  for (let i = 0; i < 200; i++) {
    const next = run("client_credit", { ...credit, base_credit: base, delta_ms: "20000" });
    assert.notEqual(next.post_charge_credit, null); base = next.post_charge_credit;
  }
});

test("v4.rekey_credit.causality: wider server idle and retained balance never reject affordable client credit", () => {
  // rho=1/2, eta=2. These observed increments are at opposite extrema of
  // qualified clocks; server's real idle includes client's real idle.
  for (let tau = 0; tau <= 80; tau += 2) for (let base = 0; base <= 60; base += 5) {
    const client = run("client_credit", { ...credit, refill_period_ms: "30", base_credit: String(base),
      delta_ms: String(tau * 3 / 2 + 2), rate_numerator: "1", rate_denominator: "2", quantization_ms: "2" });
    const server = run("server_credit", { ...credit, refill_period_ms: "30", base_credit: String(Math.min(60, base + 3)),
      delta_ms: String(Math.max(0, (tau + 2) / 2 - 2)), rate_numerator: "1", rate_denominator: "2", quantization_ms: "2" });
    assert.ok(BigInt(server.available_credit) >= BigInt(client.available_credit));
    if (client.post_charge_credit !== null) {
      assert.notEqual(server.post_charge_credit, null);
      assert.ok(BigInt(server.post_charge_credit) >= BigInt(client.post_charge_credit));
    }
  }
});

test("v4.rekey_credit.service_bound: retained credit traces fit the full response envelope", () => {
  // Worst per-idle server upper a*tau+e, including its artificial surplus at
  // zero idle. Charge as rapidly as possible; keep partial credit across ACKs.
  const B = 2n, R = 30n, e = 9n, a = 3n, C = B * R;
  let base = C - R, rounds = 1n, elapsed = 0n;
  for (let i = 0; i < 400; i++) {
    const tau = BigInt(i % 7), refill = B * (a * tau + e);
    const available = base + refill > C ? C : base + refill;
    if (available < R) continue;
    base = available - R; rounds++; elapsed += tau;
    if (elapsed > 0n) {
      const envelope = run("service", { ...service, refill_period_ms: "30", rate_numerator: "1",
        rate_denominator: "2", quantization_ms: "2", session_not_after_ms: String(elapsed) });
      assert.ok(rounds <= BigInt(envelope.max_rounds));
    }
  }
});

test("v4.rekey_credit.inputs: strict inert strings, closed fields and no mutable output aliases", () => {
  let calls = 0; const trap = () => { calls++; throw new Error("caller hook"); };
  fail(() => rekeyCreditReference(schema, { toString: trap }, "service", service), "rekey_credit_profile");
  fail(() => run({ toString: trap }, service), "rekey_credit_operation");
  fail(() => run("service", new Proxy(service, { getPrototypeOf: trap })), "rekey_credit_input");
  fail(() => run("service", Object.defineProperty({ ...service }, "burst_rounds", { get: trap })), "rekey_credit_data");
  fail(() => run("service", { ...service, root_age_ms: "1" }), "rekey_credit_fields");
  for (const value of [0, 0n, true, null, "", "00", "-1", "+1", "1.0", "1\n", "١", "18446744073709551616", { toString: trap }]) {
    fail(() => run("service", { ...service, issued_at_ms: value }), "rekey_credit_integer");
  }
  assert.equal(calls, 0);
  const result = run("service", service); assert.ok(Object.isFrozen(result));
  // Shorter root/policy deadlines cannot shrink the signed full-service bound.
  fail(() => run("service", { ...service, root_not_after_ms: "1" }), "rekey_credit_fields");
});
