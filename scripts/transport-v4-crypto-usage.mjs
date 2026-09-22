import assert from "node:assert/strict";
import { types } from "node:util";
import { VectorError } from "./transport-v4-codec.mjs";

const requireThat = (condition, code) => { if (!condition) throw new VectorError(code); };

export function verifyCryptoUsageRegistry(schema) {
  const registry = schema.crypto_usage_registry;
  assert.equal(registry.status, "design_fixed_limits_reference_charges_only");
  assert.equal(registry.source, "3.5.3");
  assert.equal(registry.quantity_max, "18446744073709551615");
  assert.equal(registry.authentication_block_bytes, 16);
  assert.equal(registry.length_blocks, 1);
  assert.deepEqual(registry.charge_fields, ["operation", "aad_bytes", "input_bytes"]);
  assert.deepEqual(registry.operations, ["seal", "open"]);
  assert.deepEqual(Object.keys(registry.profiles).sort(), Object.keys(schema.crypto_profiles).sort());
  // Assert the design's fixed table, not a deployment-selectable budget.
  const count = power => (1n << BigInt(power)).toString();
  const limits = (calls, blocks, bytes) => ({ seal_calls: count(calls), open_attempts: count(calls), authentication_blocks: count(blocks), ciphertext_bytes: count(bytes) });
  for (const [profile, usage] of Object.entries(registry.profiles)) {
    const algorithm = schema.crypto_profiles[profile].dh_algorithm;
    assert.ok(algorithm === 0 || algorithm === 1);
    assert.deepEqual(usage, {
      key: limits(20, algorithm === 0 ? 32 : 31, 36),
      epoch: limits(algorithm === 0 ? 31 : 30, algorithm === 0 ? 42 : 41, algorithm === 0 ? 46 : 45),
      session: limits(algorithm === 0 ? 36 : 35, algorithm === 0 ? 52 : 51, algorithm === 0 ? 56 : 55),
      root_max_age_ms: "86400000", max_epochs: count(16), max_record_key_derivations: count(28),
    });
    assert.equal(schema.crypto_profiles[profile].tag_bytes, 16);
  }
  assert.match(registry.qualification, /no independent aggregate cryptographic proof/u);
}

// Decimal-string charge arithmetic for public fixtures. This performs no AEAD,
// checks no actual frame/profile input limit and reserves no crypto usage. The
// original owner must apply every key/epoch/Session cap atomically before work,
// never refund a precharge, and revalidate root age at actual invocation.
export function recordUsageReference(schema, profile, input) {
  verifyCryptoUsageRegistry(schema);
  const registry = schema.crypto_usage_registry;
  requireThat(typeof profile === "string" && Object.hasOwn(registry.profiles, profile), "crypto_usage_profile");
  requireThat(input !== null && typeof input === "object" && !types.isProxy(input) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(input)), "crypto_usage_input");
  const keys = Reflect.ownKeys(input), names = registry.charge_fields;
  requireThat(keys.length === names.length && keys.every(key => names.includes(key)), "crypto_usage_fields");
  const captured = Object.create(null);
  for (const key of names) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    requireThat(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "crypto_usage_data");
    captured[key] = descriptor.value;
  }
  requireThat(typeof captured.operation === "string" && registry.operations.includes(captured.operation), "crypto_usage_operation");
  const maximum = BigInt(registry.quantity_max);
  const integer = value => {
    requireThat(typeof value === "string" && value.length <= registry.quantity_max.length && /^(?:0|[1-9][0-9]*)$/u.test(value), "crypto_usage_integer");
    const n = BigInt(value); requireThat(n <= maximum, "crypto_usage_integer"); return n;
  };
  const checked = n => { requireThat(n >= 0n && n <= maximum, "crypto_usage_overflow"); return n; };
  const aad = integer(captured.aad_bytes), bytes = integer(captured.input_bytes);
  const tag = BigInt(schema.crypto_profiles[profile].tag_bytes), block = BigInt(registry.authentication_block_bytes);
  const seal = captured.operation === "seal";
  if (!seal) requireThat(bytes >= tag, "crypto_usage_ciphertext");
  const payload = seal ? bytes : bytes - tag, ciphertext = seal ? checked(bytes + tag) : bytes;
  const blocks = n => n / block + (n % block === 0n ? 0n : 1n);
  const authentication = checked(checked(blocks(aad) + blocks(payload)) + BigInt(registry.length_blocks));
  return Object.freeze({ calls: "1", authentication_blocks: authentication.toString(), ciphertext_bytes: ciphertext.toString() });
}

export function buildCryptoUsageCorpus(schema) {
  verifyCryptoUsageRegistry(schema);
  const ids = new Set(), vectors = [];
  for (const profile of Object.keys(schema.crypto_usage_registry.profiles)) {
    for (const spec of schema.crypto_usage_vector_plan) {
      assert.match(spec.id, /^[a-z][a-z0-9_]*$/u);
      const id = `crypto_usage_${schema.crypto_profiles[profile].dh_algorithm}_${spec.id}`;
      assert.ok(!ids.has(id)); ids.add(id);
      const input = structuredClone(spec.input);
      if (spec.expected_error) {
        assert.equal(spec.expected, undefined);
        assert.throws(() => recordUsageReference(schema, profile, input), error => error instanceof VectorError && error.code === spec.expected_error, id);
        vectors.push({ id, profile, input, expected_error: spec.expected_error });
      } else {
        const expected = recordUsageReference(schema, profile, input);
        assert.deepEqual(expected, spec.expected, id);
        vectors.push({ id, profile, input, expected });
      }
    }
  }
  return { status: "draft", schema_revision: schema.schema_revision, design_sha256: schema.design_sha256,
    coverage: "fixed_crypto_usage_limits_and_reference_record_charges_only", qualification: schema.crypto_usage_registry.qualification, vectors };
}
