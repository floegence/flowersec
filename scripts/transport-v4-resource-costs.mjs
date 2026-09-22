import assert from "node:assert/strict";
import { captureResourceRecord } from "./transport-v4-resources.mjs";

const requireThat = (condition, code) => { if (!condition) throw new Error(code); };
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const field = (schema, name) => Object.values(schema.frame_maps.SessionContract.fields).find(item => item.name === name);

export function verifyResourceFormulaRegistry(schema) {
  const registry = schema.resource_formula_registry;
  assert.equal(registry.status, "partial_known_costs_only");
  assert.deepEqual(registry.codec, { full_body_slots: 2, buffers_per_slot: 2, small_body_ceiling_bytes: 131072, small_slots_max: 4294967295 });
  assert.deepEqual(registry.bitmap, { roles: 2, bits_per_scope: 1, bits_per_byte: 8, ordinal_source: "stream_state_registry.client_ordinals" });
  assert.deepEqual(registry.application, {
    profiles: { transport: { rpc_channels: 0, notify_channels: 0, management_channels: 0 },
      services: { rpc_channels: 8, notify_channels: 2, management_channels: 0 },
      execution: { rpc_channels: 8, notify_channels: 2, management_channels: 1 } },
    channel_direction_bytes: 16384, directions: 2, query_slots: 2, reply_slot_bytes: 1024,
    fragment_associations_per_general: 2, fragment_association_bytes: 128,
    query_reserve_bytes: 524288, rpc_error_output_bytes_per_channel: 2048,
  });
  assert.deepEqual(Object.keys(registry.application.profiles), Object.keys(field(schema, "application_profile").enum));
  assert.ok(schema.stream_state_registry.client_ordinals >= schema.stream_state_registry.server_ordinals);
  assert.equal(schema.stream_state_registry.client_ordinals * registry.bitmap.roles % registry.bitmap.bits_per_byte, 0);
  assert.match(registry.qualification, /no full ready_min/u);
}

// Pure partial costs, not an admission decision or owner-union input. The body
// cost excludes envelopes, keys, jobs, indexes and simultaneous real copies.
// Application amounts enumerate the design's fixed baseline only: short-work,
// codec/reader objects, future maintenance, real tails and provider costs must
// still be charged by their actual owners before any Bind/Prepare/TxA.
export function knownResourceCosts(schema, input) {
  verifyResourceFormulaRegistry(schema);
  const config = captureResourceRecord(input,
    ["max_frame_bytes", "small_auth_slots", "application_profile", "rpc_max_general_outstanding"],
    ["max_frame_bytes", "small_auth_slots", "application_profile"]);
  const registry = schema.resource_formula_registry, codec = registry.codec, app = registry.application;
  requireThat(integer(config.max_frame_bytes, 1, schema.resource_caps.max_payload_length), "resource_frame_limit");
  requireThat(integer(config.small_auth_slots, 0, codec.small_slots_max), "resource_auth_slots");
  requireThat(typeof config.application_profile === "string" && Object.hasOwn(app.profiles, config.application_profile), "resource_application_profile");
  const profile = app.profiles[config.application_profile], enabled = profile.rpc_channels > 0;
  requireThat(Object.hasOwn(config, "rpc_max_general_outstanding") === enabled, "resource_rpc_limit_presence");
  const cap = field(schema, "rpc_max_general_outstanding");
  if (enabled) requireThat(integer(config.rpc_max_general_outstanding, cap.min, cap.max), "resource_rpc_limit");
  const maximum = BigInt(schema.resource_composition_registry.quantity_max);
  const checked = value => { requireThat(value >= 0n && value <= maximum, "resource_cost_overflow"); return value; };
  const mul = (...values) => values.reduce((total, value) => checked(total * BigInt(value)), 1n);
  const sum = values => values.reduce((total, value) => checked(total + value), 0n);
  const bigBody = mul(codec.full_body_slots, codec.buffers_per_slot, config.max_frame_bytes);
  const smallBody = mul(config.small_auth_slots, codec.buffers_per_slot, Math.min(config.max_frame_bytes, codec.small_body_ceiling_bytes));
  // Both roles cover the common encoding domain, including the server's
  // permanently unavailable management tail. It is not client+server quota.
  const bitmapBits = mul(schema.stream_state_registry.client_ordinals, registry.bitmap.roles, registry.bitmap.bits_per_scope);
  const bitmapBytes = bitmapBits / BigInt(registry.bitmap.bits_per_byte);
  const internal = profile.rpc_channels + profile.notify_channels, management = profile.management_channels;
  const k = enabled ? config.rpc_max_general_outstanding : 0;
  const replySlots = enabled ? k + app.query_slots : 0;
  const associations = enabled ? k * app.fragment_associations_per_general : 0;
  const appBytes = {
    reply_slots: mul(replySlots, app.reply_slot_bytes),
    fragment_associations: mul(associations, app.fragment_association_bytes),
    query_reserve: enabled ? BigInt(app.query_reserve_bytes) : 0n,
    rpc_error_output: mul(profile.rpc_channels, app.rpc_error_output_bytes_per_channel),
    internal_receive: mul(internal + management, app.channel_direction_bytes),
    internal_send: mul(internal + management, app.channel_direction_bytes),
  };
  return {
    codec_body_bytes: { full_slots: bigBody.toString(), small_slots: smallBody.toString(), total: sum([bigBody, smallBody]).toString() },
    permanent_bitmap_bytes: bitmapBytes.toString(),
    application_counts: { internal_active: internal, management_active: management, reply_slots: replySlots, fragment_associations: associations },
    application_bytes: { ...Object.fromEntries(Object.entries(appBytes).map(([name, value]) => [name, value.toString()])),
      total: sum(Object.values(appBytes)).toString() },
  };
}

export function buildResourceCostCorpus(schema) {
  verifyResourceFormulaRegistry(schema);
  const ids = new Set();
  const vectors = schema.resource_formula_vector_plan.map(spec => {
    assert.match(spec.id, /^resource_costs_[a-z0-9_]+$/u);
    assert.ok(!ids.has(spec.id), "duplicate resource cost vector"); ids.add(spec.id);
    const input = structuredClone(spec.input);
    if (spec.expected_error) {
      assert.throws(() => knownResourceCosts(schema, input), { message: spec.expected_error });
      return { id: spec.id, input, expected_error: spec.expected_error };
    }
    const expected = knownResourceCosts(schema, input);
    assert.equal(expected.codec_body_bytes.total, spec.expected_codec_bytes);
    assert.equal(expected.application_bytes.total, spec.expected_application_bytes);
    assert.equal(expected.permanent_bitmap_bytes, "524292");
    return { id: spec.id, input, expected };
  });
  return { status: "draft", coverage: "partial_known_resource_costs_only", schema_revision: schema.schema_revision,
    design_sha256: schema.design_sha256, qualification: schema.resource_formula_registry.qualification, vectors };
}
