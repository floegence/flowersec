// Independent test-only partial costs. These do not establish admission or RSS.
import { transportV4ResourceFormulaRegistry as spec } from "../../generated/transportV4Registry.js";
import { captureResourceObject } from "./resources.js";

function number(value: unknown, min: number, max: number, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) throw new Error(code);
  return value;
}
function checked(value: bigint): bigint {
  if (value < 0n || value > 0xffffffffffffffffn) throw new Error("resource_cost_overflow");
  return value;
}
const multiply = (...values: number[]): bigint => values.reduce((n, value) => checked(n * BigInt(value)), 1n);
const total = (values: bigint[]): string => values.reduce((a, b) => checked(a + b), 0n).toString();

export function resourceCosts(input: unknown) {
  const c = captureResourceObject(input, ["max_frame_bytes", "small_auth_slots", "application_profile", "rpc_max_general_outstanding"],
    ["max_frame_bytes", "small_auth_slots", "application_profile"]);
  const m = number(c.max_frame_bytes, 1, spec.max_frame_bytes, "resource_frame_limit");
  const n = number(c.small_auth_slots, 0, spec.codec.small_slots_max, "resource_auth_slots");
  if (typeof c.application_profile !== "string" || !Object.hasOwn(spec.application.profiles, c.application_profile)) throw new Error("resource_application_profile");
  const p = spec.application.profiles[c.application_profile as keyof typeof spec.application.profiles], a = spec.application;
  const enabled = p.rpc_channels > 0;
  if (Object.hasOwn(c, "rpc_max_general_outstanding") !== enabled) throw new Error("resource_rpc_limit_presence");
  const k = enabled ? number(c.rpc_max_general_outstanding, spec.rpc_general_limit.min, spec.rpc_general_limit.max, "resource_rpc_limit") : 0;
  const large = multiply(spec.codec.full_body_slots, spec.codec.buffers_per_slot, m);
  const small = multiply(n, spec.codec.buffers_per_slot, Math.min(m, spec.codec.small_body_ceiling_bytes));
  const bits = multiply(spec.common_scope_ordinals, spec.bitmap.roles, spec.bitmap.bits_per_scope);
  const reply = enabled ? k + a.query_slots : 0, assoc = enabled ? k * a.fragment_associations_per_general : 0;
  const internal = p.rpc_channels + p.notify_channels;
  const bytes = {
    reply_slots: multiply(reply, a.reply_slot_bytes), fragment_associations: multiply(assoc, a.fragment_association_bytes),
    query_reserve: enabled ? BigInt(a.query_reserve_bytes) : 0n,
    rpc_error_output: multiply(p.rpc_channels, a.rpc_error_output_bytes_per_channel),
    internal_receive: multiply(internal + p.management_channels, a.channel_direction_bytes),
    internal_send: multiply(internal + p.management_channels, a.channel_direction_bytes),
  };
  return {
    codec_body_bytes: { full_slots: large.toString(), small_slots: small.toString(), total: total([large, small]) },
    permanent_bitmap_bytes: (bits / BigInt(spec.bitmap.bits_per_byte)).toString(),
    application_counts: { internal_active: internal, management_active: p.management_channels, reply_slots: reply, fragment_associations: assoc },
    application_bytes: { ...Object.fromEntries(Object.entries(bytes).map(([name, value]) => [name, value.toString()])), total: total(Object.values(bytes)) },
  };
}
