// Generated stateless relations; no signature, trust or live-owner authority.
import { createHash } from "node:crypto";
import { transportV4Domains } from "../../generated/transportV4Registry.js";
import { encode, equal, join, own, uint } from "./cbor.js";
import type { Value } from "./cbor.js";
import { emptyContext, integer, lookup, record } from "./shape.js";
import type { Context } from "./shape.js";
import { Rules, array, hex, rawEqual, same, string, unsigned } from "./rules.js";
import type { Rule } from "./rules.js";
import { V4Failure } from "./unicode.js";

export function lexical(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! < b[i]! ? -1 : 1;
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}
function ordered(a: Value, b: Value): number {
  if (a.kind === "uint" && b.kind === "uint") return a.value === b.value ? 0 : a.value < b.value ? -1 : 1;
  if (a.kind === "bytes" && b.kind === "bytes") return lexical(a.value, b.value);
  throw new V4Failure("field_type");
}

export class Relations extends Rules {
  relations(input: Uint8Array, name = "", context: Context = emptyContext(), cap: bigint): Value {
    const value = this.decode(input, name, context, cap);
    if (name) this.walk(name, value, context, (name, value, ctx) => {
      this.checkVariants(name, value, ctx);
      for (const rule of own(this.registry.relation_rules, name) ?? []) {
        this.validateRelation(rule);
        if (this.applies(name, value, rule.when, ctx)) this.checkRelation(name, value, rule, ctx);
      }
    });
    return value;
  }

  private validateRelation(rule: Rule): void {
    const keys = new Set(["op", "field", "left", "right", "profile", "algorithm", "registry", "source", "domain", "when", "fields", "pairs", "rows", "max", "item_field_id", "item_fields", "item_field", "value", "feature", "present", "code_field", "target_scope_field", "stream_id_field", "retry_after_field", "selectors"]);
    if (Object.keys(rule).some(key => !keys.has(key))) throw new V4Failure("rule_unresolved");
    for (const selector of array(rule.selectors ?? [])) if (Object.keys(record(selector)).some(key => !["field", "context"].includes(key))) throw new V4Failure("rule_unresolved");
  }

  private checkRelation(name: string, value: Value, rule: Rule, context: Context): void {
    const get = (path: unknown): Value | undefined => this.path(name, value, string(path), context);
    const field = (key: string): Value | undefined => get(rule[key]), op = string(rule.op);
    switch (op) {
      case "is_null":
        if (field("field")?.kind !== "null") throw new V4Failure("field_null"); break;
      case "at_least_one":
        if (!array(rule.fields).some(path => get(path) !== undefined)) throw new V4Failure("field_presence"); break;
      case "equal": case "equal_if_present": case "not_equal": {
        const a = field("left"), b = field("right");
        if (op === "equal_if_present" && (a === undefined || b === undefined)) break;
        if (op === "not_equal") { if (same(a, b)) throw new V4Failure("field_distinctness"); }
        else if (!same(a, b)) throw new V4Failure("field_equality");
        break;
      }
      case "less_than": case "less_or_equal": case "max_difference": case "bit_subset": {
        const a = unsigned(field("left")), b = unsigned(field("right"));
        if (op === "less_than" && a >= b || op === "less_or_equal" && a > b) throw new V4Failure("field_order");
        if (op === "max_difference" && (a > b || b - a > integer(rule.max))) throw new V4Failure("field_duration");
        if (op === "bit_subset" && (a & ~b) !== 0n) throw new V4Failure("feature_subset");
        break;
      }
      case "allowed_pairs": case "allowed_tuples": {
        const fields = op === "allowed_pairs" ? [rule.left, rule.right] : array(rule.fields);
        let found = false;
        for (const row of array(rule[op === "allowed_pairs" ? "pairs" : "rows"])) {
          const entries = array(row);
          if (entries.length !== fields.length) throw new V4Failure("rule_unresolved");
          if (fields.every((path, i) => rawEqual(get(path), entries[i]))) found = true;
        }
        if (!found) throw new V4Failure(op === "allowed_pairs" ? "field_pair" : "field_tuple");
        break;
      }
      case "feature_bit": {
        const feature = own(record(this.fieldRegistry("feature_registry")), string(rule.feature));
        const bit = integer(record(feature).bit);
        if (bit >= 64n || typeof rule.present !== "boolean") throw new V4Failure("registry_unresolved");
        if (((unsigned(field("field")) & (1n << bit)) !== 0n) !== rule.present) throw new V4Failure("feature_policy");
        break;
      }
      case "profile_algorithm": {
        const profile = field("profile");
        if (profile?.kind !== "text") throw new V4Failure("field_type");
        const descriptor = record(own(record(this.fieldRegistry("crypto_profiles")), profile.value));
        if (unsigned(field("algorithm")) !== integer(descriptor.dh_algorithm)) throw new V4Failure("profile_algorithm");
        break;
      }
      case "error_scope": {
        const code = field("code_field");
        const label = Object.entries(record(this.fieldRegistry("error_codes"))).find(([, n]) => rawEqual(code, n))?.[0];
        if (label === undefined) throw new V4Failure("enum_value");
        const policy = record(own(record(this.fieldRegistry("error_code_metadata")), label));
        const target = field("target_scope_field"), stream = field("stream_id_field");
        if (target?.kind !== "uint") throw new V4Failure("error_scope");
        if (policy.scope === "session") {
          if (target.value !== 0n || stream !== undefined) throw new V4Failure("error_scope");
        } else if (policy.scope === "stream") {
          if (target.value === 0n || !same(stream, uint(target.value))) throw new V4Failure("error_scope");
        } else throw new V4Failure("registry_unresolved");
        if (typeof policy.retryable !== "boolean") throw new V4Failure("registry_unresolved");
        if (!policy.retryable && field("retry_after_field") !== undefined) throw new V4Failure("retry_after_forbidden");
        break;
      }
      case "registry_tuple": {
        let tuple = record(this.fieldRegistry(string(rule.registry)));
        for (const raw of array(rule.selectors)) {
          const selector = record(raw);
          let key: string | undefined;
          if (selector.context !== undefined) key = own(context.selectors, string(selector.context));
          else {
            const path = string(selector.field), actual = get(path);
            const field = Object.values(this.descriptor(name).fields).find(field => field.name === path);
            key = Object.entries(field?.enum ?? {}).find(([, n]) => rawEqual(actual, n))?.[0];
          }
          if (key === undefined || !Object.hasOwn(tuple, key)) throw new V4Failure("context_unresolved");
          tuple = record(tuple[key]);
        }
        for (const raw of array(rule.fields)) {
          const path = string(raw), expected = own(tuple, path);
          if (expected === undefined) throw new V4Failure("registry_unresolved");
          if (!rawEqual(get(path), expected)) throw new V4Failure("carrier_tuple");
        }
        break;
      }
      case "map_digest": this.mapDigest(string(rule.domain), field("source"), field("field")); break;
      case "unique_by": case "increasing_tuple": case "ordinal_indices": case "increasing":
      case "increasing_bytes": case "increasing_cbor": case "increasing_scopes": case "exclusive_item":
        this.arrayRelation(name, value, rule, context); break;
      default: throw new V4Failure("rule_unresolved");
    }
  }

  private mapDigest(name: string, source: Value | undefined, target: Value | undefined): void {
    if (target?.kind !== "bytes" || source?.kind !== "bytes" && source?.kind !== "map") throw new V4Failure("field_type");
    const raw = source.kind === "bytes" ? source.value : encode(source);
    const domain = (transportV4Domains as readonly unknown[]).map(record).find(domain => domain.name === name);
    if (!domain) throw new V4Failure("registry_unresolved");
    const parts = array(record(domain.input_schema).parts);
    if (domain.operation !== "sha256" || integer(domain.output_length) !== 32n || parts.length !== 1 || record(parts[0]).encoding !== "lp-map" || record(parts[0]).projection !== "full") throw new V4Failure("domain_projection");
    if (raw.length > 0xffffffff) throw new V4Failure("map_size");
    const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, raw.length, false);
    // Hash the complete embedded bytes, including their original signature.
    const actual = createHash("sha256").update(join([hex(domain.label_bytes), length, raw])).digest();
    if (!equal(actual, target.value)) throw new V4Failure("map_digest_mismatch");
  }

  private arrayRelation(name: string, value: Value, rule: Rule, context: Context): void {
    const op = string(rule.op), path = string(rule.field);
    const get = (path: string): Value | undefined => this.path(name, value, path, context);
    const input = get(path);
    if (input === undefined && ["increasing_bytes", "increasing_cbor"].includes(op)) return;
    if (input?.kind !== "array") throw new V4Failure("field_type");
    const scopeMax = op === "increasing_scopes" ? integer(record(record(this.fieldRegistry("resource_caps")).scope_id).max) : 0n;
    let previous: Value[] = [], previousBytes: Uint8Array = new Uint8Array();
    const seen = new Set<string>();
    for (let index = 0; index < input.value.length; index++) {
      const item = input.value[index]!, current = rule.item_field_id === undefined ? item : lookup(item, integer(rule.item_field_id));
      if (current === undefined) throw new V4Failure("unknown_rule_field");
      const base = `${path}.${index}.`;
      switch (op) {
        case "unique_by": case "increasing_tuple": {
          const tuple = array(rule.item_fields).map(field => {
            const value = get(base + string(field)); if (value === undefined) throw new V4Failure("unknown_rule_field"); return value;
          });
          if (op === "unique_by") {
            const identity = Buffer.from(encode({ kind: "array", value: tuple })).toString("hex");
            if (seen.has(identity)) throw new V4Failure("item_identity"); seen.add(identity);
          } else if (index > 0) {
            let order = 0;
            for (let i = 0; i < tuple.length; i++) { order = ordered(previous[i]!, tuple[i]!); if (order !== 0) break; }
            if (order >= 0) throw new V4Failure("item_order");
          }
          previous = tuple; break;
        }
        case "ordinal_indices":
          if (current.kind !== "uint" || current.value !== BigInt(index)) throw new V4Failure("item_index"); break;
        case "increasing": case "increasing_scopes": {
          const n = unsigned(current), unordered = index > 0 && ordered(previous[0]!, current) >= 0;
          if (op === "increasing_scopes") {
            if (n === 0n || n > scopeMax || unordered) throw new V4Failure("scope_order");
          } else if (unordered) throw new V4Failure("item_order");
          previous = [current]; break;
        }
        case "increasing_bytes": case "increasing_cbor": {
          if (op === "increasing_bytes" && current.kind !== "bytes") throw new V4Failure("field_type");
          const raw = op === "increasing_cbor" ? encode(current) : (current as Extract<Value, { kind: "bytes" }>).value;
          // Array ordering is bytewise, unlike length-first canonical map keys.
          if (index > 0 && lexical(previousBytes, raw) >= 0) throw new V4Failure("item_order");
          previousBytes = raw; break;
        }
        case "exclusive_item":
          if (rawEqual(get(base + string(rule.item_field)), rule.value) && input.value.length !== 1) throw new V4Failure("item_exclusive"); break;
        default: throw new V4Failure("rule_unresolved");
      }
    }
  }
}
