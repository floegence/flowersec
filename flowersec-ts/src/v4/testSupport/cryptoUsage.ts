// Independent test-only charges, without AEAD, input eligibility or reservation.
import { types } from "node:util";
import { transportV4CryptoUsageRegistry as spec, transportV4RecordRegistry } from "../../generated/transportV4Registry.js";

const maximum = BigInt(spec.quantity_max);
function must(condition: unknown, code: string): asserts condition { if (!condition) throw new Error(code); }
export function cryptoUsage(profile: unknown, input: unknown): Readonly<Record<string, string>> {
  must(typeof profile === "string" && Object.hasOwn(spec.profiles, profile), "crypto_usage_profile");
  must(input !== null && typeof input === "object" && !types.isProxy(input) && [null, Object.prototype as unknown].includes(Object.getPrototypeOf(input)), "crypto_usage_input");
  const fields: readonly string[] = spec.charge_fields, keys = Reflect.ownKeys(input);
  must(keys.length === fields.length && keys.every(key => typeof key === "string" && fields.includes(key)), "crypto_usage_fields");
  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    must(descriptor && Object.hasOwn(descriptor, "value") && descriptor.enumerable, "crypto_usage_data"); values[key] = descriptor.value as unknown;
  }
  must(typeof values.operation === "string" && (spec.operations as readonly string[]).includes(values.operation), "crypto_usage_operation");
  const integer = (value: unknown): bigint => {
    must(typeof value === "string" && value.length <= spec.quantity_max.length && /^(0|[1-9][0-9]*)$/u.test(value), "crypto_usage_integer");
    const n = BigInt(value); must(n <= maximum, "crypto_usage_integer"); return n;
  };
  const aad = integer(values.aad_bytes), bytes = integer(values.input_bytes), block = BigInt(spec.authentication_block_bytes);
  const tag = BigInt(transportV4RecordRegistry.profiles[profile as keyof typeof spec.profiles].tag_bytes);
  const seal = values.operation === "seal";
  must(seal || bytes >= tag, "crypto_usage_ciphertext");
  const payload = seal ? bytes : bytes - tag, ciphertext = seal ? bytes + tag : bytes;
  must(ciphertext <= maximum, "crypto_usage_overflow");
  const blocks = (n: bigint): bigint => n / block + (n % block ? 1n : 0n);
  const authentication = blocks(aad) + blocks(payload) + BigInt(spec.length_blocks);
  must(authentication <= maximum, "crypto_usage_overflow");
  return Object.freeze({ calls: "1", authentication_blocks: String(authentication), ciphertext_bytes: String(ciphertext) });
}
