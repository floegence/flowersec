import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { resourceMinimum } from "./testSupport/resources.js";
import { resourceCosts } from "./testSupport/resourceCosts.js";
import type { ResourceTotals } from "./testSupport/resources.js";
import { root } from "./testSupport/unicode.js";

type Input = { reference_limit: number; base: Record<string, Record<string, unknown>[]>; features: Record<string, Record<string, unknown>[]>; legal_selections: string[][] };
type Vector = { id: string; input: Input; expected_error?: string; expected_ready_min?: ResourceTotals };
const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/resources.json", root), "utf8")) as { vectors: Vector[] };
const basic = (): Input => structuredClone(corpus.vectors.find(vector => vector.id === "resources_empty_features")!.input);

it("v4.ts_resources independently checks all partial cost vectors", () => {
  const costs = JSON.parse(readFileSync(new URL("testdata/transport_v4/resource_costs.json", root), "utf8")) as {
    vectors: { id: string; input: unknown; expected?: unknown; expected_error?: string }[];
  };
  expect(costs.vectors).toHaveLength(18);
  for (const vector of costs.vectors) {
    const before = structuredClone(vector.input);
    if (vector.expected_error) expect(() => resourceCosts(vector.input), vector.id).toThrow(vector.expected_error);
    else expect(resourceCosts(vector.input), vector.id).toEqual(vector.expected);
    expect(vector.input).toEqual(before);
  }
  let calls = 0;
  const hook = (): never => { calls++; throw new Error("caller hook"); };
  expect(() => resourceCosts(new Proxy({}, { get: hook, ownKeys: hook }))).toThrow("resource_object");
  expect(() => resourceCosts(Object.defineProperty({}, "max_frame_bytes", { get: hook, enumerable: true }))).toThrow("resource_data_property");
  for (const value of [true, "1", 1n, 0.5, NaN, Infinity, { valueOf: hook }]) {
    expect(() => resourceCosts({ max_frame_bytes: 131072, small_auth_slots: value, application_profile: "transport" })).toThrow("resource_auth_slots");
  }
  expect(calls).toBe(0);
});

it("v4.ts_resources independently consumes complete synthetic composition corpus", () => {
  expect(corpus.vectors).toHaveLength(19);
  for (const vector of corpus.vectors) {
    const before = structuredClone(vector.input);
    if (vector.expected_error) expect(() => resourceMinimum(vector.input), vector.id).toThrow(vector.expected_error);
    else expect(resourceMinimum(vector.input), vector.id).toEqual(vector.expected_ready_min);
    expect(vector.input).toEqual(before);
  }
});

it("v4.ts_resources rejects caller hooks, unsafe quantities and overflowing dimensions", () => {
  let calls = 0; const hook = (): never => { calls++; throw new Error("caller callback"); };
  const changes: ((input: Input) => unknown)[] = [
    input => new Proxy(input, { get: hook, ownKeys: hook, getPrototypeOf: hook }),
    input => Object.defineProperty(input, "features", { get: hook }),
    input => Object.setPrototypeOf(input, new Proxy({}, { getPrototypeOf: hook })) as unknown,
    input => { Object.defineProperty(input.legal_selections, "0", { get: hook }); return input; },
    input => { input.base.transport_core = new Proxy([], { get: hook }); return input; },
    input => { (input.base.transport_core![0]!.vector as Record<string, unknown>).bytes = { toString: hook }; return input; },
  ];
  for (const change of changes) { expect(() => resourceMinimum(change(basic()))).toThrow(/^resource_/u); expect(calls).toBe(0); }
  for (const dimension of ["bytes", "work", "items"]) {
    const input = basic(), first = input.base.transport_core![0]!, second = structuredClone(first);
    second.owner_instance_id = "independent";
    (first.vector as Record<string, unknown>)[dimension] = "18446744073709551615";
    (second.vector as Record<string, unknown>)[dimension] = "1";
    input.base.actual_shared_refs!.push(second);
    expect(() => resourceMinimum(input)).toThrow("resource_sum_overflow");
  }
});

it("v4.ts_resources uses exact identity and detached results", () => {
  const input = basic(), first = input.base.transport_core![0]!, second = structuredClone(first);
  first.environment_id = "a:b"; first.owner_kind = "c";
  second.environment_id = "a"; second.owner_kind = "b:c";
  input.base.actual_shared_refs!.push(second);
  const result = resourceMinimum(input);
  expect(result.sdk_owned).toEqual({ bytes: "200", work: "20", items: "2" });
  result.sdk_owned!.bytes = "0";
  expect(resourceMinimum(input).sdk_owned!.bytes).toBe("200");
  // Canonically equivalent Unicode values still name distinct original owners.
  first.environment_id = "\u00e9"; second.environment_id = "e\u0301";
  first.owner_kind = second.owner_kind = "same";
  expect(resourceMinimum(input).sdk_owned!.bytes).toBe("200");
});
