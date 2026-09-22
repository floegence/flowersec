import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { cryptoUsage } from "./testSupport/cryptoUsage.js";
import { root } from "./testSupport/unicode.js";
import { transportV4CryptoUsageRegistry as spec } from "../generated/transportV4Registry.js";

it("v4.ts_crypto_usage consumes all shared charge vectors", () => {
  const corpus = JSON.parse(readFileSync(new URL("testdata/transport_v4/crypto_usage.json", root), "utf8")) as {
    vectors: { id: string; profile: string; input: unknown; expected?: unknown; expected_error?: string }[];
  };
  expect(corpus.vectors).toHaveLength(28);
  for (const v of corpus.vectors) {
    const original = structuredClone(v.input);
    if (v.expected_error) expect(() => cryptoUsage(v.profile,v.input),v.id).toThrow(v.expected_error);
    else expect(cryptoUsage(v.profile,v.input),v.id).toEqual(v.expected);
    expect(v.input).toEqual(original);
  }
});
it("v4.ts_crypto_usage covers block rounding, strict inputs and output ownership", () => {
  for (const profile of Object.keys(spec.profiles)) for (let aad = 0; aad <= 33; aad++) for (let payload = 0; payload <= 33; payload++) {
    const result = cryptoUsage(profile,{ operation:"seal",aad_bytes:String(aad),input_bytes:String(payload) });
    expect(result).toEqual(cryptoUsage(profile,{ operation:"open",aad_bytes:String(aad),input_bytes:String(payload+16) }));
    expect(result.authentication_blocks).toBe(String(Math.ceil(aad/16)+Math.ceil(payload/16)+1));
  }
  const profile = Object.keys(spec.profiles)[0]!, input = { operation:"seal",aad_bytes:"0",input_bytes:"0" };
  let calls = 0; const trap = (): never => { calls++; throw new Error("hook"); };
  expect(() => cryptoUsage(profile,new Proxy(input,{ getPrototypeOf:trap }))).toThrow("crypto_usage_input");
  expect(() => cryptoUsage(profile,Object.defineProperty({...input},"aad_bytes",{get:trap}))).toThrow("crypto_usage_data");
  expect(() => cryptoUsage({toString:trap},input)).toThrow("crypto_usage_profile");
  for (const bad of [1,1n,true,null,"","01","-1","+1","1.0","1\n","١","18446744073709551616",{toString:trap}]) expect(() => cryptoUsage(profile,{...input,aad_bytes:bad})).toThrow("crypto_usage_integer");
  const result = cryptoUsage(profile,input); input.input_bytes = "100";
  expect(Object.isFrozen(result)).toBe(true); expect(result.ciphertext_bytes).toBe("16"); expect(calls).toBe(0);
});
