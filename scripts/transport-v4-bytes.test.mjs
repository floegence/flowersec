import assert from "node:assert/strict";
import test from "node:test";
import { referenceByteView } from "./transport-v4-bytes.mjs";

test("byte inspection rejects inherited proxy prototypes without executing traps", () => {
  for (const value of [new Uint8Array([7]), Buffer.from([7])]) {
    let calls = 0; const original = Object.getPrototypeOf(value);
    const prototype = new Proxy({}, { getPrototypeOf() {
      calls++; Object.setPrototypeOf(value, original); return original;
    } });
    Object.setPrototypeOf(value, prototype);
    assert.throws(() => referenceByteView(value), TypeError);
    assert.equal(calls, 0); assert.equal(Object.getPrototypeOf(value), prototype);
  }
});

test("byte inspection uses internal brand and exact view bounds", () => {
  let calls = 0;
  const trap = new Proxy(new Uint8Array([7]), { getPrototypeOf() { calls++; return Uint8Array.prototype; } });
  const revoked = Proxy.revocable(new Uint8Array([7]), {}); revoked.revoke();
  for (const value of [trap, revoked.proxy, Object.create(Uint8Array.prototype), new Uint16Array([7]), new (class extends Uint8Array {})([7]), null, undefined, 7]) assert.throws(() => referenceByteView(value), TypeError);
  assert.equal(calls, 0);
  for (const backing of [new Uint8Array([1, 2, 3, 4]), Buffer.from([1, 2, 3, 4])]) {
    const view = referenceByteView(backing.subarray(1, 3));
    assert.deepEqual([...view], [2, 3]); assert.equal(view.length, 2);
  }
});
