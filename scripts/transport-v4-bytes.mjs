import { types } from "node:util";

// Reference-tooling byte inspection, not runtime ownership or immutability proof.
const typedArrayPrototype=Object.getPrototypeOf(Uint8Array.prototype);
const metadata=Object.fromEntries(["length","buffer","byteOffset","byteLength"].map(name=>[name,Object.getOwnPropertyDescriptor(typedArrayPrototype,name).get]));

export function referenceByteView(value) {
  // A genuine view can inherit a Proxy prototype. instanceof would traverse
  // that chain and invoke caller code before the immediate-prototype check.
  if (!types.isUint8Array(value) || ![Uint8Array.prototype,Buffer.prototype].includes(Object.getPrototypeOf(value))) throw new TypeError("unsupported byte representation");
  for (const name of Object.keys(metadata)) if (Object.hasOwn(value,name)) throw new TypeError("shadowed byte metadata");
  // Intrinsic getters brand-check the view, including rejecting proxies, and
  // never invoke caller-supplied length/buffer/offset accessors.
  const buffer=metadata.buffer.call(value), offset=metadata.byteOffset.call(value), length=metadata.byteLength.call(value);
  if (metadata.length.call(value)!==length) throw new TypeError("byte width mismatch");
  // Buffer.from(ArrayBuffer) reads its public byteLength, which can itself be
  // shadowed. The intrinsic typed-array constructor uses the backing's internal
  // slots. Give only this fresh, private view Buffer's byte-search methods.
  return Object.setPrototypeOf(new Uint8Array(buffer,offset,length),Buffer.prototype);
}
