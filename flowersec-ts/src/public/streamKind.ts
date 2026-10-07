import { unicode151Assigned } from "../generated/unicode151.js";

const encoder = new TextEncoder();
/** Application kinds keep their existing Unicode and NFC contract independently
 * of carrier, record-engine or upper-layer *_v1 names. */
export function validApplicationStreamKind(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.normalize("NFC") !== value || encoder.encode(value).length > 128) return false;
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0)!;
    if (codePoint >= 0xd800 && codePoint <= 0xdfff || codePoint <= 0x1f || codePoint >= 0x7f && codePoint <= 0x9f || !unicode151Assigned(codePoint)) return false;
  }
  const scalars = Array.from(value);
  return !isUnicodeWhitespace(scalars[0]!.codePointAt(0)!) && !isUnicodeWhitespace(scalars.at(-1)!.codePointAt(0)!);
}
function isUnicodeWhitespace(codePoint: number): boolean {
  return codePoint >= 0x0009 && codePoint <= 0x000d || codePoint === 0x0020 || codePoint === 0x0085 || codePoint === 0x00a0 || codePoint === 0x1680 ||
    codePoint >= 0x2000 && codePoint <= 0x200a || codePoint === 0x2028 || codePoint === 0x2029 || codePoint === 0x202f || codePoint === 0x205f || codePoint === 0x3000;
}
