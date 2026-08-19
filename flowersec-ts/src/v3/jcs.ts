const encoder = new TextEncoder();

export type JCSValue = null | boolean | number | string | readonly JCSValue[] | Readonly<{ [key: string]: JCSValue }>;

export function canonicalizeJCSV3(value: JCSValue): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
        throw new TypeError("Flowersec v3 JCS numbers must be safe integers");
      }
      return String(value);
    case "string":
      assertUnicodeScalarString(value);
      return JSON.stringify(value);
    case "object":
      if (Array.isArray(value)) return `[${value.map(canonicalizeJCSV3).join(",")}]`;
      const object = value as Readonly<{ [key: string]: JCSValue }>;
      return `{${Object.keys(object).sort(compareUTF16).map((key) => {
        assertUnicodeScalarString(key);
        return `${JSON.stringify(key)}:${canonicalizeJCSV3(object[key]!)}`;
      }).join(",")}}`;
  }
}

export function jcsUTF8V3(value: JCSValue): Uint8Array {
  return encoder.encode(canonicalizeJCSV3(value));
}

export function assertJCSValueV3(value: unknown): asserts value is JCSValue {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new TypeError("invalid JCS number");
    return;
  }
  if (typeof value === "string") {
    assertUnicodeScalarString(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertJCSValueV3(item);
    return;
  }
  if (typeof value !== "object" || value === null) throw new TypeError("invalid JCS value");
  for (const [key, item] of Object.entries(value)) {
    assertUnicodeScalarString(key);
    assertJCSValueV3(item);
  }
}

function compareUTF16(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertUnicodeScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) throw new TypeError("unpaired UTF-16 surrogate");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("unpaired UTF-16 surrogate");
    }
  }
}
