const encoder = new TextEncoder();

type JSONPathSegment = string | number;

type ScopedPayloadLimits = {
  nodes: number;
};

export function preflightJSONV3(text: string, scanScopedPayloads = false): void {
  new JSONPreflightScanner(text, scanScopedPayloads).scan();
}

class JSONPreflightScanner {
  private index = 0;

  constructor(
    private readonly text: string,
    private readonly scanScopedPayloads: boolean,
  ) {}

  scan(): void {
    this.value(0, []);
    this.whitespace();
    if (this.index !== this.text.length) throw new Error("trailing JSON value");
  }

  private value(depth: number, path: readonly JSONPathSegment[]): void {
    if (depth > 128) throw new Error("JSON nesting is too deep");
    this.whitespace();
    if (this.scanScopedPayloads && isScopedPayloadPath(path)) {
      this.scopedValue(1, { nodes: 0 }, true);
      return;
    }
    const char = this.text[this.index];
    if (char === "{") return this.object(depth, path);
    if (char === "[") return this.array(depth, path);
    if (char === '"') {
      this.string();
      return;
    }
    if (char === "t") return this.literal("true");
    if (char === "f") return this.literal("false");
    if (char === "n") return this.literal("null");
    this.number(false);
  }

  private object(depth: number, path: readonly JSONPathSegment[]): void {
    this.index += 1;
    this.whitespace();
    const seen = new Set<string>();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return;
    }
    while (true) {
      this.whitespace();
      if (this.text[this.index] !== '"') throw new Error("JSON object key is not a string");
      const key = this.string();
      if (seen.has(key)) throw new Error(`duplicate JSON field ${JSON.stringify(key)}`);
      seen.add(key);
      this.whitespace();
      if (this.text[this.index] !== ":") throw new Error("missing JSON colon");
      this.index += 1;
      this.value(depth + 1, [...path, key]);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "}") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new Error("invalid JSON object separator");
      this.index += 1;
    }
  }

  private array(depth: number, path: readonly JSONPathSegment[]): void {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return;
    }
    let item = 0;
    while (true) {
      this.value(depth + 1, [...path, item]);
      item += 1;
      this.whitespace();
      const next = this.text[this.index];
      if (next === "]") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new Error("invalid JSON array separator");
      this.index += 1;
    }
  }

  private scopedValue(depth: number, limits: ScopedPayloadLimits, requireObject = false): void {
    this.whitespace();
    if (depth > 16) throw new Error("scope payload depth exceeds 16");
    limits.nodes += 1;
    if (limits.nodes > 256) throw new Error("scope payload node count exceeds 256");
    const char = this.text[this.index];
    if (requireObject && char !== "{") throw new Error("scope payload root is not an object");
    if (char === "{") return this.scopedObject(depth, limits);
    if (char === "[") return this.scopedArray(depth, limits);
    if (char === '"') {
      if (encoder.encode(this.string()).length > 1_024) throw new Error("scope payload string exceeds 1024 bytes");
      return;
    }
    if (char === "t") return this.literal("true");
    if (char === "f") return this.literal("false");
    if (char === "n") return this.literal("null");
    this.number(true);
  }

  private scopedObject(depth: number, limits: ScopedPayloadLimits): void {
    this.index += 1;
    this.whitespace();
    const seen = new Set<string>();
    if (this.text[this.index] === "}") {
      this.index += 1;
      return;
    }
    let members = 0;
    while (true) {
      this.whitespace();
      if (this.text[this.index] !== '"') throw new Error("JSON object key is not a string");
      const key = this.string();
      if (encoder.encode(key).length > 128) throw new Error("scope payload key exceeds 128 bytes");
      if (seen.has(key)) throw new Error(`duplicate JSON field ${JSON.stringify(key)}`);
      seen.add(key);
      members += 1;
      if (members > 64) throw new Error("scope payload object exceeds 64 members");
      this.whitespace();
      if (this.text[this.index] !== ":") throw new Error("missing JSON colon");
      this.index += 1;
      this.scopedValue(depth + 1, limits);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "}") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new Error("invalid JSON object separator");
      this.index += 1;
    }
  }

  private scopedArray(depth: number, limits: ScopedPayloadLimits): void {
    this.index += 1;
    this.whitespace();
    if (this.text[this.index] === "]") {
      this.index += 1;
      return;
    }
    let elements = 0;
    while (true) {
      elements += 1;
      if (elements > 64) throw new Error("scope payload array exceeds 64 elements");
      this.scopedValue(depth + 1, limits);
      this.whitespace();
      const next = this.text[this.index];
      if (next === "]") {
        this.index += 1;
        return;
      }
      if (next !== ",") throw new Error("invalid JSON array separator");
      this.index += 1;
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.text.length) {
      const code = this.text.charCodeAt(this.index);
      if (code === 0x22) {
        this.index += 1;
        return JSON.parse(this.text.slice(start, this.index)) as string;
      }
      if (code < 0x20) throw new Error("control character in JSON string");
      if (code === 0x5c) {
        this.index += 1;
        const escaped = this.text[this.index];
        if (escaped === "u") {
          const digits = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) throw new Error("invalid JSON unicode escape");
          this.index += 5;
          continue;
        }
        if (escaped === undefined || !'"\\/bfnrt'.includes(escaped)) {
          throw new Error("invalid JSON escape");
        }
      }
      this.index += 1;
    }
    throw new Error("unterminated JSON string");
  }

  private number(canonicalInteger: boolean): void {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(this.text.slice(this.index));
    if (match === null) throw new Error("invalid JSON value");
    const raw = match[0];
    if (canonicalInteger) {
      if (!/^-?(?:0|[1-9]\d*)$/.test(raw) || raw === "-0") {
        throw new Error("scope payload number is not a canonical integer");
      }
      try {
        const value = BigInt(raw);
        if (value < -9_007_199_254_740_991n || value > 9_007_199_254_740_991n) {
          throw new Error("scope payload integer is outside the signed safe range");
        }
      } catch (error) {
        if (error instanceof Error && error.message.includes("scope payload")) throw error;
        throw new Error("scope payload integer is outside the signed safe range");
      }
    }
    this.index += raw.length;
  }

  private literal(value: string): void {
    if (!this.text.startsWith(value, this.index)) throw new Error("invalid JSON literal");
    this.index += value.length;
  }

  private whitespace(): void {
    while (/[\u0009\u000a\u000d\u0020]/.test(this.text[this.index] ?? "")) this.index += 1;
  }
}

function isScopedPayloadPath(path: readonly JSONPathSegment[]): boolean {
  return path.length === 3 && path[0] === "scoped" && typeof path[1] === "number" && path[2] === "payload";
}
