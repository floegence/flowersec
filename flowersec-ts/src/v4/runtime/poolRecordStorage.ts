/** Pure storage facts reader shared with the fixed SQLite worker. All returned
 * byte slices borrow the one bounded row; no credential or authority is made. */
export const poolProjectionInspectionBytes = 1048576n;
export type PoolStorageValue = bigint | string | Uint8Array | boolean | PoolStorageValue[] | Map<number, PoolStorageValue>;
export function readPoolStorageValue(input: Uint8Array, maximum: number, maximumNodes = 1024): PoolStorageValue {
  const invalid = (): never => { throw new Error("storage_format"); };
  const require = (condition: unknown): void => { if (!condition) invalid(); };
    require(input.length > 0 && input.length <= maximum);
    let offset = 0, nodes = 0;
    const take = (): number => { if (offset >= input.length) invalid(); return input[offset++]!; };
    const read = (depth: number): PoolStorageValue => {
      require(depth <= 16 && ++nodes <= maximumNodes);
      const tag = take(), major = tag >>> 5, additional = tag & 31;
      if (tag === 0xf4 || tag === 0xf5) return tag === 0xf5;
      require(major === 0 || major >= 2 && major <= 5);
      let length = BigInt(additional);
      if (additional >= 24) {
        require(additional <= 27);
        const width = 1 << (additional - 24); length = 0n;
        for (let index = 0; index < width; index++) length = length << 8n | BigInt(take());
        require(length >= (width === 1 ? 24n : 1n << BigInt(width * 4)));
      }
      if (major === 0) return length;
      require(length <= BigInt(input.length));
      const size = Number(length);
      if (major === 2 || major === 3) {
        require(size <= input.length - offset);
        const bytes = input.subarray(offset, offset += size);
        if (major === 2) return bytes;
        require(size <= 1024);
        const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        require(value.normalize("NFC") === value); return value;
      }
      if (major === 4) {
        require(size <= 64); const values: PoolStorageValue[] = [];
        for (let index = 0; index < size; index++) values.push(read(depth + 1));
        return values;
      }
      require(size <= 64); const values = new Map<number, PoolStorageValue>(); let previous = -1n;
      for (let index = 0; index < size; index++) {
        const field = read(depth + 1);
        require(typeof field === "bigint" && field > previous && field <= 65535n);
        previous = field as bigint; values.set(Number(field), read(depth + 1));
      }
      return values;
    };
    const value = read(0); require(offset === input.length); return value;
}

export function validatePersistedPoolProjection(key: Uint8Array, encoded: Uint8Array,
  identity: Readonly<{ authority: string; storeID: Uint8Array; generation: bigint }>,
  fence: bigint, currentEpoch: bigint, retainedUntil: bigint,
  activationDigest: (bytes: Uint8Array) => Uint8Array, parse = readPoolStorageValue): void {
  type Value = PoolStorageValue;
  const invalid = (): never => { throw new Error("storage_format"); };
  const require = (condition: unknown): void => { if (!condition) invalid(); };
  const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((value, index) => value === b[index]);
  const map = (value: Value | undefined, size?: number): Map<number, Value> => {
    if (!(value instanceof Map) || size !== undefined && value.size !== size) return invalid(); return value;
  };
  const uint = (value: Value | undefined, minimum = 0n, maximum = 0xffffffffffffffffn): bigint => {
    if (typeof value !== "bigint" || value < minimum || value > maximum) return invalid(); return value;
  };
  const data = (value: Value | undefined, size?: number): Uint8Array => {
    if (!(value instanceof Uint8Array) || size !== undefined && value.length !== size) return invalid(); return value;
  };
  const text = (value: Value | undefined): string => {
    if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(value)) return invalid(); return value;
  };
  const fields = map(parse(encoded, 1 << 20), 40);
  for (let index = 0; index < 40; index++) require(fields.has(index));
  const u = (id: number, minimum = 0n, maximum = 0xffffffffffffffffn): bigint => uint(fields.get(id), minimum, maximum);
  const b = (id: number, size?: number): Uint8Array => data(fields.get(id), size);
  const t = (id: number): string => text(fields.get(id));
  require(u(0) === 1n && same(b(1, 32), identity.storeID) && u(2, 1n) === identity.generation &&
    u(3, 1n) === fence && fence <= currentEpoch && t(27) === identity.authority && u(32) === 0n);
  const tenant = new TextEncoder().encode(t(4));
  require(key.length === tenant.length + 33 && key[0] === tenant.length && same(key.subarray(1, 1 + tenant.length), tenant) &&
    same(key.subarray(1 + tenant.length, 17 + tenant.length), b(5, 16)) && same(key.subarray(17 + tenant.length), b(6, 16)));
  for (const id of [10, 13, 14, 15]) require(b(id, 16).some(value => value !== 0));
  for (const id of [7, 9, 12, 17, 18, 31, 33, 34, 35]) b(id, 32);
  u(11, 0n, 15n); u(16, 1n); u(30, 1n); t(28); t(29); t(37); t(38);
  require(["fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1", "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"].includes(t(36)) && t(39) === "preauthorized_pool");
  // Certificate and relay lifetimes can shorten the effective session end
  // independently of the activation window retained in this projection.
  require(u(20) <= u(24) && u(24) < u(23) && u(24) < u(21) && u(24) < u(22) && u(21) <= u(26) &&
    u(25, 1n) === retainedUntil && retainedUntil === (u(26) > u(24) ? u(26) : u(24)) + 604800000n);
  const proof = b(8), activation = map(parse(proof, 4096), 17);
  for (let index = 0; index < 17; index++) require(activation.has(index));
  require(uint(activation.get(0)) === 1n && text(activation.get(1)) === t(27) && text(activation.get(2)) === t(38) &&
    text(activation.get(3)) === t(4) && text(activation.get(12)) === t(37));
  for (const [field, projection, size] of [[4, 5, 16], [5, 6, 16], [6, 7, 32], [8, 18, 32], [9, 13, 16], [10, 33, 32], [11, 34, 32]] as const)
    require(same(data(activation.get(field), size), b(projection, size)));
  require(uint(activation.get(13)) === u(20) && uint(activation.get(14)) >= u(21) &&
    uint(activation.get(13)) < uint(activation.get(14)) && uint(activation.get(14)) <= uint(activation.get(15)) && uint(activation.get(15)) >= u(22));
  data(activation.get(16), 64);
  const digest = activationDigest(proof);
  try { require(same(digest, b(9, 32))); } finally { digest.fill(0); }
  const selection = map(activation.get(7), 5), once = map(selection.get(4), 4), budget = map(selection.get(3), 5);
  require(same(data(selection.get(0), 32), b(7, 32)) && same(data(selection.get(2), 32), b(17, 32)) &&
    text(once.get(0)) === t(4) && same(data(once.get(1), 16), b(5, 16)) && text(once.get(2)) === t(27) && text(once.get(3)) === t(28));
  const indices = selection.get(1); require(Array.isArray(indices) && indices.length >= 1 && indices.length <= 16);
  let previous = -1n, selected = false;
  for (const value of indices as Value[]) { const index = uint(value, 0n, 15n); require(index > previous); previous = index; selected ||= index === u(11); }
  require(selected); const candidateBudget = map(budget.get(0), 3);
  uint(candidateBudget.get(0), 1n, 8n); uint(candidateBudget.get(1), 1n, 262144n); uint(candidateBudget.get(2), 1n, 256n);
  uint(budget.get(1), 1n, 32n); uint(budget.get(2), 1n, 8388608n); uint(budget.get(3), 1n, 8192n); uint(budget.get(4), 1n, 2n);
  const leg = map(parse(b(19), 65536));
  require(leg.size >= 10 && leg.size <= 14);
  for (const id of [0, 1, 2, 3, 4, 5, 6, 7, 8, 10]) require(leg.has(id));
  for (const id of leg.keys()) require(id <= 13);
  const access = uint(leg.get(0), 0n, 1n), endpoint = uint(leg.get(2), 0n, 1n), dialer = uint(leg.get(3), 0n, 2n), listener = uint(leg.get(4), 0n, 2n);
  const carrier = uint(leg.get(5), 0n, 2n), port = uint(leg.get(7), 1n, 65535n);
  data(leg.get(1), 16);
  const boundedText = (value: Value | undefined, maximum: number): string => {
    if (typeof value !== "string" || new TextEncoder().encode(value).length > maximum) return invalid(); return value;
  };
  const host = boundedText(leg.get(6), 253), path = boundedText(leg.get(8), 128), subprotocol = boundedText(leg.get(10), 128);
  require(host.length > 0 && !/[^\x21-\x7e]/u.test(host));
  // The writer retains either the direct leg or the selected tunnel's client
  // leg. Its role tuple determines which registered carrier tuple applies.
  const direct = endpoint === 1n && dialer === 0n && listener === 1n;
  require(direct || endpoint === 0n && (dialer === 0n && listener === 2n || dialer === 2n && listener === 0n));
  if (access === 1n) {
    require(direct && carrier === 1n && port >= 1024n && !leg.has(9) && !leg.has(11) && !leg.has(12));
    const loopback = host === "::1" || /^127(?:\.(?:0|[1-9][0-9]{0,2})){3}$/u.test(host) && host.split(".").every(part => Number(part) <= 255);
    require(loopback && path === "/flowersec/v4/local" && subprotocol === "flowersec.local.v4" &&
      boundedText(leg.get(13), 512) === `http://${host === "::1" ? "[::1]" : host}:${port}`);
  } else {
    require(!leg.has(13));
    const alpn = boundedText(leg.get(9), 128), kind = direct ? "direct" : "tunnel";
    require(carrier === 0n ? path === "" && alpn === `flowersec-${kind}/4` && subprotocol === "" :
      carrier === 1n ? path === `/flowersec/v4/${kind}` && alpn === "http/1.1" && subprotocol === `flowersec.${kind}.v4` :
        path === `/flowersec/webtransport/v4/${kind}` && alpn === "h3" && subprotocol === "");
    require(carrier !== 0n || !leg.has(12)); require(carrier !== 2n || leg.has(12));
    const tls = map(leg.get(11)), mode = uint(tls.get(0), 0n, 1n);
    require(typeof tls.get(1) === "boolean" && tls.size === (mode === 0n ? 2 : 4));
    if (mode === 1n) {
      require(uint(tls.get(2)) === 0n);
      const pins = tls.get(3); require(Array.isArray(pins) && pins.length >= 1 && pins.length <= 16);
      let previousPin: Uint8Array | undefined;
      for (const value of pins as Value[]) {
        const pin = map(value, 4), digest = data(pin.get(0), 32), start = uint(pin.get(1)), end = uint(pin.get(2));
        require(start < end && end - start <= 1209600000n && pin.get(3) === "x509v3-p256-14d");
        if (previousPin !== undefined) {
          const first = digest.findIndex((byte, index) => byte !== previousPin![index]);
          require(first >= 0 && digest[first]! > previousPin[first]!);
        }
        previousPin = digest;
      }
    }
    if (leg.has(12)) {
      const policy = map(leg.get(12), 2), origins = policy.get(0);
      require(typeof policy.get(1) === "boolean" && Array.isArray(origins) && origins.length >= 1 && origins.length <= 8);
      let previousOrigin: string | undefined;
      for (const value of origins as Value[]) {
        const origin = boundedText(value, 512);
        require(/^(?:https?|wss?|ftp):\/\/(?:\[[0-9a-f:]+\]|[^:/?#@\\\[\]\s]+)(?::(?:0|[1-9][0-9]{0,4}))?$/u.test(origin) && !/[^\x21-\x7e]/u.test(origin));
        require(previousOrigin === undefined || origin.length > previousOrigin.length || origin.length === previousOrigin.length && origin > previousOrigin);
        previousOrigin = origin;
      }
    }
  }
}
