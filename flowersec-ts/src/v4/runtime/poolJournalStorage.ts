import { readPoolStorageValue, type PoolStorageValue as Value } from "./poolRecordStorage.js";

/** Validate the current journal envelope without importing material or calling
 * an application decoder. Material bytes remain opaque and digest-bound. */
export function validatePersistedPoolJournal(key: Uint8Array, encoded: Uint8Array, epoch: bigint,
  hash: (bytes: Uint8Array) => Uint8Array, certificateDigest: (bytes: Uint8Array) => Uint8Array,
  terminalCode: (value: string) => boolean, parse = readPoolStorageValue): void {
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
  const array = (value: Value | undefined, maximum: number): Value[] => {
    if (!Array.isArray(value) || value.length > maximum) return invalid(); return value;
  };
  const identifier = (value: Value | undefined): string => {
    if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._:/@-]{0,127}$/u.test(value)) return invalid(); return value;
  };
  const matchesDigest = (bytes: Uint8Array, expected: Uint8Array, digest = hash): void => {
    const result = digest(bytes); try { require(same(result, expected)); } finally { result.fill(0); }
  };
  const journal = map(parse(encoded, 1 << 20, 4096));
  require(journal.size === (journal.has(6) ? 10 : 9));
  require(uint(journal.get(0)) === 2n && same(data(journal.get(2), 16), key) && typeof journal.get(8) === "boolean");
  const tenant = identifier(journal.get(1));
  const next = uint(journal.get(3), 1n), retired = uint(journal.get(4)), frontier = uint(journal.get(5));
  require(retired < next);
  type Receipt = { sequence: bigint; generation: bigint; expiry: bigint; digest: Uint8Array; identity: Uint8Array };
  const receipt = (value: Value): Receipt => {
    const fields = map(value, 5);
    const entry = { sequence: uint(fields.get(0), 1n, frontier), generation: uint(fields.get(1), 1n, epoch), expiry: uint(fields.get(2), 1n),
      digest: data(fields.get(3), 32), identity: data(fields.get(4), 32) };
    require(entry.digest.some(value => value !== 0) && entry.identity.some(value => value !== 0)); return entry;
  };
  const sameReceipt = (a: Receipt, b: Receipt): boolean => a.sequence === b.sequence && a.generation === b.generation && a.expiry === b.expiry && same(a.digest, b.digest) && same(a.identity, b.identity);
  const applied = array(journal.get(9), 64).map(receipt);
  let previous = 0n;
  for (const entry of applied) { require(entry.sequence > previous); previous = entry.sequence; }
  require(previous === frontier);
  if (journal.has(6)) {
    const pending = map(journal.get(6));
    const id = data(pending.get(0), 16), state = uint(pending.get(1), 0n, 3n), desired = uint(pending.get(2), 1n, 4n), maximum = uint(pending.get(3), 1n, 65536n);
    const pool = data(pending.get(4), 32), generation = uint(pending.get(5), 1n, epoch), deadline = uint(pending.get(6));
    const certificate = data(pending.get(7)), identity = data(pending.get(8), 32), requestDigest = data(pending.get(9), 32);
    const originalFrontier = uint(pending.get(16), 0n, frontier), attemptGeneration = uint(pending.get(17), generation, epoch);
    require(certificate.length > 0 && certificate.length <= 8192); matchesDigest(certificate, identity, certificateDigest);
    // This is the original client certificate retained by the source. Check
    // immutable shape and binding only; its validity window can be historical.
    const client = map(parse(certificate, 8192), 17);
    for (let index = 0; index < 17; index++) require(client.has(index));
    require(identifier(client.get(0)) === tenant && uint(client.get(5)) === 0n && uint(client.get(8)) < uint(client.get(9)));
    for (const field of [1, 6, 10, 13]) identifier(client.get(field));
    for (const field of [11, 12, 14]) uint(client.get(field));
    data(client.get(4), 32); data(client.get(7), 16); data(client.get(15), 32); data(client.get(16), 64);
    const profile = client.get(2), noise = map(client.get(3), 2), algorithm = uint(noise.get(0), 0n, 1n);
    require(profile === (algorithm === 0n ? "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1" : "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1"));
    const publicKey = data(noise.get(1), algorithm === 0n ? 32 : 65);
    require(algorithm === 0n || publicKey[0] === 4);
    let optional = 0;
    for (let index = 10; index <= 15; index++) if (pending.has(index)) optional++;
    require(pending.size === 12 + optional);
    if (pending.has(10)) data(pending.get(10), 32);
    if (pending.has(11)) uint(pending.get(11));
    if (pending.has(12)) require(typeof pending.get(12) === "boolean");
    if (pending.has(13)) uint(pending.get(13));
    if (pending.has(14)) require(typeof pending.get(14) === "string" && terminalCode(pending.get(14) as string));
    if (state === 0n) require(optional === 0 && originalFrontier === frontier);
    if (state === 1n || state === 2n) require([10, 11, 12, 15].every(field => pending.has(field)) && pending.get(12) === pending.has(13) && !pending.has(14));
    if (state === 3n) require(pending.has(14));
    if (pending.has(15)) {
      const entries = array(pending.get(15), 4).map(receipt), highest = uint(pending.get(11));
      require(BigInt(entries.length) === desired && highest === frontier && highest >= desired);
      let sequence = highest - desired + 1n, receiptGeneration = 0n;
      require(pending.has(13) ? uint(pending.get(13)) >= originalFrontier && sequence === uint(pending.get(13)) + 1n : sequence === originalFrontier + 1n);
      for (const entry of entries) {
        require(entry.sequence === sequence++ && entry.generation >= generation && entry.generation <= attemptGeneration && same(entry.identity, identity));
        if (receiptGeneration === 0n) receiptGeneration = entry.generation;
        require(entry.generation === receiptGeneration && applied.some(original => sameReceipt(original, entry)));
      }
    }
    const sequence = new DataView(id.buffer, id.byteOffset, 8).getBigUint64(0);
    require(sequence + 1n === next && (sequence > retired || state === 2n || state === 3n));
    // Hash the original canonical intent using the same finite fields as its
    // writer. Scratch space is bounded independently of journal/material size.
    const scratch = new Uint8Array(16384); let offset = 0;
    const head = (major: number, value: bigint): void => {
      if (value < 24n) { scratch[offset++] = major * 32 + Number(value); return; }
      const width = value <= 255n ? 1 : value <= 65535n ? 2 : value <= 0xffffffffn ? 4 : 8;
      scratch[offset++] = major * 32 + (width === 1 ? 24 : width === 2 ? 25 : width === 4 ? 26 : 27);
      for (let index = width - 1; index >= 0; index--) scratch[offset++] = Number(value >> BigInt(index * 8) & 255n);
    };
    const blob = (value: Uint8Array, major = 2): void => { head(major, BigInt(value.length)); require(offset + value.length <= scratch.length); scratch.set(value, offset); offset += value.length; };
    try {
      head(5, 8n); head(0, 0n); blob(id); head(0, 1n); blob(new TextEncoder().encode(tenant), 3);
      head(0, 2n); blob(key); head(0, 3n); head(0, desired); head(0, 4n); head(0, maximum);
      head(0, 5n); blob(pool); head(0, 8n); head(0, deadline); head(0, 9n); blob(identity);
      matchesDigest(scratch.subarray(0, offset), requestDigest);
    } finally { scratch.fill(0); }
  }
  previous = 0n;
  for (const value of array(journal.get(7), 16)) {
    const material = map(value, 6), sequence = uint(material.get(0), 1n, frontier), bytes = data(material.get(3));
    const entry = { sequence, generation: uint(material.get(1), 1n, epoch), expiry: uint(material.get(2), 1n), digest: data(material.get(4), 32), identity: data(material.get(5), 32) };
    require(sequence > previous && bytes.length > 0 && bytes.length <= 65536 && applied.some(original => sameReceipt(original, entry)));
    matchesDigest(bytes, entry.digest); previous = sequence;
  }
}
