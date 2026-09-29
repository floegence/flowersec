import { transportV4ProxyApplicationRegistry } from "../generated/transportV4Registry.js";
import type { ProxyHeader } from "./types.js";

const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const octets = /^[\x09\x20-\x7e\x80-\xff]*$/u;
const singletons = new Set(["host", "origin", "authorization", "proxy-authorization", "content-type", "content-range", "etag", "last-modified", "location"]);
const trimOWS = (value: string): string => value.replace(/^[ \t]+|[ \t]+$/gu, "");

export type ProxyHeaderFacts = Readonly<{
  fields: readonly ProxyHeader[];
  connection: ReadonlySet<string>;
  contentLength: bigint | undefined;
  transferEncoding: boolean;
}>;

// Capture and validate the complete original field list before any policy
// filtering. In particular, Connection cannot erase a length assertion or a
// conflicting transfer coding. Values remain exact HTTP octets.
export function inspectProxyHeaders(input: readonly ProxyHeader[]): ProxyHeaderFacts {
  if (!Array.isArray(input) || input.length > transportV4ProxyApplicationRegistry.max_field_count) throw new Error("invalid HTTP field list");
  const fields: ProxyHeader[] = [];
  const connection = new Set<string>();
  const seen = new Map<string, string>();
  let contentLength: bigint | undefined;
  let transferEncoding = false;
  for (const entry of input) {
    const rawName = entry?.name, value = entry?.value;
    if (typeof rawName !== "string" || !token.test(rawName) || typeof value !== "string" || !octets.test(value)) throw new Error("invalid HTTP field");
    const name = rawName.toLowerCase();
    fields.push(Object.freeze({ name, value }));
    if (name === "content-length") {
      for (const item of value.split(",")) {
        const decimal = trimOWS(item);
        if (!/^[0-9]+$/u.test(decimal)) throw new Error("invalid content length");
        // Accumulate into a fixed integer bound, avoiding a peer-sized BigInt.
        let length = 0n;
        for (const digit of decimal) {
          length = length * 10n + BigInt(digit.charCodeAt(0) - 48);
          if (length > 0x7fff_ffff_ffff_ffffn) throw new Error("content length overflow");
        }
        if (contentLength !== undefined && contentLength !== length) throw new Error("conflicting content length");
        contentLength = length;
      }
    } else if (name === "transfer-encoding") {
      if (transferEncoding || trimOWS(value).toLowerCase() !== "chunked") throw new Error("invalid transfer coding");
      transferEncoding = true;
    } else if (name === "connection") {
      for (const part of value.split(",")) {
        const name = trimOWS(part).toLowerCase();
        if (!token.test(name)) throw new Error("invalid connection token");
        connection.add(name);
      }
    }
    if (singletons.has(name)) {
      const current = trimOWS(value), previous = seen.get(name);
      if (previous !== undefined && previous !== current) throw new Error("conflicting singleton");
      seen.set(name, current);
    }
  }
  if (transferEncoding && contentLength !== undefined) throw new Error("conflicting transfer framing");
  return Object.freeze({ fields: Object.freeze(fields), connection, contentLength, transferEncoding });
}
