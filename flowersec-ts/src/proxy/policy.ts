export class InvalidProxyPathError extends TypeError {}

export function normalizePath(input: string): string {
  // This value is already an origin-form target: leading and repeated slashes
  // are path bytes, never another authority. Keep its spelling through dispatch.
  if (!input.startsWith("/") || /[^\x21-\x7e]/u.test(input) || input.includes("\\") || input.includes("#") || /%(?![0-9a-f]{2})/iu.test(input)) {
    throw new InvalidProxyPathError("proxy path must be an encoded origin-relative path");
  }
  return input;
}

export function normalizeSubtreePath(input: string): string {
  const path = normalizePath(input);
  const pathname = path.split("?", 1)[0]!;
  for (const segment of pathname.split("/")) {
    const decoded = decodeSegment(segment);
    if (decoded === "." || decoded === ".." || decoded.includes("/") || decoded.includes("\\") || decoded.includes("%") || /[\u0000-\u001f\u007f;?#]/u.test(decoded)) {
      throw new InvalidProxyPathError("proxy path contains a forbidden segment");
    }
  }
  return path;
}

function decodeSegment(segment: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < segment.length;) {
    const code = segment.charCodeAt(i);
    if (code === 0x25) {
      const hex = segment.slice(i + 1, i + 3);
      if (!/^[0-9a-f]{2}$/iu.test(hex)) throw new InvalidProxyPathError("proxy path contains invalid percent encoding");
      bytes.push(Number.parseInt(hex, 16)); i += 3;
    } else {
      // Origin-form paths are ASCII after URL serialization. Reject non-ASCII
      // literals instead of allowing implicit UTF-8 re-encoding to change the
      // route that was authorized.
      if (code > 0x7f) throw new InvalidProxyPathError("proxy path contains non-ASCII text");
      bytes.push(code); i++;
    }
  }
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Uint8Array.from(bytes)); }
  catch { throw new InvalidProxyPathError("proxy path contains invalid UTF-8"); }
}

export function normalizePrefixes(name: string, values: readonly string[] | undefined): readonly string[] {
  const result: string[] = [];
  for (const raw of values ?? []) {
    const value = normalizeSubtreePath(raw);
    if (value.includes("?")) throw new TypeError(`${name} must not include a query`);
    if (!result.includes(value)) result.push(value);
  }
  return Object.freeze(result);
}

/** Match a normalized origin-relative pathname against a path prefix.
 * Prefixes are segment bounded so `/api` cannot authorize `/api-private`.
 */
export function matchesPathPrefix(path: string, prefix: string): boolean {
  const pathname = path.split("?", 1)[0] ?? path;
  const candidate = pathname.split("/").map(decodeSegment);
  const root = prefix.split("/").map(decodeSegment);
  if (prefix.endsWith("/")) root.pop();
  if (candidate.length < root.length || root.some((segment, index) => candidate[index] !== segment)) return false;
  return !prefix.endsWith("/") || candidate.length > root.length;
}

// Cookie is deliberately absent from the default base sets. It becomes eligible
// only when an embedding explicitly lists it in the narrow policy allowlist;
// ambient browser/Session credentials are never synthesized. Authorization
// remains forbidden unless a future credential-specific API makes its policy
// explicit.
export const FORBIDDEN_HEADERS = new Set(["authorization", "connection", "host", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "set-cookie", "transfer-encoding", "upgrade"]);

export function normalizeHeaderNames(values: readonly string[] | undefined): ReadonlySet<string> {
  const result = new Set<string>();
  for (const raw of values ?? []) {
    const value = raw.toLowerCase().trim();
    if (!/^[!#$%&'*+\-.^_`|~0-9a-z]+$/u.test(value) || FORBIDDEN_HEADERS.has(value)) {
      throw new TypeError("proxy header allowlist contains a forbidden name");
    }
    result.add(value);
  }
  return result;
}
