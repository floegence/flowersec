export class InvalidProxyPathError extends TypeError {}

export function normalizePath(input: string): string {
  if (input !== input.trim() || !input.startsWith("/") || input.startsWith("//") || /[\u0000-\u0020]/u.test(input) || input.includes("://") || input.includes("#")) {
    throw new InvalidProxyPathError("proxy path must be an origin-relative path");
  }
  let parsed: URL;
  try {
    parsed = new URL(input, "https://flowersec.invalid/");
  } catch {
    throw new InvalidProxyPathError("proxy path must be an origin-relative path");
  }
  const pathname = normalizePercentEscapes(parsed.pathname, true).replace(/\/{2,}/gu, "/");
  const search = normalizePercentEscapes(parsed.search, false);
  return pathname + search;
}

function normalizePercentEscapes(input: string, rejectEncodedSeparators: boolean): string {
  if (/%(?![0-9a-f]{2})/iu.test(input)) throw new InvalidProxyPathError("proxy path contains invalid percent encoding");
  return input.replace(/%([0-9a-f]{2})/giu, (_match, hex: string) => {
    const value = Number.parseInt(hex, 16);
    if (rejectEncodedSeparators && (value === 0x2f || value === 0x5c)) {
      throw new InvalidProxyPathError("proxy path contains an encoded separator");
    }
    const character = String.fromCharCode(value);
    return /[A-Za-z0-9\-._~]/u.test(character) ? character : `%${hex.toUpperCase()}`;
  });
}

export function normalizePrefixes(name: string, values: readonly string[] | undefined): readonly string[] {
  const result: string[] = [];
  for (const raw of values ?? []) {
    const value = normalizePath(raw);
    if (value.includes("?")) throw new TypeError(`${name} must not include a query`);
    if (!result.includes(value)) result.push(value);
  }
  return Object.freeze(result);
}

export const FORBIDDEN_HEADERS = new Set(["authorization", "connection", "cookie", "host", "keep-alive", "proxy-authorization", "set-cookie", "transfer-encoding", "upgrade"]);

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

