import type { Header } from "./types.js";

const DEFAULT_REQUEST_HEADER_ALLOWLIST = new Set<string>([
  "accept",
  "accept-language",
  "cache-control",
  "content-type",
  "if-match",
  "if-modified-since",
  "if-none-match",
  "if-unmodified-since",
  "pragma",
  "range",
  "x-requested-with"
]);

const DEFAULT_RESPONSE_HEADER_ALLOWLIST = new Set<string>([
  "cache-control",
  "content-disposition",
  "content-encoding",
  "content-language",
  "content-type",
  "etag",
  "expires",
  "last-modified",
  "location",
  "pragma",
  "vary",
  "www-authenticate",
  "set-cookie"
]);

const DEFAULT_WS_HEADER_ALLOWLIST = new Set<string>(["sec-websocket-protocol", "cookie"]);

export function normalizeHeaderName(name: string): string {
  return name.trim().toLowerCase();
}

export function isValidHeaderName(name: string): boolean {
  // Minimal RFC 7230 token validation; keep strict to avoid smuggling bugs.
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    const isAlpha = c >= 0x61 && c <= 0x7a;
    const isDigit = c >= 0x30 && c <= 0x39;
    if (isAlpha || isDigit) continue;
    // ! # $ % & ' * + - . ^ _ ` | ~
    if (c === 0x21 || c === 0x23 || c === 0x24 || c === 0x25 || c === 0x26 || c === 0x27) continue;
    if (c === 0x2a || c === 0x2b || c === 0x2d || c === 0x2e) continue;
    if (c === 0x5e || c === 0x5f || c === 0x60 || c === 0x7c || c === 0x7e) continue;
    return false;
  }
  return name.length > 0;
}

export function isSafeHeaderValue(value: string): boolean {
  return !value.includes("\r") && !value.includes("\n");
}

export type FilterHeadersOptions = Readonly<{ extraAllowed?: readonly string[] }>;

function buildExtraAllowedSet(extraAllowed: readonly string[] | undefined): Set<string> | null {
  if (extraAllowed == null || extraAllowed.length === 0) return null;
  const s = new Set<string>();
  for (const n of extraAllowed) {
    const nn = normalizeHeaderName(n);
    if (nn !== "" && isValidHeaderName(nn)) s.add(nn);
  }
  return s;
}

function isAllowed(allow: Set<string>, extra: Set<string> | null, name: string): boolean {
  return allow.has(name) || (extra != null && extra.has(name));
}

export function filterRequestHeaders(input: readonly Header[], opts: FilterHeadersOptions = {}): Header[] {
  const extra = buildExtraAllowedSet(opts.extraAllowed);
  const out: Header[] = [];
  for (const h of input) {
    const name = normalizeHeaderName(h.name);
    if (name === "" || !isValidHeaderName(name)) continue;
    if (!isSafeHeaderValue(h.value)) continue;

    // Never forward these from the client runtime.
    if (name === "host" || name === "authorization") continue;

    // Cookie is injected by the runtime CookieJar (not copied from browser cookie store).
    if (name === "cookie") continue;

    if (!isAllowed(DEFAULT_REQUEST_HEADER_ALLOWLIST, extra, name)) continue;
    out.push({ name, value: h.value });
  }
  return out;
}

export type FilterResponseResult = Readonly<{ passthrough: Header[]; setCookie: string[] }>;

export function filterResponseHeaders(input: readonly Header[], opts: FilterHeadersOptions = {}): FilterResponseResult {
  const extra = buildExtraAllowedSet(opts.extraAllowed);
  const passthrough: Header[] = [];
  const setCookie: string[] = [];
  for (const h of input) {
    const name = normalizeHeaderName(h.name);
    if (name === "" || !isValidHeaderName(name)) continue;
    if (!isSafeHeaderValue(h.value)) continue;
    if (!isAllowed(DEFAULT_RESPONSE_HEADER_ALLOWLIST, extra, name)) continue;
    if (name === "set-cookie") {
      setCookie.push(h.value);
      continue;
    }
    passthrough.push({ name, value: h.value });
  }
  return { passthrough, setCookie };
}

export function filterWsOpenHeaders(input: readonly Header[], opts: FilterHeadersOptions = {}): Header[] {
  const extra = buildExtraAllowedSet(opts.extraAllowed);
  const out: Header[] = [];
  for (const h of input) {
    const name = normalizeHeaderName(h.name);
    if (name === "" || !isValidHeaderName(name)) continue;
    if (!isSafeHeaderValue(h.value)) continue;
    if (!isAllowed(DEFAULT_WS_HEADER_ALLOWLIST, extra, name)) continue;
    out.push({ name, value: h.value });
  }
  return out;
}

