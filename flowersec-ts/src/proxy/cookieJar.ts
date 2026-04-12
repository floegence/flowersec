type Cookie = Readonly<{
  name: string;
  value: string;
  path: string;
  expiresAtMs?: number;
  createdAtSeq: number;
}>;

function nowMs(): number {
  return Date.now();
}

function parseCookieNameValue(s: string): { name: string; value: string } | null {
  const idx = s.indexOf("=");
  if (idx <= 0) return null;
  const name = s.slice(0, idx).trim();
  const value = s.slice(idx + 1).trim();
  if (name === "") return null;
  return { name, value };
}

function cookieStorageKey(name: string, path: string): string {
  return `${name}\u0000${path}`;
}

function requestPathOnly(path: string): string {
  const raw = path.trim();
  if (!raw.startsWith("/")) return "/";
  const q = raw.indexOf("?");
  const out = q >= 0 ? raw.slice(0, q) : raw;
  return out === "" ? "/" : out;
}

function defaultCookiePathFromRequestPath(requestPath: string): string {
  const path = requestPathOnly(requestPath);
  if (path === "/") return "/";
  const lastSlash = path.lastIndexOf("/");
  if (lastSlash <= 0) return "/";
  return path.slice(0, lastSlash);
}

function normalizeCookiePath(pathAttr: string | undefined, requestPath: string): string {
  const path = pathAttr?.trim() ?? "";
  if (path === "" || !path.startsWith("/")) return defaultCookiePathFromRequestPath(requestPath);
  return path;
}

function pathMatchesCookiePath(requestPath: string, cookiePath: string): boolean {
  const path = requestPathOnly(requestPath);
  if (cookiePath === "/") return true;
  if (path === cookiePath) return true;
  if (!path.startsWith(cookiePath)) return false;
  if (cookiePath.endsWith("/")) return true;
  return path.charAt(cookiePath.length) === "/";
}

function compareCookiesForHeader(a: Cookie, b: Cookie): number {
  const pathLenDiff = b.path.length - a.path.length;
  if (pathLenDiff !== 0) return pathLenDiff;
  return a.createdAtSeq - b.createdAtSeq;
}

export class CookieJar {
  private readonly cookies = new Map<string, Cookie>();
  private nextCreatedAtSeq = 0;

  setCookie(setCookieHeader: string, requestPath = "/"): void {
    const raw = setCookieHeader.trim();
    if (raw === "") return;

    const parts = raw.split(";").map((p) => p.trim()).filter((p) => p !== "");
    if (parts.length === 0) return;

    const nv = parseCookieNameValue(parts[0] ?? "");
    if (nv == null) return;

    let pathAttr: string | undefined;
    let expiresAtMs: number | undefined;
    let maxAgeSeen = false;

    for (let i = 1; i < parts.length; i++) {
      const p = parts[i]!;
      const lower = p.toLowerCase();
      if (lower.startsWith("path=")) {
        const v = p.slice("path=".length).trim();
        if (v !== "") pathAttr = v;
        continue;
      }
      if (lower.startsWith("max-age=")) {
        const v = p.slice("max-age=".length).trim();
        const n = Number.parseInt(v, 10);
        if (!Number.isFinite(n)) continue;
        maxAgeSeen = true;
        expiresAtMs = n <= 0 ? 0 : nowMs() + n * 1000;
        continue;
      }
      if (lower.startsWith("expires=")) {
        if (maxAgeSeen) continue;
        const v = p.slice("expires=".length).trim();
        const t = Date.parse(v);
        if (!Number.isFinite(t)) continue;
        expiresAtMs = t;
        continue;
      }
    }

    const path = normalizeCookiePath(pathAttr, requestPath);
    const key = cookieStorageKey(nv.name, path);

    if (expiresAtMs != null && expiresAtMs <= nowMs()) {
      this.cookies.delete(key);
      return;
    }

    const createdAtSeq = this.cookies.get(key)?.createdAtSeq ?? this.nextCreatedAtSeq++;
    if (expiresAtMs == null) {
      this.cookies.set(key, { name: nv.name, value: nv.value, path, createdAtSeq });
    } else {
      this.cookies.set(key, { name: nv.name, value: nv.value, path, expiresAtMs, createdAtSeq });
    }
  }

  updateFromSetCookieHeaders(headers: readonly string[], requestPath = "/"): void {
    for (const h of headers) this.setCookie(h, requestPath);
  }

  getCookieHeader(path: string): string {
    const now = nowMs();
    const matched: Cookie[] = [];
    for (const [key, c] of this.cookies.entries()) {
      if (c.expiresAtMs != null && c.expiresAtMs <= now) {
        this.cookies.delete(key);
        continue;
      }
      if (!pathMatchesCookiePath(path, c.path)) continue;
      matched.push(c);
    }
    matched.sort(compareCookiesForHeader);
    return matched.map((c) => `${c.name}=${c.value}`).join("; ");
  }
}
