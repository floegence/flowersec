type Cookie = Readonly<{
  name: string;
  value: string;
  path: string;
  expiresAtMs?: number;
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

export class CookieJar {
  private readonly cookies = new Map<string, Cookie>();

  setCookie(setCookieHeader: string): void {
    const raw = setCookieHeader.trim();
    if (raw === "") return;

    const parts = raw.split(";").map((p) => p.trim()).filter((p) => p !== "");
    if (parts.length === 0) return;

    const nv = parseCookieNameValue(parts[0] ?? "");
    if (nv == null) return;

    let path = "/";
    let expiresAtMs: number | undefined;

    for (let i = 1; i < parts.length; i++) {
      const p = parts[i]!;
      const lower = p.toLowerCase();
      if (lower.startsWith("path=")) {
        const v = p.slice("path=".length).trim();
        if (v !== "") path = v;
        continue;
      }
      if (lower.startsWith("max-age=")) {
        const v = p.slice("max-age=".length).trim();
        const n = Number.parseInt(v, 10);
        if (!Number.isFinite(n)) continue;
        if (n <= 0) {
          this.cookies.delete(nv.name);
          return;
        }
        expiresAtMs = nowMs() + n * 1000;
        continue;
      }
      if (lower.startsWith("expires=")) {
        const v = p.slice("expires=".length).trim();
        const t = Date.parse(v);
        if (!Number.isFinite(t)) continue;
        expiresAtMs = t;
        continue;
      }
    }

    // Expired via Expires.
    if (expiresAtMs != null && expiresAtMs <= nowMs()) {
      this.cookies.delete(nv.name);
      return;
    }

    if (expiresAtMs == null) {
      this.cookies.set(nv.name, { name: nv.name, value: nv.value, path });
    } else {
      this.cookies.set(nv.name, { name: nv.name, value: nv.value, path, expiresAtMs });
    }
  }

  updateFromSetCookieHeaders(headers: readonly string[]): void {
    for (const h of headers) this.setCookie(h);
  }

  getCookieHeader(path: string): string {
    const now = nowMs();
    const pairs: string[] = [];
    for (const c of this.cookies.values()) {
      if (c.expiresAtMs != null && c.expiresAtMs <= now) {
        this.cookies.delete(c.name);
        continue;
      }
      if (c.path !== "/" && !path.startsWith(c.path)) continue;
      pairs.push(`${c.name}=${c.value}`);
    }
    return pairs.join("; ");
  }
}
