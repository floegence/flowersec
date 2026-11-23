export function resolveProxyTarget(upstream: URL, path: string): URL | undefined {
  if (!path.startsWith("/") || path.startsWith("//") || path.includes("://") || path.includes("#") || /[\u0000-\u0020\u007f]/u.test(path) || path.trim() !== path) return undefined;
  try {
    const target = new URL(path, upstream);
    if (target.origin !== upstream.origin || target.username || target.password || target.pathname.startsWith("//")) return undefined;
    return target;
  } catch { return undefined; }
}
