import type { ProxyFetchRequest } from "./types.js";
interface Association { readonly context: string | undefined; readonly generation?: number; readonly requestOrigin?: string; readonly signal?: AbortSignal; }
const requests = new WeakMap<ProxyFetchRequest, Association>();
/** These facts are SDK admission custody, never parsed from a content request. */
export function bindProxyRequestAssociation(request: ProxyFetchRequest, association: Association): void {
  if (requests.has(request)) throw new Error("request_association_already_bound"); requests.set(request, Object.freeze({ ...association }));
}
export function proxyRequestAssociation(request: ProxyFetchRequest): Association | undefined { return requests.get(request); }
