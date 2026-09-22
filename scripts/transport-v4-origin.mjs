// Reference signed Origin syntax. Scheme/default-port allocations come from
// the draft registry; unknown schemes require an explicit registry decision.
import { validateWireHost151 } from "./transport-v4-host.mjs";

export class OriginValidationError extends Error {}
const requireThat = (condition, code) => { if (!condition) throw new OriginValidationError(code); };

export function validateWireOrigin(text, schema) {
  requireThat(typeof text === "string" && text.length > 0 && !/[^\x21-\x7e]/u.test(text), "origin_ascii");
  const match = /^([a-z][a-z0-9+.-]*):\/\/(\[[0-9a-f:]+\]|[^:/?#@\\\[\]]+)(?::([0-9]+))?$/u.exec(text);
  requireThat(match !== null && match[0] === text, "origin_syntax");
  const [, scheme, authorityHost, portText] = match;
  requireThat(Object.hasOwn(schema.origin_schemes, scheme), "origin_scheme_unregistered");
  const host = authorityHost.startsWith("[") ? authorityHost.slice(1, -1) : authorityHost;
  // Brackets are reserved for IPv6; the host validator preserves address
  // family and rejects aliases instead of applying URL parser corrections.
  requireThat(!authorityHost.startsWith("[") || host.includes(":"), "origin_syntax");
  validateWireHost151(host);
  if (portText !== undefined) {
    requireThat(/^(?:0|[1-9][0-9]{0,4})$/u.test(portText) && Number(portText) <= 65535, "origin_port");
    requireThat(Number(portText) !== schema.origin_schemes[scheme].default_port, "origin_default_port");
  }
  return text;
}
