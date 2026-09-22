// Reference host grammar. The issuer may canonicalize DNS and IPv6 input;
// received signed fields must already have the unique canonical spelling.
import { issuerDNS151 } from "./transport-v4-idna.mjs";

export class HostValidationError extends Error {}
const requireThat = (condition, code) => { if (!condition) throw new HostValidationError(code); };

function ipv4(text) {
  const parts = text.split(".");
  requireThat(parts.length === 4 && parts.every(part => /^(?:0|[1-9][0-9]{0,2})$/u.test(part) && Number(part) <= 255), "host_ipv4");
  return parts.map(Number);
}

function ipv6(text) {
  // Dotted tails are unambiguous issuer input, but never a wire spelling.
  if (text.includes(".")) {
    const lastColon = text.lastIndexOf(":");
    const tail = ipv4(text.slice(lastColon + 1));
    text = text.slice(0, lastColon + 1) + ((tail[0] << 8) | tail[1]).toString(16) + ":" + ((tail[2] << 8) | tail[3]).toString(16);
  }
  const halves = text.split("::");
  requireThat(halves.length <= 2, "host_ipv6");
  const read = half => {
    if (half === "") return [];
    const words = half.split(":");
    requireThat(words.every(word => /^[0-9a-fA-F]{1,4}$/u.test(word)), "host_ipv6");
    return words.map(word => Number.parseInt(word, 16));
  };
  const left = read(halves[0]), right = halves.length === 2 ? read(halves[1]) : [];
  const missing = 8 - left.length - right.length;
  requireThat(halves.length === 2 ? missing >= 1 : missing === 0, "host_ipv6");
  const words = [...left, ...Array(missing).fill(0), ...right];
  let bestStart = -1, bestLength = 1;
  for (let start = 0; start < 8;) {
    if (words[start] !== 0) { start++; continue; }
    let end = start;
    while (end < 8 && words[end] === 0) end++;
    if (end - start > bestLength) { bestStart = start; bestLength = end - start; }
    start = end;
  }
  const hex = words.map(word => word.toString(16));
  if (bestStart < 0) return hex.join(":");
  return hex.slice(0, bestStart).join(":") + "::" + hex.slice(bestStart + bestLength).join(":");
}

export function issuerHost151(text) {
  requireThat(typeof text === "string" && text.length > 0, "host_text");
  requireThat(!/[\s\[\]%\\/?#@]/u.test(text), "host_syntax");
  if (text.includes(":")) return ipv6(text);
  if (/^[0-9.]+$/u.test(text)) return ipv4(text).join(".");
  const dns = issuerDNS151(text), last = dns.slice(dns.lastIndexOf(".") + 1);
  requireThat(!/^(?:[0-9]+|0x[0-9a-f]*)$/u.test(last), "host_numeric_final_label");
  return dns;
}

export function validateWireHost151(text) {
  requireThat(typeof text === "string" && /^[\x00-\x7f]+$/u.test(text), "host_wire_ascii");
  requireThat(issuerHost151(text) === text, "host_noncanonical");
  return text;
}

export function validateWireLoopbackHost151(text) {
  validateWireHost151(text);
  requireThat(text === "::1" || /^127(?:\.[0-9]{1,3}){3}$/u.test(text), "host_loopback");
  return text;
}
