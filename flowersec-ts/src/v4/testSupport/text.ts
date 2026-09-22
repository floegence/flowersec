// Signed text syntax; actual DNS/TLS/Origin request admission is separate.
import { own } from "./cbor.js";
import type { Field, Value } from "./cbor.js";
import { emptyContext, integer, record } from "./shape.js";
import type { Context } from "./shape.js";
import { array, string } from "./rules.js";
import { Relations } from "./relations.js";
import { IDNA, points } from "./idna.js";
import { V4Failure } from "./unicode.js";

export class TextReference extends Relations {
  readonly idna = new IDNA(this.syntax);

  issuerHost(input: string): string {
    if (!input.length) throw new V4Failure("host_text");
    const forbidden = new Set([32, 91, 93, 37, 92, 47, 63, 35, 64, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);
    if (points(input).some(cp => cp >= 9 && cp <= 13 || cp >= 0x2000 && cp <= 0x200a || forbidden.has(cp))) throw new V4Failure("host_syntax");
    if (input.includes(":")) {
      const words = ipv6(input); if (!words) throw new V4Failure("host_ipv6"); return ipv6Hex(words);
    }
    if (!/[^0-9.]/u.test(input)) {
      const octets = ipv4(input); if (!octets) throw new V4Failure("host_ipv4"); return octets.join(".");
    }
    const dns = this.idna.issuerDNS(input), last = dns.split(".").at(-1)!;
    if (!/[^0-9]/u.test(last) || last.startsWith("0x") && !/[^0-9a-f]/u.test(last.slice(2))) throw new V4Failure("host_numeric_final_label");
    return dns;
  }

  wireHost(input: string): void {
    if (!input.length || /[^\x00-\x7f]/u.test(input)) throw new V4Failure("host_wire_ascii");
    if (this.issuerHost(input) !== input) throw new V4Failure("host_noncanonical");
  }

  private defaultPort(scheme: string): bigint {
    const entry = own(record(this.fieldRegistry("origin_schemes")), scheme);
    if (entry === undefined) throw new V4Failure("origin_scheme_unregistered"); return integer(record(entry).default_port);
  }

  wireOrigin(input: string): void {
    if (!input.length || /[^\x21-\x7e]/u.test(input)) throw new V4Failure("origin_ascii");
    const parts = input.split("://"), scheme = parts[0]!;
    if (parts.length !== 2 || !/^[a-z]/u.test(scheme) || /[^a-z0-9+.-]/u.test(scheme)) throw new V4Failure("origin_syntax");
    const defaultValue = this.defaultPort(scheme), authority = parts[1]!;
    let host: string, port: string | undefined;
    if (authority.startsWith("[")) {
      const pair = authority.split("]");
      if (pair.length !== 2) throw new V4Failure("origin_syntax"); host = pair[0]!.slice(1);
      if (!host.includes(":") || /[^0-9a-f:]/u.test(host)) throw new V4Failure("origin_syntax");
      if (pair[1]!.length) {
        if (!pair[1]!.startsWith(":")) throw new V4Failure("origin_syntax"); port = pair[1]!.slice(1);
      }
    } else {
      const pair = authority.split(":");
      if (pair.length > 2) throw new V4Failure("origin_syntax"); [host, port] = [pair[0]!, pair[1]];
    }
    this.wireHost(host);
    if (port !== undefined) {
      if (!port.length || /[^0-9]/u.test(port) || port.length > 1 && port[0] === "0" || port.length > 5 || Number(port) > 65535) throw new V4Failure("origin_port");
      if (BigInt(port) === defaultValue) throw new V4Failure("origin_default_port");
    }
  }

  private format(name: string, input: string): void {
    if (name === "host") this.wireHost(input);
    else if (name === "origin") this.wireOrigin(input);
    else if (name === "loopback_host") {
      this.wireHost(input);
      if (input !== "::1" && ipv4(input)?.[0] !== 127) throw new V4Failure("host_loopback");
    } else throw new V4Failure("text_format_unresolved");
  }

  private fieldFormats(original: Field, value: Value, context: Context): void {
    const field = this.selectedField(original, context);
    if (field.text_format) {
      if (value.kind !== "text") throw new V4Failure("field_type"); return this.format(field.text_format, value.value);
    }
    if (field.type === "array") {
      if (value.kind !== "array" || !field.items) throw new V4Failure("field_type");
      for (const item of value.value) this.fieldFormats(field.items, item, context);
    } else if (field.type === "text_map") {
      if (value.kind !== "map" || !field.keys) throw new V4Failure("map_type");
      for (const [key, item] of value.value) {
        this.fieldFormats(field.keys, key, context);
        if (key.kind !== "text") throw new V4Failure("field_type");
        const child = field.entries ? own(field.entries, key.value) : field.values;
        if (!child) throw new V4Failure("registry_unresolved"); this.fieldFormats(child, item, context);
      }
    }
    // The shared walker visits map and embedded children under their own scope.
  }

  private checkText(name: string, value: Value, context: Context): void {
    if (value.kind !== "map") throw new V4Failure("map_type");
    const descriptor = this.descriptor(name);
    for (const [key, item] of value.value) {
      if (key.kind !== "uint") throw new V4Failure("field_id_type");
      const field = own(descriptor.fields, key.value.toString());
      if (!field) throw new V4Failure("unknown_field"); this.fieldFormats(field, item, context);
    }
    const keys = new Set(["op", "field", "format", "host", "port", "origin", "scheme", "when"]);
    for (const raw of array(own(this.registry.text_rules, name) ?? [])) {
      const rule = record(raw);
      if (Object.keys(rule).some(key => !keys.has(key))) throw new V4Failure("rule_unresolved");
      if (!this.applies(name, value, rule.when, context)) continue;
      const get = (key: string): Value => {
        const result = this.path(name, value, string(rule[key]), context);
        if (result === undefined) throw new V4Failure("unknown_rule_field"); return result;
      };
      if (rule.op === "text_format") {
        const field = get("field"); if (field.kind !== "text") throw new V4Failure("field_type"); this.format(string(rule.format), field.value);
      } else if (rule.op === "origin_endpoint") {
        const host = get("host"), port = get("port"), origin = get("origin"), scheme = string(rule.scheme);
        if (host.kind !== "text" || port.kind !== "uint" || origin.kind !== "text") throw new V4Failure("field_type");
        let expected = scheme + "://" + (host.value.includes(":") ? `[${host.value}]` : host.value);
        if (port.value !== this.defaultPort(scheme)) expected += `:${port.value}`;
        if (expected !== origin.value) throw new V4Failure("origin_endpoint");
      } else throw new V4Failure("rule_unresolved");
    }
  }

  wireMap(input: Uint8Array, name = "", context: Context = emptyContext(), cap: bigint): Value {
    const value = this.relations(input, name, context, cap);
    if (name) this.walk(name, value, context, (name, value, ctx) => this.checkText(name, value, ctx));
    return value;
  }
}

export function ipv4(input: string): number[] | undefined {
  const parts = input.split("."); if (parts.length !== 4) return undefined;
  const output: number[] = [];
  for (const part of parts) {
    if (!part.length || part.length > 3 || /[^0-9]/u.test(part) || part.length > 1 && part[0] === "0" || Number(part) > 255) return undefined;
    output.push(Number(part));
  }
  return output;
}

export function ipv6(input: string): number[] | undefined {
  const halves = input.split("::"); if (halves.length > 2) return undefined;
  function words(input: string, allowIPv4: boolean): number[] | undefined {
    if (!input.length) return [];
    const fields = input.split(":"), out: number[] = [];
    for (let i = 0; i < fields.length; i++) {
      const field = fields[i]!;
      if (field.includes(".")) {
        const octets = ipv4(field);
        if (!allowIPv4 || i !== fields.length - 1 || !octets) return undefined;
        out.push(octets[0]! * 256 + octets[1]!, octets[2]! * 256 + octets[3]!);
      } else {
        if (!field.length || field.length > 4 || /[^0-9a-f]/iu.test(field)) return undefined; out.push(Number.parseInt(field, 16));
      }
    }
    return out;
  }
  const left = words(halves[0]!, halves.length === 1); if (!left) return undefined;
  if (halves.length === 1) return left.length === 8 ? left : undefined;
  const right = words(halves[1]!, true);
  if (!right || left.length + right.length >= 8) return undefined;
  return [...left, ...new Array<number>(8 - left.length - right.length).fill(0), ...right];
}

export function ipv6Hex(words: number[]): string {
  if (words.length !== 8 || words.some(word => !Number.isInteger(word) || word < 0 || word > 65535)) throw new V4Failure("host_ipv6");
  let best: number | undefined, length = 1, index = 0;
  while (index < words.length) {
    if (words[index] !== 0) { index += 1; continue; }
    let end = index + 1;
    while (end < words.length && words[end] === 0) end += 1;
    if (end - index > length) { best = index; length = end - index; }
    index = end;
  }
  const text = words.map(word => word.toString(16));
  return best === undefined ? text.join(":") : text.slice(0, best).join(":") + "::" + text.slice(best + length).join(":");
}
