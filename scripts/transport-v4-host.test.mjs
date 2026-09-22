import assert from "node:assert/strict";
import test from "node:test";
import { issuerHost151, validateWireHost151 } from "./transport-v4-host.mjs";

test("host grammar preserves DNS/IPv4 distinctions and rejects URL aliases", () => {
  const cases = [
    ["BÜCHER.example", "xn--bcher-kva.example"], ["example.0xg", "example.0xg"],
    ["127.0.0.1", "127.0.0.1"], ["0.0.0.0", "0.0.0.0"], ["255.255.255.255", "255.255.255.255"],
  ];
  for (const [input, output] of cases) {
    assert.equal(issuerHost151(input), output);
    assert.equal(validateWireHost151(output), output);
    assert.equal(new URL(`https://${output}/`).hostname, output);
  }
  for (const host of ["127.1", "2130706433", "0x7f000001", "0177.0.0.1", "127.0.0.01", "256.0.0.1", "127.0.0.1.", "example.123", "example.0x123", "example.0x", "example.09", "example.0XFF", "１２７.０.０.１", "example.com.", "a..b", "localhost:443", "example.com/", "a\\b", "a@b", "a%2eb", "a?b", "a#b", " a", "a\n", "", "[::1]", "fe80::1%en0"]) {
    assert.throws(() => issuerHost151(host), undefined, host);
    assert.throws(() => validateWireHost151(host), undefined, host);
  }
  assert.throws(() => validateWireHost151("BÜCHER.example"), /host_wire_ascii/u);
  assert.throws(() => validateWireHost151("EXAMPLE.com"), /host_noncanonical/u);
});

test("IPv6 has one all-hex spelling, including mapped addresses", () => {
  for (const [input, output] of [
    ["0:0:0:0:0:0:0:0", "::"], ["0:0:0:0:0:0:0:1", "::1"],
    ["2001:0DB8:0000:0000:0001:0000:0000:0001", "2001:db8::1:0:0:1"],
    ["2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"],
    ["1:0:0:2:0:0:0:3", "1:0:0:2::3"], ["1:2:3:4:5:6:0:0", "1:2:3:4:5:6::"],
    ["::ffff:192.0.2.1", "::ffff:c000:201"], ["::192.0.2.1", "::c000:201"],
    ["1:2:3:4:5:6:192.0.2.1", "1:2:3:4:5:6:c000:201"],
  ]) {
    assert.equal(issuerHost151(input), output, input);
    assert.equal(validateWireHost151(output), output);
    assert.equal(new URL(`https://[${input}]/`).hostname, `[${output}]`);
    if (input !== output) assert.throws(() => validateWireHost151(input), /host_noncanonical/u, input);
  }
  for (const input of [":", ":::1", "1::2::3", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7::8", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "12345::", "::g", "::ffff:192.000.2.1", "::ffff:0xc0.0.2.1", "::ffff:192.0.2", "1:2:3:4:5:6:7:192.0.2.1"]) assert.throws(() => issuerHost151(input), undefined, input);
});

test("canonical host output agrees with an independent URL parser", () => {
  let state = 0x425dfc12;
  const next = () => { state ^= state << 13; state ^= state >>> 17; state ^= state << 5; return state >>> 0; };
  for (let i = 0; i < 4096; i++) {
    const words = Array.from({length:8}, () => next() % 4 === 0 ? 0 : next() & 65535);
    const input = words.map(word => word.toString(16).padStart(4,"0").toUpperCase()).join(":");
    const output = issuerHost151(input);
    assert.equal(new URL(`https://[${input}]/`).hostname, `[${output}]`, input);
    assert.equal(validateWireHost151(output), output);
    const v4 = Array.from({length:4}, () => next() & 255).join(".");
    assert.equal(validateWireHost151(v4), new URL(`https://${v4}/`).hostname);
  }
});
