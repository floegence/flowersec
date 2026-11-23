import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const read = (relative) => readFileSync(path.join(root, relative), "utf8");
const json = (relative) => JSON.parse(read(relative));
const registry = json("stability/transport_v5_contract.json");
assert.equal(registry.version, 5);
assert.equal(registry.design.version, "5.0.0");
assert.equal(registry.design.source_path, "docs/TRANSPORT_V5_WIRE.md");
const design = read(registry.design.source_path);
assert.equal(createHash("sha256").update(design).digest("hex"), registry.design.sha256);
assert.deepEqual(registry.profiles, { session: "flowersec/5", direct: "flowersec-direct/5", tunnel: "flowersec-tunnel/5" });
assert.deepEqual(registry.version_isolation.accepted_artifact_versions, [5]);
assert.equal(registry.version_isolation.wire_negotiation, false);
for (const identifier of [...Object.values(registry.profiles), ...Object.values(registry.routes)]) {
  assert.ok(design.includes(`| ${identifier} |`), `wire contract omits ${identifier}`);
}

const commands = new Map([
  ...["generate_contract_vectors", "validate_application_vectors", "generate_crypto_vectors", "generate_handshake_vectors"].map((name) => {
    const script = `testdata/transport_v5/${name}.mjs`;
    return [script, ["node", script, "--check"]];
  }),
  ["flowersec-go/internal/cmd/issuer-admission-vectors/main.go", ["go", "-C", "flowersec-go", "run", "./internal/cmd/issuer-admission-vectors", "--check"]],
]);
assert.deepEqual(registry.fixture_generation.map(({ producer }) => producer), [...commands.keys()]);
const outputs = registry.fixture_generation.flatMap(({ outputs }) => outputs);
assert.equal(new Set(outputs).size, outputs.length, "duplicate v5 fixture owner");
assert.deepEqual([...outputs].sort(), registry.wire_fixtures.map(({ path }) => path).sort());
for (const { producer, check_command } of registry.fixture_generation) {
  assert.deepEqual(check_command, commands.get(producer));
  const [binary, ...args] = check_command;
  const result = spawnSync(binary === "node" ? process.execPath : binary, args, { cwd: root, encoding: "utf8" });
  assert.equal(result.status, 0, `${producer}: ${result.error ?? result.stderr + result.stdout}`);
}

const browser = json("testdata/transport_v5/capability_vectors.json").exact_browser_pin_provider;
assert.equal(browser.playwright, json("flowersec-ts/package.json").devDependencies["@playwright/test"]);
assert.equal(browser.full_version, "151.0.7922.34");
const issuer = json("testdata/transport_v5/go_issuer_admission_vectors.json");
assert.equal(issuer.version, 5);
assert.equal(JSON.parse(issuer.artifact_json).profile, registry.profiles.session);
assert.ok(issuer.fsb5_hex.startsWith("4653423505"));
assert.match(read("docs/TRANSPORT_V5_ARCHITECTURE.md"), /Flowersec 7 endpoints speak `flowersec\/5`/u);
for (const [file, definition] of [
  ["flowersec-go/internal/protocolv3/handshake_wire.go", /message\.Profile != "flowersec\/5"/u],
  ["flowersec-ts/src/v3/transportConstants.ts", /FLOWERSEC_V3_PROFILE = "flowersec\/5"/u],
  ["flowersec-rust/src/transport_v3.rs", /SESSION_PROFILE_V3: &str = "flowersec\/5"/u],
  ["flowersec-swift/Sources/Flowersec/TransportV3.swift", /sessionProfile = "flowersec\/5"/u],
]) assert.match(read(file), definition, `${file} changed its production profile`);

console.log(`Transport v5 product wire and ${outputs.length} generated fixtures verified`);
