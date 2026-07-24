import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const generatorPath = path.join(sourceRoot, "scripts/generate-source-inventory.mjs");

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function loadGenerator() {
  assert.ok(fs.existsSync(generatorPath), "scripts/generate-source-inventory.mjs must exist");
  return import(pathToFileURL(generatorPath));
}

function fixtureComponents() {
  return [
    {
      ecosystem: "npm",
      name: "z-package",
      version: "2.0.0",
      declaredLicense: "MIT OR Apache-2.0",
      concludedLicense: "MIT",
      source: "https://registry.npmjs.org/z-package/-/z-package-2.0.0.tgz",
      purl: "pkg:npm/z-package@2.0.0",
    },
    {
      ecosystem: "go",
      name: "example.com/a",
      version: "v1.2.3",
      declaredLicense: "BSD-3-Clause",
      concludedLicense: "BSD-3-Clause",
      source: "https://example.com/a",
      purl: "pkg:golang/example.com/a@v1.2.3",
    },
  ];
}

function fixtureGraph() {
  const components = fixtureComponents();
  return {
    root: {
      ecosystem: "npm",
      name: "@floegence/flowersec-core",
      version: "2.0.0",
      purl: "pkg:npm/%40floegence/flowersec-core@2.0.0",
    },
    components,
    edges: components.map((component) => ({
      from: "pkg:npm/%40floegence/flowersec-core@2.0.0",
      to: component.purl,
      kind: "runtime",
    })),
  };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: { ...process.env, ...options.env },
    encoding: "utf8",
    input: options.input,
    maxBuffer: 64 * 1024 * 1024,
  });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`,
  );
  return result.stdout;
}

function extractedFiles(root) {
  const files = new Map();
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile()) files.set(path.relative(root, absolute), fs.readFileSync(absolute));
    }
  }
  return files;
}

function stripArchiveRoot(files) {
  const roots = new Set([...files.keys()].map((file) => file.split(path.sep)[0]));
  assert.equal(roots.size, 1, `archive must have one root, got ${[...roots].join(", ")}`);
  const [root] = roots;
  return new Map([...files].map(([file, contents]) => [file.slice(root.length + 1), contents]));
}

function stripArchivePrefix(files, prefix) {
  const normalizedPrefix = `${prefix.split("/").join(path.sep)}${path.sep}`;
  for (const file of files.keys()) {
    assert.equal(file.startsWith(normalizedPrefix), true, `archive entry ${file} is outside ${prefix}`);
  }
  return new Map([...files].map(([file, contents]) => [file.slice(normalizedPrefix.length), contents]));
}

function assertDistributionPayload(label, files, expected, owns = (file) => (
  file === "THIRD_PARTY_NOTICES.md" || file.startsWith("sbom/")
)) {
  for (const [relative, contents] of expected) {
    assert.equal(files.has(relative), true, `${label} missing ${relative}`);
    assert.deepEqual(files.get(relative), Buffer.from(contents), `${label} stale ${relative}`);
  }
  const expectedPaths = new Set(expected.keys());
  const owned = [...files.keys()].filter(owns);
  assert.deepEqual(owned.sort(), [...expectedPaths].sort(), `${label} has unexpected owned output`);
}

function findSingleFile(root, suffix) {
  const matches = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else if (entry.isFile() && absolute.endsWith(suffix)) matches.push(absolute);
    }
  }
  assert.equal(matches.length, 1, `expected one ${suffix}, got ${matches.join(", ")}`);
  return matches[0];
}

test("source inventory output closure is explicit and package-local", async () => {
  const { requiredArtifactPaths } = await loadGenerator();
  assert.deepEqual(requiredArtifactPaths, [
    "THIRD_PARTY_NOTICES.md",
    "sbom/source-inventory.json",
    "sbom/source.spdx.json",
    "sbom/source.cyclonedx.json",
    "flowersec-go/THIRD_PARTY_NOTICES.md",
    "flowersec-go/sbom/spdx.json",
    "flowersec-go/sbom/cyclonedx.json",
    "flowersec-ts/THIRD_PARTY_NOTICES.md",
    "flowersec-ts/sbom/spdx.json",
    "flowersec-ts/sbom/cyclonedx.json",
    "flowersec-rust/THIRD_PARTY_NOTICES.md",
    "flowersec-rust/sbom/spdx.json",
    "flowersec-rust/sbom/cyclonedx.json",
    "sbom/swift/spdx.json",
    "sbom/swift/cyclonedx.json",
    ...["runtime", "runtime-image"].flatMap((kind) => [
      `release-compliance/${kind}/THIRD_PARTY_NOTICES.md`,
      `release-compliance/${kind}/SBOM_SCOPE.md`,
      `release-compliance/${kind}/sbom/spdx.json`,
      `release-compliance/${kind}/sbom/cyclonedx.json`,
    ]),
  ]);
});

test("SPDX, CycloneDX, and notices are deterministic and preserve license decisions", async () => {
  const {
    renderCycloneDx,
    renderNotice,
    renderSpdx,
    validateCycloneDxDocument,
    validateSpdxDocument,
  } = await loadGenerator();
  const graph = fixtureGraph();
  const components = graph.components;
  const spdx = renderSpdx("fixture", graph, "abc123");
  assert.equal(spdx.spdxVersion, "SPDX-2.3");
  assert.equal(spdx.packages[0].name, "@floegence/flowersec-core");
  assert.equal(spdx.packages[0].versionInfo, "2.0.0");
  assert.notEqual(spdx.packages[0].versionInfo, "abc123");
  assert.ok(spdx.relationships.some((edge) => edge.relationshipType === "DEPENDS_ON"));
  assert.equal(spdx.creationInfo.created, "1970-01-01T00:00:00Z");
  assert.doesNotThrow(() => validateSpdxDocument(spdx));

  const cyclone = renderCycloneDx("fixture", graph, "abc123");
  assert.equal(cyclone.bomFormat, "CycloneDX");
  assert.equal(cyclone.specVersion, "1.5");
  assert.equal(cyclone.metadata.component.version, "2.0.0");
  assert.notEqual(cyclone.metadata.component.version, "abc123");
  assert.equal(cyclone.components.length, 2);
  assert.ok(cyclone.serialNumber.startsWith("urn:uuid:"));
  assert.ok(cyclone.metadata.properties.some((property) => (
    property.name === "flowersec:source-inventory-sha256" && property.value === "abc123"
  )));
  assert.ok(cyclone.dependencies.some((edge) => edge.ref === graph.root.purl));
  assert.doesNotThrow(() => validateCycloneDxDocument(cyclone));

  const notice = renderNotice("fixture", components);
  assert.match(notice, /example\.com\/a v1\.2\.3/);
  assert.match(notice, /Declared: MIT OR Apache-2\.0; selected: MIT/);
  assert.equal(renderNotice("fixture", components), notice);
});

test("SBOM validators reject schema and exact dependency graph mutations", async () => {
  const {
    renderCycloneDx,
    renderSpdx,
    validateCycloneDxDocument,
    validateOfficialSbomSchema,
    validateSpdxDocument,
  } = await loadGenerator();
  const graph = fixtureGraph();
  const spdx = renderSpdx("fixture", graph, "abc123");
  assert.doesNotThrow(() => validateOfficialSbomSchema(sourceRoot, "spdx", spdx));
  const noSpdxEdges = structuredClone(spdx);
  noSpdxEdges.relationships = noSpdxEdges.relationships.filter((edge) => (
    edge.relationshipType !== "DEPENDS_ON"
  ));
  assert.throws(() => validateSpdxDocument(noSpdxEdges, graph), /depend/i);
  const unknownSpdxTarget = structuredClone(spdx);
  unknownSpdxTarget.relationships.at(-1).relatedSpdxElement = "SPDXRef-Package-unknown";
  assert.throws(() => validateSpdxDocument(unknownSpdxTarget), /unknown/i);
  const missingSpdxNamespace = structuredClone(spdx);
  delete missingSpdxNamespace.documentNamespace;
  assert.throws(() => validateSpdxDocument(missingSpdxNamespace), /schema|namespace/i);
  const missingSpdxCreationInfo = structuredClone(spdx);
  delete missingSpdxCreationInfo.creationInfo;
  assert.throws(
    () => validateOfficialSbomSchema(sourceRoot, "spdx", missingSpdxCreationInfo),
    /official spdx schema validation failed/i,
  );
  const oneMissingSpdxEdge = structuredClone(spdx);
  oneMissingSpdxEdge.relationships.splice(1, 1);
  assert.throws(() => validateSpdxDocument(oneMissingSpdxEdge, graph), /exact|depend/i);

  const cyclonedx = renderCycloneDx("fixture", graph, "abc123");
  assert.doesNotThrow(() => validateOfficialSbomSchema(sourceRoot, "cyclonedx", cyclonedx));
  const wrongSpec = structuredClone(cyclonedx);
  wrongSpec.specVersion = "1.4";
  assert.throws(() => validateCycloneDxDocument(wrongSpec), /schema/i);
  const missingRootType = structuredClone(cyclonedx);
  delete missingRootType.metadata.component.type;
  assert.throws(() => validateCycloneDxDocument(missingRootType), /schema|root/i);
  assert.throws(
    () => validateOfficialSbomSchema(sourceRoot, "cyclonedx", missingRootType),
    /official cyclonedx schema validation failed/i,
  );
  const digestAsVersion = structuredClone(cyclonedx);
  digestAsVersion.metadata.component.version = "abc123";
  assert.throws(() => validateCycloneDxDocument(digestAsVersion), /version|digest/i);
  const missingDependencyRecord = structuredClone(cyclonedx);
  missingDependencyRecord.dependencies.pop();
  assert.throws(() => validateCycloneDxDocument(missingDependencyRecord), /incomplete/i);
  const unknownCycloneTarget = structuredClone(cyclonedx);
  unknownCycloneTarget.dependencies[0].dependsOn.push("pkg:npm/unknown@1.0.0");
  assert.throws(() => validateCycloneDxDocument(unknownCycloneTarget), /dependency graph/i);
  const oneMissingCycloneEdge = structuredClone(cyclonedx);
  oneMissingCycloneEdge.dependencies.find((dependency) => dependency.dependsOn.length > 0).dependsOn.pop();
  assert.throws(() => validateCycloneDxDocument(oneMissingCycloneEdge, graph), /exact|dependency graph/i);
});

test("official SBOM schemas and validator versions are pinned by digest", () => {
  const lock = JSON.parse(fs.readFileSync(path.join(sourceRoot, "scripts/sbom-schema-lock.json"), "utf8"));
  assert.deepEqual(lock.validator, {
    package: "ajv",
    version: "8.20.0",
    formatsPackage: "ajv-formats",
    formatsVersion: "3.0.1",
    internationalFormatsPackage: "ajv-formats-draft2019",
    internationalFormatsVersion: "1.6.1",
  });
  assert.deepEqual(Object.keys(lock.schemas).sort(), [
    "cyclonedx-1.5",
    "cyclonedx-spdx",
    "jsf-0.82",
    "spdx-2.3",
  ]);
  for (const [name, record] of Object.entries(lock.schemas)) {
    assert.match(record.source, /^https:\/\/(?:raw\.githubusercontent\.com)\//, `${name} source`);
    assert.match(record.sha256, /^[0-9a-f]{64}$/, `${name} digest`);
    assert.equal(
      sha256(fs.readFileSync(path.join(sourceRoot, record.path))),
      record.sha256,
      `${name} vendored schema digest`,
    );
  }
});

test("SPDX expressions use strict reviewed normalization", async () => {
  const {
    normalizeSpdxExpression,
    resolveLicenseReview,
    validateSpdxDocument,
  } = await loadGenerator();
  const policy = {
    allowed: ["Apache-2.0", "MIT"],
    review: ["LLVM-exception"],
    denied: ["GPL-3.0-only"],
    exceptions: ["LLVM-exception"],
    licenseRefs: {
      "LicenseRef-Flowersec-Test": {
        extractedText: "Test license text",
        sha256: "48b2adcd0f509743a6e1a7f683b89176b5c5f175a1fa9544eabbe738e042f981",
      },
    },
    legacyExpressionMappings: {
      "MIT/Apache-2.0": "MIT OR Apache-2.0",
    },
    expressionDecisions: {
      "MIT OR Apache-2.0": {
        decision: "approved",
        concludedExpression: "MIT",
        reviewer: "fixture-reviewer",
        reviewedAt: "2026-07-22",
      },
      "Apache-2.0 WITH LLVM-exception": {
        decision: "approved",
        concludedExpression: "Apache-2.0 WITH LLVM-exception",
        reviewer: "fixture-reviewer",
        reviewedAt: "2026-07-22",
      },
      "LicenseRef-Flowersec-Test": {
        decision: "approved",
        concludedExpression: "LicenseRef-Flowersec-Test",
        reviewer: "fixture-reviewer",
        reviewedAt: "2026-07-22",
      },
    },
  };

  assert.equal(normalizeSpdxExpression("MIT/Apache-2.0", policy), "MIT OR Apache-2.0");
  assert.equal(
    normalizeSpdxExpression("Apache-2.0 WITH LLVM-exception", policy),
    "Apache-2.0 WITH LLVM-exception",
  );
  assert.equal(normalizeSpdxExpression("LicenseRef-Flowersec-Test", policy), "LicenseRef-Flowersec-Test");
  assert.throws(() => normalizeSpdxExpression("MIT/Unknown-1.0", policy), /legacy|unknown/i);
  assert.throws(() => normalizeSpdxExpression("MIT OR Unknown-1.0", policy), /unknown/i);
  assert.throws(() => normalizeSpdxExpression("MIT WITH LLVM-exception OR", policy), /expression/i);
  assert.throws(() => normalizeSpdxExpression("GPL-3.0-only", policy), /denied/i);
  assert.throws(() => normalizeSpdxExpression("LicenseRef-Missing", policy), /LicenseRef/i);
  assert.throws(() => resolveLicenseReview("MIT", policy), /review decision/i);
  assert.equal(resolveLicenseReview("MIT/Apache-2.0", policy).concludedExpression, "MIT");

  const invalidSpdx = {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: "invalid",
    documentNamespace: "https://example.invalid/spdx/invalid",
    creationInfo: { created: "1970-01-01T00:00:00Z", creators: ["Tool: fixture"] },
    packages: [{
      name: "bad",
      SPDXID: "SPDXRef-Package-bad",
      versionInfo: "1.0.0",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: "MIT",
      licenseDeclared: "MIT/Apache-2.0",
      copyrightText: "NOASSERTION",
      externalRefs: [],
    }],
    relationships: [],
  };
  assert.throws(() => validateSpdxDocument(invalidSpdx), /licenseDeclared|SPDX/i);
});

test("license review records are component-bound and obligation-complete", async () => {
  const { generateSourceArtifacts } = await loadGenerator();
  const artifacts = generateSourceArtifacts(sourceRoot);
  const inventory = JSON.parse(artifacts.get("sbom/source-inventory.json"));
  for (const component of inventory.components) {
    assert.equal(component.review.decision, "approved", `${component.purl} review decision`);
    assert.match(component.review.expressionEvidenceSha256, /^[0-9a-f]{64}$/);
    assert.match(component.review.sourceEvidenceSha256, /^[0-9a-f]{64}$/);
    assert.ok(component.review.sourceEvidenceValue, `${component.purl} immutable source evidence`);
    assert.equal(
      sha256(component.review.sourceEvidenceValue),
      component.review.sourceEvidenceSha256,
      `${component.purl} source evidence digest`,
    );
    const binding = {
      purl: component.purl,
      sourceEvidenceSha256: component.review.sourceEvidenceSha256,
      declaredExpression: component.review.declaredExpression,
      concludedExpression: component.review.concludedExpression,
      policyRevision: component.review.policyRevision,
    };
    assert.equal(
      sha256(stableJson(binding)),
      component.review.expressionEvidenceSha256,
      `${component.purl} expression review binding`,
    );
    assert.notEqual(
      sha256(stableJson({ ...binding, purl: `${component.purl}-mutated` })),
      component.review.expressionEvidenceSha256,
      `${component.purl} mutation must invalidate review binding`,
    );
    assert.ok(component.review.reviewer);
    assert.ok(component.review.reviewedAt);
    assert.match(component.review.copyright.fulfillment, /generated-notice/);
    assert.notEqual(
      component.review.copyright.fulfillment,
      "dependency-source-is-not-bundled-in-the-published-package",
      `${component.purl} must not deny compiled distribution`,
    );
    assert.ok(component.review.notice.fulfillment);
    assert.equal(typeof component.review.sourceOffer.required, "boolean");
    assert.ok(component.review.sourceOffer.fulfillment);
  }
});

test("Swift inventory resolution is lockfile-pinned and cleans isolated scratch paths", async () => {
  const { resolveSwiftDependencyTree } = await loadGenerator();
  const calls = [];
  const graph = { identity: "fixture", version: "unspecified", dependencies: [] };
  const runner = (command, args, options) => {
    calls.push({ command, args, options });
    return JSON.stringify(graph);
  };

  resolveSwiftDependencyTree(sourceRoot, "/tmp/flowersec-inventory-cache", { run: runner });
  resolveSwiftDependencyTree(sourceRoot, "/tmp/flowersec-inventory-cache", { run: runner });
  assert.equal(calls.length, 2);
  const scratchPaths = calls.map((call) => {
    assert.equal(call.command, "swift");
    assert.equal(call.options.cwd, sourceRoot);
    assert.equal(call.options.env.GIT_CONFIG_GLOBAL, os.devNull);
    assert.equal(call.options.env.GIT_CONFIG_SYSTEM, os.devNull);
    assert.equal(call.options.env.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(call.options.env.GIT_TERMINAL_PROMPT, "0");
    for (const variable of ["GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_WORK_TREE"]) {
      assert.equal(variable in call.options.env, false, `${variable} must be scrubbed`);
    }
    assert.ok(call.args.includes("--cache-path"));
    assert.ok(call.args.includes("--scratch-path"));
    assert.ok(call.args.includes("--skip-update"));
    assert.ok(call.args.includes("--only-use-versions-from-resolved-file"));
    assert.ok(call.args.includes("show-dependencies"));
    const scratchIndex = call.args.indexOf("--scratch-path");
    return call.args[scratchIndex + 1];
  });
  assert.notEqual(scratchPaths[0], scratchPaths[1]);
  for (const scratch of scratchPaths) assert.equal(fs.existsSync(scratch), false);

  for (const failure of [
    () => { throw new Error("runner failed"); },
    () => "not-json",
  ]) {
    let failedScratch;
    assert.throws(() => resolveSwiftDependencyTree(sourceRoot, "/tmp/cache", {
      run(command, args) {
        failedScratch = args[args.indexOf("--scratch-path") + 1];
        return failure(command, args);
      },
    }), /runner failed|JSON/);
    assert.ok(failedScratch);
    assert.equal(fs.existsSync(failedScratch), false);
  }
});

test("source and package graphs preserve real dependency edges and npm runtime closure", async () => {
  const {
    generateSourceArtifacts,
    validateDependencyGraph,
    validateCycloneDxDocument,
    validateSpdxDocument,
  } = await loadGenerator();
  const artifacts = generateSourceArtifacts(sourceRoot);
  const inventory = JSON.parse(artifacts.get("sbom/source-inventory.json"));
  const npmSource = inventory.contexts.find((context) => context.id === "npm:flowersec-ts");
  assert.ok(npmSource.components.some((component) => component.name === "typescript"));
  assert.ok(npmSource.components.some((component) => component.name === "vitest"));
  assert.ok(npmSource.edges.length > npmSource.components.length / 2);
  for (const context of inventory.contexts) {
    assert.doesNotThrow(
      () => validateDependencyGraph(context),
      `${context.id} must be fully reachable from its root`,
    );
  }
  const rustFuzz = inventory.contexts.find((context) => context.id === "rust:flowersec-rust/fuzz");
  const disconnected = structuredClone(rustFuzz);
  const target = disconnected.edges.find((edge) => edge.from === disconnected.root.purl)?.to;
  assert.ok(target, "Rust fuzz graph must have a root dependency");
  disconnected.edges = disconnected.edges.filter((edge) => edge.to !== target);
  assert.throws(() => validateDependencyGraph(disconnected), /unreachable/i);

  const npmSpdx = JSON.parse(artifacts.get("flowersec-ts/sbom/spdx.json"));
  const npmCyclone = JSON.parse(artifacts.get("flowersec-ts/sbom/cyclonedx.json"));
  assert.equal(npmSpdx.packages[0].name, "@floegence/flowersec-core");
  assert.equal(npmSpdx.packages[0].versionInfo, "2.0.0");
  assert.ok(npmSpdx.relationships.some((edge) => edge.relationshipType === "DEPENDS_ON"));
  assert.equal(npmSpdx.packages.some((pkg) => pkg.name === "typescript"), false);
  assert.equal(npmSpdx.packages.some((pkg) => pkg.name === "vitest"), false);
  assert.equal(npmSpdx.packages.some((pkg) => pkg.name === "@noble/ciphers"), true);
  assert.equal(npmCyclone.components.some((component) => component.name === "typescript"), false);
  assert.ok(npmCyclone.dependencies.some((edge) => edge.dependsOn.length > 0));
  assert.doesNotThrow(() => validateSpdxDocument(npmSpdx));
  assert.doesNotThrow(() => validateCycloneDxDocument(npmCyclone));
});

test("owned source inventory outputs reject omission, stale content, and extras", async (t) => {
  const {
    assertOwnedOutputClosure,
    generateSourceArtifacts,
  } = await loadGenerator();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-inventory-closure-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifacts = generateSourceArtifacts(sourceRoot);
  for (const [relative, content] of artifacts) {
    const output = path.join(root, relative);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, content);
  }
  assert.doesNotThrow(() => assertOwnedOutputClosure(root, artifacts));

  fs.rmSync(path.join(root, "flowersec-go/sbom/spdx.json"));
  assert.throws(() => assertOwnedOutputClosure(root, artifacts), /missing/i);
  fs.writeFileSync(path.join(root, "flowersec-go/sbom/spdx.json"), artifacts.get("flowersec-go/sbom/spdx.json"));
  fs.appendFileSync(path.join(root, "flowersec-ts/THIRD_PARTY_NOTICES.md"), "stale\n");
  assert.throws(() => assertOwnedOutputClosure(root, artifacts), /stale/i);
  fs.writeFileSync(path.join(root, "flowersec-ts/THIRD_PARTY_NOTICES.md"), artifacts.get("flowersec-ts/THIRD_PARTY_NOTICES.md"));
  const expectedOutput = path.join(root, "flowersec-go/THIRD_PARTY_NOTICES.md");
  fs.rmSync(expectedOutput);
  fs.symlinkSync(path.join(root, "flowersec-ts/THIRD_PARTY_NOTICES.md"), expectedOutput);
  assert.throws(() => assertOwnedOutputClosure(root, artifacts), /regular file/i);
  fs.rmSync(expectedOutput);
  fs.writeFileSync(expectedOutput, artifacts.get("flowersec-go/THIRD_PARTY_NOTICES.md"));
  fs.writeFileSync(path.join(root, "sbom/obsolete.spdx.json"), "{}\n");
  assert.throws(() => assertOwnedOutputClosure(root, artifacts), /unexpected/i);
  fs.rmSync(path.join(root, "sbom/obsolete.spdx.json"));
  fs.symlinkSync("source.spdx.json", path.join(root, "sbom/obsolete-link.json"));
  assert.throws(() => assertOwnedOutputClosure(root, artifacts), /unexpected|symbolic/i);
});

test("distribution package allowlists are bound to generated NOTICE and SBOM outputs", async () => {
  const { validateDistributionConfiguration } = await loadGenerator();
  assert.doesNotThrow(() => validateDistributionConfiguration(sourceRoot));

  const packageJson = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package.json"), "utf8"));
  packageJson.files = packageJson.files.filter((entry) => entry !== "sbom/**");
  assert.throws(
    () => validateDistributionConfiguration(sourceRoot, { npmPackage: packageJson }),
    /sbom/i,
  );
  const cargoToml = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/Cargo.toml"), "utf8")
    .replace(', "sbom/**"', "");
  assert.throws(
    () => validateDistributionConfiguration(sourceRoot, { cargoToml }),
    /sbom/i,
  );
});

test("npm, Rust, Go, and Swift source archives carry exact generated distribution outputs", async (t) => {
  const { generateSourceArtifacts } = await loadGenerator();
  const artifacts = generateSourceArtifacts(sourceRoot);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-source-packages-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const npmPack = path.join(root, "npm-pack");
  const npmExtract = path.join(root, "npm-extract");
  fs.mkdirSync(npmPack, { recursive: true });
  fs.mkdirSync(npmExtract, { recursive: true });
  const npmArchiveName = run(
    "npm",
    ["pack", "--silent", "--ignore-scripts", "--pack-destination", npmPack],
    { cwd: path.join(sourceRoot, "flowersec-ts") },
  ).trim().split(/\s+/).at(-1);
  run("tar", ["-xzf", path.join(npmPack, npmArchiveName), "-C", npmExtract]);
  const npmFiles = stripArchiveRoot(extractedFiles(npmExtract));
  const npmExpected = new Map([
    ["THIRD_PARTY_NOTICES.md", artifacts.get("flowersec-ts/THIRD_PARTY_NOTICES.md")],
    ["sbom/spdx.json", artifacts.get("flowersec-ts/sbom/spdx.json")],
    ["sbom/cyclonedx.json", artifacts.get("flowersec-ts/sbom/cyclonedx.json")],
  ]);
  assertDistributionPayload("npm tgz", npmFiles, npmExpected);
  const policy = JSON.parse(fs.readFileSync(path.join(sourceRoot, "scripts/source-license-policy.json"), "utf8"));
  const npmNotice = npmFiles.get("THIRD_PARTY_NOTICES.md").toString("utf8");
  for (const [purl, record] of Object.entries(policy.bundledNotices)) {
    const licenseText = `${record.licenseTextLines.join("\n")}\n`;
    assert.equal(sha256(licenseText), record.sha256, `${purl} reviewed bundled notice digest`);
    assert.match(npmNotice, new RegExp(record.copyright.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.ok(npmNotice.includes(licenseText.trimEnd()), `${purl} full license text in npm NOTICE`);
  }
  assert.equal(npmFiles.has("dist/vendor/tr46.js"), true, "npm tgz must contain the audited browser bundle");
  const browserBundle = npmFiles.get("dist/vendor/tr46.js").toString("utf8");
  assert.match(browserBundle, /node_modules\/tr46\//, "browser bundle must contain tr46");
  assert.match(browserBundle, /node_modules\/punycode\//, "browser bundle must contain punycode");

  const rustTarget = path.join(root, "rust-target");
  run("cargo", [
    "package", "--allow-dirty", "--no-verify",
    "--manifest-path", path.join(sourceRoot, "flowersec-rust/Cargo.toml"),
    "--target-dir", rustTarget,
  ], { cwd: sourceRoot });
  const rustArchive = findSingleFile(rustTarget, ".crate");
  const rustExtract = path.join(root, "rust-extract");
  fs.mkdirSync(rustExtract);
  run("tar", ["-xzf", rustArchive, "-C", rustExtract]);
  const rustFiles = stripArchiveRoot(extractedFiles(rustExtract));
  assertDistributionPayload("Rust crate", rustFiles, new Map([
    ["THIRD_PARTY_NOTICES.md", artifacts.get("flowersec-rust/THIRD_PARTY_NOTICES.md")],
    ["sbom/spdx.json", artifacts.get("flowersec-rust/sbom/spdx.json")],
    ["sbom/cyclonedx.json", artifacts.get("flowersec-rust/sbom/cyclonedx.json")],
  ]));

  const goZipTool = path.join(root, "go-module-zip-tool");
  fs.mkdirSync(goZipTool);
  fs.writeFileSync(
    path.join(goZipTool, "go.mod"),
    "module flowersec.local/source-zip-test\n\ngo 1.26.5\n\nrequire golang.org/x/mod v0.37.0\n",
  );
  fs.writeFileSync(
    path.join(goZipTool, "go.sum"),
    "golang.org/x/mod v0.37.0 h1:vF1DjpVEshcIqoEaauuHebaLk1O1forxjxBaVn884JQ=\n"
      + "golang.org/x/mod v0.37.0/go.mod h1:m8S8VeM9r4dzDwjrKO0a1sZP3YjeMamRRlD+fmR2Q/0=\n",
  );
  fs.writeFileSync(path.join(goZipTool, "main.go"), `package main
import (
  "os"
  "golang.org/x/mod/module"
  modzip "golang.org/x/mod/zip"
)
func main() {
  output, err := os.Create(os.Args[4])
  if err != nil { panic(err) }
  defer output.Close()
  if err := modzip.CreateFromDir(output, module.Version{Path: os.Args[1], Version: os.Args[2]}, os.Args[3]); err != nil { panic(err) }
}
`);
  const goModules = [
    "flowersec-go",
    "tools/idlgen",
    "tools/releasenotes",
    "tools/stabilitycheck",
    "tools/transportcheck",
  ];
  for (const relative of goModules) {
    const moduleRoot = path.join(sourceRoot, relative);
    const modulePath = /^module\s+(\S+)$/m.exec(fs.readFileSync(path.join(moduleRoot, "go.mod"), "utf8"))?.[1];
    assert.ok(modulePath, `${relative} has no module path`);
    const stagedModuleRoot = path.join(root, `${relative.replaceAll("/", "-")}-source`);
    fs.mkdirSync(stagedModuleRoot);
    const moduleFiles = run(
      "git",
      ["ls-files", "--cached", "--others", "--exclude-standard", "--", relative],
      { cwd: sourceRoot },
    ).split("\n").filter((repositoryRelative) =>
      repositoryRelative && fs.existsSync(path.join(sourceRoot, repositoryRelative))
    );
    for (const repositoryRelative of moduleFiles) {
      const moduleRelative = path.relative(relative, repositoryRelative);
      const destination = path.join(stagedModuleRoot, moduleRelative);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(path.join(sourceRoot, repositoryRelative), destination);
    }
    const archive = path.join(root, `${relative.replaceAll("/", "-")}.zip`);
    const archiveVersion = modulePath.endsWith("/v2")
      ? "v2.0.0-securityinventory"
      : "v0.0.0-securityinventory";
    run("go", ["run", ".", modulePath, archiveVersion, stagedModuleRoot, archive], {
      cwd: goZipTool,
      env: { GOWORK: "off" },
    });
    const extract = path.join(root, `${relative.replaceAll("/", "-")}-extract`);
    fs.mkdirSync(extract);
    run("unzip", ["-q", archive, "-d", extract]);
    const files = stripArchivePrefix(
      extractedFiles(extract),
      `${modulePath}@${archiveVersion}`,
    );
    assert.equal(files.has("go.mod"), true, `${relative} module zip missing go.mod`);
    if (relative === "flowersec-go") {
      assertDistributionPayload("Go module zip", files, new Map([
        ["THIRD_PARTY_NOTICES.md", artifacts.get("flowersec-go/THIRD_PARTY_NOTICES.md")],
        ["sbom/spdx.json", artifacts.get("flowersec-go/sbom/spdx.json")],
        ["sbom/cyclonedx.json", artifacts.get("flowersec-go/sbom/cyclonedx.json")],
      ]));
    }
  }

  const swiftArchive = path.join(root, "flowersec-swift-source.tar");
  const sourcePaths = run(
    "git",
    ["ls-files", "--cached", "--others", "--exclude-standard"],
    { cwd: sourceRoot },
  ).split("\n").filter((repositoryRelative) =>
    repositoryRelative && fs.existsSync(path.join(sourceRoot, repositoryRelative))
  );
  run("tar", ["-cf", swiftArchive, "-T", "-"], {
    cwd: sourceRoot,
    input: `${sourcePaths.join("\n")}\n`,
  });
  const swiftExtract = path.join(root, "swift-extract");
  fs.mkdirSync(swiftExtract);
  run("tar", ["-xf", swiftArchive, "-C", swiftExtract]);
  const swiftFiles = extractedFiles(swiftExtract);
  assertDistributionPayload("Swift source archive", swiftFiles, new Map([
    ["THIRD_PARTY_NOTICES.md", artifacts.get("THIRD_PARTY_NOTICES.md")],
    ["sbom/swift/spdx.json", artifacts.get("sbom/swift/spdx.json")],
    ["sbom/swift/cyclonedx.json", artifacts.get("sbom/swift/cyclonedx.json")],
  ]), (file) => file === "THIRD_PARTY_NOTICES.md" || file.startsWith("sbom/swift/"));

  const omitted = new Map(npmFiles);
  omitted.delete("sbom/spdx.json");
  assert.throws(() => assertDistributionPayload("mutated npm", omitted, npmExpected), /missing/i);
  const stale = new Map(npmFiles);
  stale.set("sbom/spdx.json", Buffer.from("{}\n"));
  assert.throws(() => assertDistributionPayload("mutated npm", stale, npmExpected), /stale/i);
  const extra = new Map(npmFiles);
  extra.set("sbom/obsolete.json", Buffer.from("{}\n"));
  assert.throws(() => assertDistributionPayload("mutated npm", extra, npmExpected), /unexpected/i);
});

test("release target matrix produces exact binary dependency graphs and full license notices", async () => {
  const manifestPath = path.join(sourceRoot, "scripts/release-go-targets.json");
  assert.equal(fs.existsSync(manifestPath), true, "release Go target manifest must exist");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  assert.deepEqual(manifest, {
    schema: "flowersec.release-go-targets.v1",
    platforms: {
      archive: [
        { goos: "linux", goarch: "amd64" },
        { goos: "linux", goarch: "arm64" },
      ],
      image: [
        { goos: "linux", goarch: "amd64" },
        { goos: "linux", goarch: "arm64" },
      ],
    },
    distributions: {
      runtime: {
        platforms: "archive",
        targets: [{ module: "flowersec-go", package: "./cmd/flowersec-runtime" }],
      },
      "runtime-image": {
        platforms: "image",
        targets: [{ module: "flowersec-go", package: "./cmd/flowersec-runtime" }],
      },
    },
  });

  const {
    assertReleaseNoticeLicenseClosure,
    collectGoReleaseDistributions,
    generateSourceArtifacts,
  } = await loadGenerator();
  assert.equal(typeof collectGoReleaseDistributions, "function");
  assert.equal(typeof assertReleaseNoticeLicenseClosure, "function");
  const distributions = collectGoReleaseDistributions(sourceRoot);
  const artifacts = generateSourceArtifacts(sourceRoot);
  assert.deepEqual([...distributions.keys()], Object.keys(manifest.distributions));

  for (const [kind, graph] of distributions) {
    const definition = manifest.distributions[kind];
    const actualModules = new Set();
    for (const platform of manifest.platforms[definition.platforms]) {
      for (const target of definition.targets) {
        const output = run("go", [
          "list",
          "-deps",
          "-mod=readonly",
          "-f",
          "{{with .Module}}{{if not .Main}}{{if .Replace}}{{if .Replace.Version}}{{.Replace.Path}}@{{.Replace.Version}}{{end}}{{else}}{{.Path}}@{{.Version}}{{end}}{{end}}{{end}}",
          target.package,
        ], {
          cwd: path.join(sourceRoot, target.module),
          env: {
            CGO_ENABLED: "0",
            GOOS: platform.goos,
            GOARCH: platform.goarch,
            GOWORK: "off",
          },
        });
        for (const module of output.split("\n").filter(Boolean)) actualModules.add(module);
      }
    }
    const graphModules = graph.components
      .filter((component) => component.ecosystem === "go")
      .map((component) => `${component.name}@${component.version}`);
    assert.deepEqual(graphModules.sort(), [...actualModules].sort(), `${kind} exact Go binary closure`);
    const notice = artifacts.get(`release-compliance/${kind}/THIRD_PARTY_NOTICES.md`);
    assertReleaseNoticeLicenseClosure(notice, graph);
    for (const component of graph.components.filter((entry) => entry.ecosystem === "go")) {
      assert.ok(component.licenseFiles.length > 0, `${kind} ${component.purl} full license files`);
      for (const file of component.licenseFiles) {
        assert.match(file.sha256, /^[0-9a-f]{64}$/);
        assert.ok(notice.includes(file.contents.trimEnd()), `${kind} ${component.purl} ${file.path}`);
      }
    }
    const first = graph.components.find((component) => component.ecosystem === "go").licenseFiles[0];
    assert.throws(
      () => assertReleaseNoticeLicenseClosure(notice.replace(first.contents.trimEnd(), ""), graph),
      /license|notice|missing/i,
    );
  }

  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  const archiveTargets = Object.values(manifest.distributions)
    .filter((definition) => definition.platforms === "archive")
    .flatMap((definition) => definition.targets.map((target) => target.package));
  for (const target of new Set(archiveTargets)) {
    assert.equal(
      workflow.split(`${target} \\`).length - 1,
      archiveTargets.filter((candidate) => candidate === target).length,
      `${target} workflow and manifest occurrence count`,
    );
  }
});

test("GitHub Release archives and container definitions carry exact runtime compliance outputs", async (t) => {
  const { generateSourceArtifacts } = await loadGenerator();
  const artifacts = generateSourceArtifacts(sourceRoot);
  const stageScript = path.join(sourceRoot, "scripts/stage-release-compliance.sh");
  assert.equal(fs.existsSync(stageScript), true, "release compliance staging script must exist");

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-compliance-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const kind of ["runtime"]) {
    const expected = new Map([
      ["THIRD_PARTY_NOTICES.md", artifacts.get(`release-compliance/${kind}/THIRD_PARTY_NOTICES.md`)],
      ["SBOM_SCOPE.md", artifacts.get(`release-compliance/${kind}/SBOM_SCOPE.md`)],
      ["sbom/spdx.json", artifacts.get(`release-compliance/${kind}/sbom/spdx.json`)],
      ["sbom/cyclonedx.json", artifacts.get(`release-compliance/${kind}/sbom/cyclonedx.json`)],
    ]);
    for (const [relative, contents] of expected) {
      assert.equal(typeof contents, "string", `${kind} generator output ${relative}`);
    }

    const payload = path.join(root, `${kind}-payload`);
    fs.mkdirSync(path.join(payload, "sbom"), { recursive: true });
    fs.writeFileSync(path.join(payload, "binary"), "fixture\n");
    fs.writeFileSync(path.join(payload, "THIRD_PARTY_NOTICES.md"), "stale\n");
    fs.writeFileSync(path.join(payload, "sbom/obsolete.json"), "{}\n");
    run(stageScript, [kind, payload], { cwd: sourceRoot });
    assertDistributionPayload(`${kind} staged payload`, extractedFiles(payload), expected, (file) => (
      file === "THIRD_PARTY_NOTICES.md" || file === "SBOM_SCOPE.md" || file.startsWith("sbom/")
    ));

    const tarArchive = path.join(root, `${kind}.tar.gz`);
    run("tar", ["-czf", tarArchive, "-C", root, path.basename(payload)]);
    const tarExtract = path.join(root, `${kind}-tar-extract`);
    fs.mkdirSync(tarExtract);
    run("tar", ["-xzf", tarArchive, "-C", tarExtract]);
    assertDistributionPayload(`${kind} tar archive`, stripArchiveRoot(extractedFiles(tarExtract)), expected, (file) => (
      file === "THIRD_PARTY_NOTICES.md" || file === "SBOM_SCOPE.md" || file.startsWith("sbom/")
    ));

    const zipArchive = path.join(root, `${kind}.zip`);
    run("zip", ["-qr", zipArchive, "."], { cwd: payload });
    const zipExtract = path.join(root, `${kind}-zip-extract`);
    fs.mkdirSync(zipExtract);
    run("unzip", ["-q", zipArchive, "-d", zipExtract]);
    assertDistributionPayload(`${kind} zip archive`, extractedFiles(zipExtract), expected, (file) => (
      file === "THIRD_PARTY_NOTICES.md" || file === "SBOM_SCOPE.md" || file.startsWith("sbom/")
    ));
  }

  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  for (const kind of ["runtime"]) {
    assert.equal(
      (workflow.match(new RegExp(`scripts/stage-release-compliance\\.sh ${kind} "\\$dir"`, "g")) ?? []).length,
      1,
      `${kind} release archive compliance staging`,
    );
  }
  assert.equal((workflow.match(/^\s+sbom: true$/gm) ?? []).length, 1, "runtime image needs a full-image SBOM attestation");

  const dockerDefinitions = [
    ["docker/flowersec-runtime/Dockerfile", "runtime-image"],
  ];
  for (const [dockerfile, kind] of dockerDefinitions) {
    const source = fs.readFileSync(path.join(sourceRoot, dockerfile), "utf8");
    assert.equal((source.match(/^FROM .*@sha256:[0-9a-f]{64}/gm) ?? []).length, 2);
    assert.match(source, /^COPY LICENSE \/usr\/share\/doc\/flowersec\/LICENSE$/m, `${dockerfile} project license`);
    assert.match(
      source,
      new RegExp(`^COPY release-compliance/${kind}/THIRD_PARTY_NOTICES\\.md /usr/share/doc/flowersec/THIRD_PARTY_NOTICES\\.md$`, "m"),
      `${dockerfile} third-party notice`,
    );
    assert.match(
      source,
      new RegExp(`^COPY release-compliance/${kind}/SBOM_SCOPE\\.md /usr/share/doc/flowersec/SBOM_SCOPE\\.md$`, "m"),
      `${dockerfile} SBOM scope`,
    );
    assert.match(
      source,
      new RegExp(`^COPY release-compliance/${kind}/sbom /usr/share/doc/flowersec/sbom$`, "m"),
      `${dockerfile} application SBOM`,
    );
  }

  const containerCheckerPath = path.join(sourceRoot, "scripts/check-container-release-policy.mjs");
  assert.equal(fs.existsSync(containerCheckerPath), true, "container release policy checker must exist");
  const { containerDockerfileContracts, verifyContainerDockerfile } = await import(
    pathToFileURL(containerCheckerPath)
  );
  for (const [dockerfile] of dockerDefinitions) {
    const source = fs.readFileSync(path.join(sourceRoot, dockerfile), "utf8");
    assert.doesNotThrow(() => verifyContainerDockerfile(source, containerDockerfileContracts[dockerfile]));
    assert.throws(
      () => verifyContainerDockerfile(
        `${source}\nRUN rm -rf /usr/share/doc/flowersec\n`,
        containerDockerfileContracts[dockerfile],
      ),
      /instruction|sequence|final/i,
    );
    assert.throws(
      () => verifyContainerDockerfile(`${source}\nFROM scratch\n`, containerDockerfileContracts[dockerfile]),
      /instruction|sequence|final/i,
    );
    assert.throws(
      () => verifyContainerDockerfile(source.replace(/^(FROM .*?)@sha256:[0-9a-f]{64}/m, "$1"), containerDockerfileContracts[dockerfile]),
      /base|stage|sequence/i,
    );
    assert.throws(
      () => verifyContainerDockerfile(source.replace(/^# syntax=.*\n/, ""), containerDockerfileContracts[dockerfile]),
      /syntax|frontend|digest/i,
    );
    assert.throws(
      () => verifyContainerDockerfile(source.replace(/^# syntax=.*$/m, "# syntax=docker/dockerfile:1.7"), containerDockerfileContracts[dockerfile]),
      /syntax|frontend|digest/i,
    );
  }
  assert.match(
    workflow,
    /driver-opts: image=moby\/buildkit:buildx-stable-1@sha256:[0-9a-f]{64}/,
  );
});

test("generated source inventory is complete and checked-in artifacts are current", async () => {
  const { generateSourceArtifacts, requiredArtifactPaths } = await loadGenerator();
  const artifacts = generateSourceArtifacts(sourceRoot);
  assert.deepEqual([...artifacts.keys()].sort(), [...requiredArtifactPaths].sort());
  for (const relativePath of requiredArtifactPaths) {
    const actualPath = path.join(sourceRoot, relativePath);
    assert.equal(fs.existsSync(actualPath), true, `missing ${relativePath}`);
    assert.equal(fs.readFileSync(actualPath, "utf8"), artifacts.get(relativePath), `stale ${relativePath}`);
  }
});

test("published npm and Rust packages include their NOTICE and SBOM", async () => {
  await loadGenerator();
  const packageJson = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package.json"), "utf8"));
  assert.ok(packageJson.files.includes("THIRD_PARTY_NOTICES.md"));
  assert.ok(packageJson.files.includes("sbom/**"));

  const cargoToml = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/Cargo.toml"), "utf8");
  assert.match(cargoToml, /^include = \[.*"THIRD_PARTY_NOTICES\.md".*"sbom\/\*\*".*\]$/m);
});

test("source inventory generation and freshness are wired into local gates", async () => {
  await loadGenerator();
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(makefile, /^source-inventory:\n\tnode scripts\/generate-source-inventory\.mjs$/m);
  assert.match(
    makefile,
    /^security-dependency-check: ts-build\n\tnode --test scripts\/security-dependencies\.test\.mjs scripts\/go-security\.test\.mjs scripts\/rust-security\.test\.mjs scripts\/swift-security\.test\.mjs scripts\/source-inventory\.test\.mjs scripts\/security-makefile\.test\.mjs\n\tnode scripts\/generate-source-inventory\.mjs --check$/m,
  );
});
