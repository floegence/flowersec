#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { collectGoModuleDirectories } from "./check-go-security.mjs";
import {
  normalizeSwiftPins,
  swiftSecurityGitEnvironment,
  withSwiftSecurityCache,
} from "./check-swift-security.mjs";

export const releaseComplianceKinds = Object.freeze([
  "runtime",
  "runtime-image",
]);

export const requiredArtifactPaths = [
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
  ...releaseComplianceKinds.flatMap((kind) => [
    `release-compliance/${kind}/THIRD_PARTY_NOTICES.md`,
    `release-compliance/${kind}/SBOM_SCOPE.md`,
    `release-compliance/${kind}/sbom/spdx.json`,
    `release-compliance/${kind}/sbom/cyclonedx.json`,
  ]),
];

function run(command, args, cwd, environment = {}, replaceEnvironment = false) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    env: replaceEnvironment ? environment : { ...process.env, ...environment },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.error?.message ?? result.stderr}`);
  }
  return result.stdout;
}

function readRegularFile(filePath, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
  } catch (error) {
    throw new Error(`${label}: ${filePath}`, { cause: error });
  }
  try {
    const opened = fs.fstatSync(descriptor);
    const linked = fs.lstatSync(filePath);
    if (!opened.isFile() || !linked.isFile() || linked.isSymbolicLink()
      || opened.dev !== linked.dev || opened.ino !== linked.ino) {
      throw new Error(`${label}: ${filePath}`);
    }
    return fs.readFileSync(descriptor, "utf8");
  } finally {
    fs.closeSync(descriptor);
  }
}

export function resolveSwiftDependencyTree(packageRoot, cachePath, options = {}) {
  const commandRunner = options.run ?? ((command, args, runOptions) => (
    run(command, args, runOptions.cwd, runOptions.env, true)
  ));
  const makeScratch = options.makeScratch ?? (() => fs.mkdtempSync(
    path.join(os.tmpdir(), "flowersec-swift-inventory-scratch-"),
  ));
  const cleanupScratch = options.cleanupScratch ?? ((scratch) => fs.rmSync(
    scratch,
    { recursive: true, force: true },
  ));
  const scratch = makeScratch();
  try {
    return JSON.parse(commandRunner(
      "swift",
      [
        "package",
        "--cache-path",
        cachePath,
        "--package-path",
        packageRoot,
        "--scratch-path",
        scratch,
        "--skip-update",
        "--only-use-versions-from-resolved-file",
        "show-dependencies",
        "--format",
        "json",
      ],
      {
        cwd: packageRoot,
        env: swiftSecurityGitEnvironment(),
      },
    ));
  } finally {
    cleanupScratch(scratch);
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function compareComponents(left, right) {
  return left.ecosystem.localeCompare(right.ecosystem)
    || left.name.localeCompare(right.name)
    || left.version.localeCompare(right.version);
}

function compareEdges(left, right) {
  return left.from.localeCompare(right.from)
    || left.to.localeCompare(right.to)
    || left.kind.localeCompare(right.kind);
}

function uniqueEdges(edges) {
  const seen = new Set();
  return edges.filter((edge) => {
    const key = `${edge.from}\0${edge.to}\0${edge.kind}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort(compareEdges);
}

function parseJsonSequence(input) {
  const values = [];
  let index = 0;
  while (index < input.length) {
    while (/\s/.test(input[index] ?? "")) index += 1;
    if (index >= input.length) break;
    if (input[index] !== "{") throw new Error(`invalid JSON sequence at byte ${index}`);
    const start = index;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (; index < input.length; index += 1) {
      const character = input[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') inString = true;
      else if (character === "{") depth += 1;
      else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          index += 1;
          values.push(JSON.parse(input.slice(start, index)));
          break;
        }
      }
    }
    if (depth !== 0 || inString) throw new Error("truncated JSON sequence");
  }
  return values;
}

function componentKey(component) {
  return `${component.ecosystem}\0${component.name}\0${component.version}`;
}

function mergeComponents(groups) {
  const merged = new Map();
  for (const component of groups.flat()) {
    const key = componentKey(component);
    const previous = merged.get(key);
    if (previous) {
      const { licenseEvidence: previousEvidence, ...previousCore } = previous;
      const { licenseEvidence: currentEvidence, ...currentCore } = component;
      if (JSON.stringify(previousCore) !== JSON.stringify(currentCore)
        || (previousEvidence && currentEvidence
          && JSON.stringify(previousEvidence) !== JSON.stringify(currentEvidence))) {
        throw new Error(`conflicting dependency metadata for ${component.name}@${component.version}`);
      }
      if (!previousEvidence && currentEvidence) merged.set(key, component);
      continue;
    }
    merged.set(key, component);
  }
  return [...merged.values()].sort(compareComponents);
}

function loadLicensePolicy(repoRoot) {
  return readJson(path.join(repoRoot, "scripts/source-license-policy.json"));
}

const officialSchemaValidatorCache = new Map();

function loadOfficialSchemaValidators(repoRoot) {
  const cached = officialSchemaValidatorCache.get(repoRoot);
  if (cached) return cached;
  const lock = readJson(path.join(repoRoot, "scripts/sbom-schema-lock.json"));
  const require = createRequire(path.join(repoRoot, "flowersec-ts/package.json"));
  let Ajv;
  let addFormats;
  let addInternationalFormats;
  try {
    Ajv = require(lock.validator.package);
    addFormats = require(lock.validator.formatsPackage);
    addInternationalFormats = require(lock.validator.internationalFormatsPackage);
  } catch (error) {
    throw new Error(`pinned SBOM schema validator is unavailable; run npm ci in flowersec-ts: ${error.message}`);
  }
  const installedVersions = new Map([
    [lock.validator.package, require(`${lock.validator.package}/package.json`).version],
    [lock.validator.formatsPackage, require(`${lock.validator.formatsPackage}/package.json`).version],
    [
      lock.validator.internationalFormatsPackage,
      require(`${lock.validator.internationalFormatsPackage}/package.json`).version,
    ],
  ]);
  const expectedVersions = new Map([
    [lock.validator.package, lock.validator.version],
    [lock.validator.formatsPackage, lock.validator.formatsVersion],
    [lock.validator.internationalFormatsPackage, lock.validator.internationalFormatsVersion],
  ]);
  for (const [packageName, expected] of expectedVersions) {
    if (installedVersions.get(packageName) !== expected) {
      throw new Error(`SBOM schema validator ${packageName} must be exactly ${expected}`);
    }
  }
  const schemas = new Map();
  for (const [name, record] of Object.entries(lock.schemas ?? {})) {
    if (!record.source?.startsWith("https://") || !/^[0-9a-f]{64}$/.test(record.sha256 ?? "")) {
      throw new Error(`official SBOM schema lock entry ${name} is incomplete`);
    }
    const schemaPath = path.resolve(repoRoot, record.path);
    const relative = path.relative(repoRoot, schemaPath);
    if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error(`official SBOM schema ${name} is outside the repository`);
    }
    const contents = fs.readFileSync(schemaPath, "utf8");
    if (sha256(contents) !== record.sha256) {
      throw new Error(`official SBOM schema ${name} digest mismatch`);
    }
    schemas.set(name, JSON.parse(contents));
  }
  for (const required of ["spdx-2.3", "cyclonedx-1.5", "jsf-0.82", "cyclonedx-spdx"]) {
    if (!schemas.has(required)) throw new Error(`official SBOM schema ${required} is not locked`);
  }
  const ajv = new Ajv({
    allErrors: true,
    strict: true,
    // CycloneDX 1.5 uses branch-local required fields that trigger Ajv's strictRequired warning.
    strictRequired: false,
    validateFormats: true,
  });
  addFormats(ajv);
  addInternationalFormats(ajv);
  ajv.addSchema(schemas.get("jsf-0.82"));
  ajv.addSchema(schemas.get("cyclonedx-spdx"));
  const validators = {
    ajv,
    spdx: ajv.compile(schemas.get("spdx-2.3")),
    cyclonedx: ajv.compile(schemas.get("cyclonedx-1.5")),
  };
  officialSchemaValidatorCache.set(repoRoot, validators);
  return validators;
}

export function validateOfficialSbomSchema(repoRoot, kind, document) {
  const validators = loadOfficialSchemaValidators(repoRoot);
  const validate = validators[kind];
  if (!validate) throw new Error(`unknown official SBOM schema kind ${kind}`);
  if (!validate(document)) {
    throw new Error(`official ${kind} schema validation failed: ${validators.ajv.errorsText(validate.errors)}`);
  }
  return document;
}

function tokenizeSpdxExpression(expression) {
  if (typeof expression !== "string" || expression.trim() === "") {
    throw new Error("SPDX expression is empty");
  }
  const tokens = [];
  const matcher = /\s*(\(|\)|AND\b|OR\b|WITH\b|LicenseRef-[A-Za-z0-9.-]+|[A-Za-z0-9][A-Za-z0-9.+-]*)/y;
  let offset = 0;
  while (offset < expression.length) {
    matcher.lastIndex = offset;
    const match = matcher.exec(expression);
    if (!match) throw new Error(`invalid SPDX expression near ${JSON.stringify(expression.slice(offset))}`);
    tokens.push(match[1]);
    offset = matcher.lastIndex;
  }
  return tokens;
}

function parseSpdxExpression(expression, policy) {
  const tokens = tokenizeSpdxExpression(expression);
  let index = 0;
  const allowed = new Set(policy.allowed ?? []);
  const reviewed = new Set(policy.review ?? []);
  const denied = new Set(policy.denied ?? []);
  const exceptions = new Set(policy.exceptions ?? []);

  function validateLicense(identifier) {
    if (identifier.startsWith("LicenseRef-")) {
      const record = policy.licenseRefs?.[identifier];
      if (!record?.extractedText || !/^[0-9a-f]{64}$/.test(record.sha256 ?? "")) {
        throw new Error(`SPDX LicenseRef ${identifier} has no reviewed extracted text`);
      }
      if (sha256(record.extractedText) !== record.sha256) {
        throw new Error(`SPDX LicenseRef ${identifier} extracted text digest mismatch`);
      }
      return;
    }
    if (denied.has(identifier)) throw new Error(`SPDX expression uses denied license ${identifier}`);
    if (exceptions.has(identifier)) {
      throw new Error(`SPDX exception ${identifier} must follow WITH`);
    }
    if (!allowed.has(identifier) && !reviewed.has(identifier)) {
      throw new Error(`SPDX expression uses unknown license ${identifier}`);
    }
  }

  function primary() {
    const token = tokens[index];
    if (token === "(") {
      index += 1;
      const node = orExpression();
      if (tokens[index] !== ")") throw new Error("invalid SPDX expression: missing closing parenthesis");
      index += 1;
      return node;
    }
    if (!token || [")", "AND", "OR", "WITH"].includes(token)) {
      throw new Error(`invalid SPDX expression at token ${token ?? "<end>"}`);
    }
    validateLicense(token);
    index += 1;
    return { type: "id", value: token };
  }

  function withExpression() {
    const left = primary();
    if (tokens[index] !== "WITH") return left;
    if (left.type !== "id" || left.value.startsWith("LicenseRef-")) {
      throw new Error("invalid SPDX expression: WITH requires a license identifier");
    }
    index += 1;
    const exception = tokens[index];
    if (!exception || !exceptions.has(exception)) {
      throw new Error(`invalid SPDX exception ${exception ?? "<end>"}`);
    }
    index += 1;
    return { type: "with", left, exception };
  }

  function andExpression() {
    let node = withExpression();
    while (tokens[index] === "AND") {
      index += 1;
      node = { type: "and", left: node, right: withExpression() };
    }
    return node;
  }

  function orExpression() {
    let node = andExpression();
    while (tokens[index] === "OR") {
      index += 1;
      node = { type: "or", left: node, right: andExpression() };
    }
    return node;
  }

  const root = orExpression();
  if (index !== tokens.length) {
    throw new Error(`invalid SPDX expression at token ${tokens[index]}`);
  }
  return root;
}

function renderSpdxExpression(node, parentPrecedence = 0) {
  if (node.type === "id") return node.value;
  if (node.type === "with") return `${renderSpdxExpression(node.left, 3)} WITH ${node.exception}`;
  const precedence = node.type === "and" ? 2 : 1;
  const operator = node.type === "and" ? "AND" : "OR";
  const rendered = `${renderSpdxExpression(node.left, precedence)} ${operator} ${renderSpdxExpression(node.right, precedence)}`;
  return precedence < parentPrecedence ? `(${rendered})` : rendered;
}

export function normalizeSpdxExpression(declaredExpression, policy) {
  const mapped = policy.legacyExpressionMappings?.[declaredExpression] ?? declaredExpression;
  if (mapped === declaredExpression && /\s\/\s|\//.test(declaredExpression)) {
    throw new Error(`legacy SPDX expression ${declaredExpression} has no reviewed mapping`);
  }
  return renderSpdxExpression(parseSpdxExpression(mapped, policy));
}

export function resolveLicenseReview(declaredExpression, policy) {
  const normalizedDeclaredExpression = normalizeSpdxExpression(declaredExpression, policy);
  const decision = policy.expressionDecisions?.[normalizedDeclaredExpression];
  if (!decision) {
    throw new Error(`SPDX expression ${normalizedDeclaredExpression} has no explicit review decision`);
  }
  if (decision.decision !== "approved") {
    throw new Error(`SPDX expression ${normalizedDeclaredExpression} is not approved`);
  }
  const concludedExpression = normalizeSpdxExpression(decision.concludedExpression, {
    ...policy,
    legacyExpressionMappings: {},
  });
  const authority = policy.reviewAuthority ?? decision;
  if (!authority.reviewer || !authority.reviewedAt) {
    throw new Error(`SPDX expression ${normalizedDeclaredExpression} has incomplete review authority`);
  }
  return {
    decision: "approved",
    declaredExpression: normalizedDeclaredExpression,
    concludedExpression,
    reviewer: authority.reviewer,
    reviewedAt: authority.reviewedAt,
    policyRevision: authority.policyRevision ?? "fixture-policy",
  };
}

function expressionContainsLicense(expression, identifiers) {
  const tokens = tokenizeSpdxExpression(expression);
  return tokens.some((token) => identifiers.has(token));
}

function makeComponent({ ecosystem, name, version, license, source, purl, policy, sourceEvidence }) {
  if (typeof sourceEvidence?.kind !== "string" || typeof sourceEvidence?.value !== "string") {
    throw new Error(`${ecosystem} ${name}@${version} has no immutable source evidence`);
  }
  const licenseReview = resolveLicenseReview(license, policy);
  const bundledNoticeRecord = policy.bundledNotices?.[purl];
  let bundledNotice;
  if (bundledNoticeRecord) {
    if (!Array.isArray(bundledNoticeRecord.licenseTextLines)
      || !bundledNoticeRecord.copyright
      || !bundledNoticeRecord.sha256) {
      throw new Error(`${purl} has incomplete bundled license notice data`);
    }
    const licenseText = `${bundledNoticeRecord.licenseTextLines.join("\n")}\n`;
    if (sha256(licenseText) !== bundledNoticeRecord.sha256) {
      throw new Error(`${purl} bundled license notice digest mismatch`);
    }
    const noticeLicense = normalizeSpdxExpression(bundledNoticeRecord.license, policy);
    if (noticeLicense !== licenseReview.concludedExpression) {
      throw new Error(`${purl} bundled notice license does not match the concluded license`);
    }
    bundledNotice = {
      copyright: bundledNoticeRecord.copyright,
      license: noticeLicense,
      licenseText,
      sha256: bundledNoticeRecord.sha256,
    };
  }
  const sourceEvidenceSha256 = sha256(sourceEvidence.value);
  const expressionEvidenceSha256 = sha256(stableJson({
    purl,
    sourceEvidenceSha256,
    declaredExpression: licenseReview.declaredExpression,
    concludedExpression: licenseReview.concludedExpression,
    policyRevision: licenseReview.policyRevision,
  }));
  const sourceOfferRequired = expressionContainsLicense(
    licenseReview.concludedExpression,
    new Set(["LGPL-2.1-or-later", "MPL-2.0"]),
  );
  return {
    ecosystem,
    name,
    version,
    declaredLicense: licenseReview.declaredExpression,
    concludedLicense: licenseReview.concludedExpression,
    source,
    purl,
    sourceOfferRequired,
    ...(bundledNotice ? { bundledNotice } : {}),
    review: {
      ...licenseReview,
      sourceEvidenceKind: sourceEvidence.kind,
      sourceEvidenceValue: sourceEvidence.value,
      sourceEvidenceSha256,
      expressionEvidenceSha256,
      copyright: {
        requirement: "retain-upstream-copyright-and-license-notices",
        fulfillment: bundledNotice
          ? "full-upstream-copyright-and-license-text-in-generated-notice"
          : "source-dependency-metadata-recorded-in-generated-notice-distribution-obligations-evaluated-separately",
      },
      notice: {
        required: true,
        fulfillment: bundledNotice
          ? "component-entry-and-full-license-text-in-generated-third-party-notice"
          : "component-entry-in-generated-third-party-notice",
      },
      sourceOffer: {
        required: sourceOfferRequired,
        fulfillment: sourceOfferRequired
          ? "exact-upstream-source-and-integrity-recorded"
          : "not-required-by-concluded-license",
      },
    },
  };
}

function readReleaseVersion(repoRoot) {
  const npmVersion = readJson(path.join(repoRoot, "flowersec-ts/package.json")).version;
  const cargoManifest = fs.readFileSync(path.join(repoRoot, "flowersec-rust/Cargo.toml"), "utf8");
  const cargoVersion = /^version = "([^"]+)"$/m.exec(cargoManifest)?.[1];
  if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(npmVersion ?? "") || cargoVersion !== npmVersion) {
    throw new Error(`package release versions are inconsistent: npm=${npmVersion}, cargo=${cargoVersion}`);
  }
  return npmVersion;
}

function rootComponent(ecosystem, name, version, purl) {
  return { ecosystem, name, version, purl };
}

function splitGoModuleToken(token) {
  const separator = token.lastIndexOf("@");
  return separator < 0
    ? { modulePath: token, version: undefined }
    : { modulePath: token.slice(0, separator), version: token.slice(separator + 1) };
}

function collectGoSumEvidence(moduleDirectories) {
  const evidence = new Map();
  for (const moduleDirectory of moduleDirectories) {
    const sumFile = path.join(moduleDirectory, "go.sum");
    if (!fs.existsSync(sumFile)) continue;
    for (const line of fs.readFileSync(sumFile, "utf8").split("\n").filter(Boolean)) {
      const [modulePath, version, sum, extra] = line.trim().split(/\s+/);
      if (!modulePath || !version || !sum || extra || !sum.startsWith("h1:")) {
        throw new Error(`invalid Go checksum entry in ${sumFile}: ${line}`);
      }
      const key = `${modulePath}\0${version}`;
      const previous = evidence.get(key);
      if (previous && previous !== sum) {
        throw new Error(`conflicting Go checksum evidence for ${modulePath}@${version}`);
      }
      evidence.set(key, sum);
    }
  }
  return evidence;
}

function collectGoContexts(repoRoot, policy, releaseVersion) {
  const licenseMap = readJson(path.join(repoRoot, "scripts/third-party-go-licenses.json"));
  const moduleDirectories = collectGoModuleDirectories(repoRoot);
  const sumEvidence = collectGoSumEvidence(moduleDirectories);
  return moduleDirectories.map((moduleDir) => {
    const relative = path.relative(repoRoot, moduleDir);
    const metadataEntries = parseJsonSequence(run(
      "go",
      ["list", "-m", "-json", "all"],
      moduleDir,
      { GOWORK: "off" },
    ));
    const packageEntries = parseJsonSequence(run(
      "go",
      ["list", "-deps", "-test", "-json", "./..."],
      moduleDir,
      { GOWORK: "off" },
    ));
    const packageModuleKeys = new Set(packageEntries.flatMap((pkg) => {
      if (!pkg.Module || pkg.Module.Main) return [];
      const selected = pkg.Module.Replace?.Version ? pkg.Module.Replace : pkg.Module;
      return typeof selected.Version === "string"
        ? [`${selected.Path}\0${selected.Version}`]
        : [];
    }));
    const main = metadataEntries.find((metadata) => metadata.Main);
    if (!main?.Path) throw new Error(`Go context ${relative} has no main module`);
    const root = rootComponent(
      "go",
      main.Path,
      relative === "flowersec-go" ? `v${releaseVersion}` : releaseVersion,
      `pkg:golang/${main.Path}@${relative === "flowersec-go" ? `v${releaseVersion}` : releaseVersion}`,
    );
    const components = metadataEntries.flatMap((metadata) => {
      if (metadata.Main || typeof metadata.Version !== "string") return [];
      if (metadata.Replace && typeof metadata.Replace.Version !== "string") return [];
      const selected = metadata.Replace?.Version ? metadata.Replace : metadata;
      if (!packageModuleKeys.has(`${selected.Path}\0${selected.Version}`)) return [];
      const mapping = licenseMap[selected.Path];
      if (!mapping?.license || !mapping?.file) {
        throw new Error(`Go module ${selected.Path} is missing reviewed license metadata`);
      }
      const moduleSum = selected.Sum ?? metadata.Sum
        ?? sumEvidence.get(`${selected.Path}\0${selected.Version}`);
      const goModSum = selected.GoModSum ?? metadata.GoModSum
        ?? sumEvidence.get(`${selected.Path}\0${selected.Version}/go.mod`);
      return [makeComponent({
        ecosystem: "go",
        name: selected.Path,
        version: selected.Version,
        license: mapping.license,
        source: `https://${selected.Path}`,
        purl: `pkg:golang/${selected.Path}@${selected.Version}`,
        policy,
        sourceEvidence: {
          kind: moduleSum ? "go-module-sum" : "go-module-go-mod-sum",
          value: moduleSum ?? goModSum,
        },
      })];
    });
    const byPath = new Map(components.map((component) => [component.name, component]));
    const graphOutput = run("go", ["mod", "graph"], moduleDir, { GOWORK: "off" });
    const edges = graphOutput.split("\n").filter(Boolean).flatMap((line) => {
      const [fromToken, toToken, extra] = line.trim().split(/\s+/);
      if (!fromToken || !toToken || extra) throw new Error(`invalid go mod graph line: ${line}`);
      const fromPath = splitGoModuleToken(fromToken).modulePath;
      const toPath = splitGoModuleToken(toToken).modulePath;
      if (toPath === "go" || toPath === "toolchain") return [];
      const from = fromPath === main.Path ? root : byPath.get(fromPath);
      const to = byPath.get(toPath);
      if (!from || !to) return [];
      return [{ from: from.purl, to: to.purl, kind: "runtime" }];
    });
    return {
      id: `go:${relative}`,
      ecosystem: "go",
      root,
      components: mergeComponents([components]),
      edges: uniqueEdges(edges),
    };
  });
}

function loadReleaseGoTargetManifest(repoRoot) {
  const manifest = readJson(path.join(repoRoot, "scripts/release-go-targets.json"));
  if (manifest?.schema !== "flowersec.release-go-targets.v1"
    || !manifest.platforms || !manifest.distributions) {
    throw new Error("invalid release Go target manifest schema");
  }
  const platformNames = new Set(Object.keys(manifest.platforms));
  for (const [name, platforms] of Object.entries(manifest.platforms)) {
    if (!Array.isArray(platforms) || platforms.length === 0) {
      throw new Error(`release Go platform group ${name} is empty`);
    }
    const keys = new Set();
    for (const platform of platforms) {
      if (!/^[a-z0-9]+$/.test(platform?.goos ?? "")
        || !/^[a-z0-9]+$/.test(platform?.goarch ?? "")) {
        throw new Error(`release Go platform group ${name} contains an invalid platform`);
      }
      const key = `${platform.goos}/${platform.goarch}`;
      if (keys.has(key)) throw new Error(`release Go platform group ${name} contains duplicate ${key}`);
      keys.add(key);
    }
  }
  for (const [kind, definition] of Object.entries(manifest.distributions)) {
    if (!platformNames.has(definition?.platforms)
      || !Array.isArray(definition.targets)
      || definition.targets.length === 0) {
      throw new Error(`release Go distribution ${kind} has no valid platforms or targets`);
    }
    const targets = new Set();
    for (const target of definition.targets) {
      if (!/^[a-z0-9-]+(?:\/[a-z0-9-]+)*$/.test(target?.module ?? "")
        || !/^\.\/[A-Za-z0-9._/-]+$/.test(target?.package ?? "")) {
        throw new Error(`release Go distribution ${kind} contains an invalid target`);
      }
      const key = `${target.module}\0${target.package}`;
      if (targets.has(key)) throw new Error(`release Go distribution ${kind} contains duplicate target ${key}`);
      targets.add(key);
    }
    if (definition.includeNpmRuntime !== undefined && definition.includeNpmRuntime !== true) {
      throw new Error(`release Go distribution ${kind} has an invalid npm runtime flag`);
    }
  }
  if (JSON.stringify(Object.keys(manifest.distributions)) !== JSON.stringify(releaseComplianceKinds)) {
    throw new Error("release Go distributions do not match the owned compliance output closure");
  }
  return manifest;
}

function selectedGoPackageModule(module) {
  if (!module || module.Main) return undefined;
  if (module.Replace) {
    return typeof module.Replace.Version === "string" && module.Replace.Version !== ""
      ? module.Replace
      : undefined;
  }
  return typeof module.Version === "string" && module.Version !== "" ? module : undefined;
}

function readGoLicenseFiles(module, mapping) {
  if (typeof module.Dir !== "string" || module.Dir === "") {
    throw new Error(`Go module ${module.Path}@${module.Version} has no source directory`);
  }
  if (typeof mapping.file !== "string" || mapping.file === ""
    || path.basename(mapping.file) !== mapping.file) {
    throw new Error(`Go module ${module.Path} has an invalid reviewed license file`);
  }
  const supplemental = fs.readdirSync(module.Dir).filter((entry) => (
    /^(?:NOTICE|PATENTS)(?:\.|$)/i.test(entry)
  ));
  const fileNames = [mapping.file, ...supplemental.filter((entry) => entry !== mapping.file)].sort((left, right) => (
    left === mapping.file ? -1 : right === mapping.file ? 1 : left.localeCompare(right)
  ));
  return fileNames.map((fileName) => {
    const filePath = path.join(module.Dir, fileName);
    const contents = readRegularFile(
      filePath,
      `Go module license material must be a regular file: ${module.Path} ${fileName}`,
    );
    if (contents.trim() === "" || contents.includes("\0")) {
      throw new Error(`Go module license material is empty or invalid: ${module.Path} ${fileName}`);
    }
    return { path: fileName, sha256: sha256(contents), contents };
  });
}

function makeGoBinaryComponent(module, licenseMap, policy, sumEvidence) {
  const mapping = licenseMap[module.Path];
  if (!mapping?.license || !mapping?.file) {
    throw new Error(`Go release module ${module.Path} is missing reviewed license metadata`);
  }
  const moduleSum = module.Sum ?? sumEvidence.get(`${module.Path}\0${module.Version}`);
  const goModSum = module.GoModSum ?? sumEvidence.get(`${module.Path}\0${module.Version}/go.mod`);
  const component = makeComponent({
    ecosystem: "go",
    name: module.Path,
    version: module.Version,
    license: mapping.license,
    source: `https://${module.Path}`,
    purl: `pkg:golang/${module.Path}@${module.Version}`,
    policy,
    sourceEvidence: {
      kind: moduleSum ? "go-module-sum" : "go-module-go-mod-sum",
      value: moduleSum ?? goModSum,
    },
  });
  return {
    ...component,
    licenseFiles: readGoLicenseFiles(module, mapping),
    review: {
      ...component.review,
      copyright: {
        requirement: "retain-upstream-copyright-and-license-notices",
        fulfillment: "full-upstream-license-material-in-generated-binary-notice",
      },
      notice: {
        required: true,
        fulfillment: "component-entry-and-full-upstream-license-material-in-generated-binary-notice",
      },
    },
  };
}

function collectGoBinaryGraph(repoRoot, policy, releaseVersion, kind, definition, platforms) {
  const root = rootComponent(
    "generic",
    `flowersec-${kind}`,
    releaseVersion,
    `pkg:generic/flowersec-${kind}@${releaseVersion}`,
  );
  const licenseMap = readJson(path.join(repoRoot, "scripts/third-party-go-licenses.json"));
  const moduleDirectories = [...new Set(definition.targets.map((target) => (
    path.join(repoRoot, target.module)
  )))];
  const sumEvidence = collectGoSumEvidence(moduleDirectories);
  const components = [];
  const edges = [];
  for (const platform of platforms) {
    const byModule = new Map();
    for (const target of definition.targets) {
      const targets = byModule.get(target.module) ?? [];
      targets.push(target.package);
      byModule.set(target.module, targets);
    }
    for (const [moduleRelative, targets] of byModule) {
      const moduleDirectory = path.join(repoRoot, moduleRelative);
      const packages = parseJsonSequence(run(
        "go",
        ["list", "-deps", "-mod=readonly", "-json", ...targets],
        moduleDirectory,
        {
          CGO_ENABLED: "0",
          GOARCH: platform.goarch,
          GOENV: "off",
          GOFLAGS: "",
          GOOS: platform.goos,
          GOTOOLCHAIN: "go1.26.5",
          GOWORK: "off",
        },
      ));
      const owners = new Map();
      for (const pkg of packages) {
        const selected = selectedGoPackageModule(pkg.Module);
        if (!selected) {
          if (pkg.Module) owners.set(pkg.ImportPath, root.purl);
          continue;
        }
        const component = makeGoBinaryComponent(selected, licenseMap, policy, sumEvidence);
        components.push(component);
        owners.set(pkg.ImportPath, component.purl);
      }
      for (const pkg of packages) {
        const from = owners.get(pkg.ImportPath);
        if (!from) continue;
        for (const imported of pkg.Imports ?? []) {
          const to = owners.get(imported);
          if (to && from !== to) edges.push({ from, to, kind: "runtime" });
        }
      }
    }
  }
  return validateDependencyGraph({
    root,
    components: mergeComponents([components]),
    edges: uniqueEdges(edges),
  });
}

function collectGoReleaseDistributionsWithInputs(repoRoot, policy, releaseVersion, npmDistribution) {
  const manifest = loadReleaseGoTargetManifest(repoRoot);
  return new Map(Object.entries(manifest.distributions).map(([kind, definition]) => {
    const goGraph = collectGoBinaryGraph(
      repoRoot,
      policy,
      releaseVersion,
      kind,
      definition,
      manifest.platforms[definition.platforms],
    );
    const graph = definition.includeNpmRuntime
      ? mergeDistributionGraphs(goGraph.root, [goGraph, npmDistribution])
      : goGraph;
    return [kind, graph];
  }));
}

export function collectGoReleaseDistributions(repoRoot) {
  const policy = loadLicensePolicy(repoRoot);
  const releaseVersion = readReleaseVersion(repoRoot);
  const npmDistribution = collectNpmContext(
    readJson(path.join(repoRoot, "flowersec-ts/package-lock.json")),
    policy,
  ).distribution;
  return collectGoReleaseDistributionsWithInputs(
    repoRoot,
    policy,
    releaseVersion,
    npmDistribution,
  );
}

function npmPackageName(packagePath) {
  const marker = "node_modules/";
  const index = packagePath.lastIndexOf(marker);
  return index < 0 ? undefined : packagePath.slice(index + marker.length);
}

function resolveNpmDependency(packages, fromPath, dependencyName) {
  let cursor = fromPath;
  while (true) {
    const candidate = cursor
      ? `${cursor}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`;
    if (packages[candidate] && packages[candidate].link !== true) return candidate;
    const parentMarker = cursor.lastIndexOf("/node_modules/");
    if (parentMarker < 0) {
      if (cursor === "") return undefined;
      cursor = "";
    } else {
      cursor = cursor.slice(0, parentMarker);
    }
  }
}

function npmPurl(name, version) {
  return `pkg:npm/${name.replace(/^@/, "%40")}@${version}`;
}

export function collectNpmComponents(lockfile, policy) {
  return collectNpmContext(lockfile, policy).source.components;
}

function collectNpmContext(lockfile, policy) {
  if (!lockfile || typeof lockfile.packages !== "object" || lockfile.packages === null) {
    throw new Error("npm lockfile has no packages object");
  }
  const rootMetadata = lockfile.packages[""];
  if (!rootMetadata?.name || !rootMetadata?.version) throw new Error("npm lockfile has no root package");
  const root = rootComponent(
    "npm",
    rootMetadata.name,
    rootMetadata.version,
    npmPurl(rootMetadata.name, rootMetadata.version),
  );
  const byPackagePath = new Map();
  for (const [packagePath, metadata] of Object.entries(lockfile.packages)) {
    const name = npmPackageName(packagePath);
    if (!name || metadata.link === true) continue;
    if (typeof metadata.version !== "string" || typeof metadata.integrity !== "string") {
      throw new Error(`npm package ${packagePath} has no exact version`);
    }
    byPackagePath.set(packagePath, makeComponent({
      ecosystem: "npm",
      name,
      version: metadata.version,
      license: metadata.license,
      source: metadata.resolved ?? `https://www.npmjs.com/package/${name}`,
      purl: npmPurl(name, metadata.version),
      policy,
      sourceEvidence: { kind: "npm-lock-integrity", value: metadata.integrity },
    }));
  }

  const edges = [];
  for (const [packagePath, metadata] of Object.entries(lockfile.packages)) {
    const from = packagePath === "" ? root : byPackagePath.get(packagePath);
    if (!from) continue;
    const dependencyGroups = [
      ["runtime", metadata.dependencies ?? {}],
      ["optional", metadata.optionalDependencies ?? {}],
      ["peer", metadata.peerDependencies ?? {}],
      ["dev", metadata.devDependencies ?? {}],
    ];
    for (const [kind, dependencies] of dependencyGroups) {
      for (const dependencyName of Object.keys(dependencies)) {
        const targetPath = resolveNpmDependency(lockfile.packages, packagePath, dependencyName);
        if (!targetPath) {
          const peerOptional = kind === "peer" && metadata.peerDependenciesMeta?.[dependencyName]?.optional === true;
          if (kind === "optional" || peerOptional) continue;
          throw new Error(`npm dependency ${dependencyName} from ${packagePath || "<root>"} is unresolved`);
        }
        edges.push({ from: from.purl, to: byPackagePath.get(targetPath).purl, kind });
      }
    }
  }

  const sourceComponents = mergeComponents([[...byPackagePath.values()]]);
  const sourceEdges = uniqueEdges(edges);
  const runtimeReachable = new Set([root.purl]);
  const pending = [root.purl];
  while (pending.length > 0) {
    const current = pending.shift();
    for (const edge of sourceEdges) {
      if (edge.from !== current || edge.kind === "dev") continue;
      if (!runtimeReachable.has(edge.to)) {
        runtimeReachable.add(edge.to);
        pending.push(edge.to);
      }
    }
  }
  const runtimeComponents = sourceComponents.filter((component) => runtimeReachable.has(component.purl));
  const runtimeEdges = sourceEdges.filter((edge) => (
    edge.kind !== "dev" && runtimeReachable.has(edge.from) && runtimeReachable.has(edge.to)
  ));
  return {
    source: { root, components: sourceComponents, edges: sourceEdges },
    distribution: { root, components: runtimeComponents, edges: runtimeEdges },
  };
}

function rustReachablePackageIds(metadata, publishedOnly) {
  if (!metadata?.resolve?.root) throw new Error("Cargo metadata has no root package");
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const visited = new Set([metadata.resolve.root]);
  const pending = [metadata.resolve.root];
  while (pending.length > 0) {
    const node = nodes.get(pending.shift());
    if (!node) throw new Error("Cargo metadata is missing a resolve node");
    for (const dependency of node.deps ?? []) {
      const kinds = dependency.dep_kinds ?? [];
      if (publishedOnly && kinds.length > 0 && kinds.every((kind) => kind.kind === "dev")) continue;
      if (!visited.has(dependency.pkg)) {
        visited.add(dependency.pkg);
        pending.push(dependency.pkg);
      }
    }
  }
  return visited;
}

function parseCargoLockChecksums(lockfile) {
  const checksums = new Map();
  const blocks = fs.readFileSync(lockfile, "utf8").split(/\n(?=\[\[package\]\])/);
  for (const block of blocks) {
    if (!block.startsWith("[[package]]")) continue;
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"$/m.exec(block)?.[1];
    const checksum = /^checksum = "([0-9a-f]{64})"$/m.exec(block)?.[1];
    if (name && version && checksum) checksums.set(`${name}\0${version}`, checksum);
  }
  return checksums;
}

function collectRustContext(metadata, policy, lockfile) {
  const rootPackage = metadata.packages.find((pkg) => pkg.id === metadata.resolve.root);
  if (!rootPackage) throw new Error("Cargo metadata has no root package details");
  const root = rootComponent(
    "cargo",
    rootPackage.name,
    rootPackage.version,
    `pkg:cargo/${rootPackage.name}@${rootPackage.version}`,
  );
  const checksums = parseCargoLockChecksums(lockfile);
  const byId = new Map();
  for (const pkg of metadata.packages) {
    if (pkg.source === null) continue;
    const checksum = checksums.get(`${pkg.name}\0${pkg.version}`);
    if (!checksum) throw new Error(`Cargo package ${pkg.name}@${pkg.version} has no lock checksum`);
    byId.set(pkg.id, makeComponent({
      ecosystem: "cargo",
      name: pkg.name,
      version: pkg.version,
      license: pkg.license,
      source: pkg.repository ?? pkg.source,
      purl: `pkg:cargo/${pkg.name}@${pkg.version}`,
      policy,
      sourceEvidence: { kind: "cargo-lock-checksum", value: checksum },
    }));
  }
  const sourceReachable = rustReachablePackageIds(metadata, false);
  const distributionReachable = rustReachablePackageIds(metadata, true);
  const sourceComponents = mergeComponents([metadata.packages.flatMap((pkg) => (
    sourceReachable.has(pkg.id) && byId.has(pkg.id) ? [byId.get(pkg.id)] : []
  ))]);
  const distributionComponents = mergeComponents([metadata.packages.flatMap((pkg) => (
    distributionReachable.has(pkg.id) && byId.has(pkg.id) ? [byId.get(pkg.id)] : []
  ))]);
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  function dependencyKind(dependency) {
    const kinds = dependency.dep_kinds ?? [];
    return kinds.length > 0 && kinds.every((entry) => entry.kind === "dev")
      ? "dev"
      : kinds.some((entry) => entry.kind === "build") ? "build" : "runtime";
  }
  function combineKinds(parentKind, childKind) {
    if (parentKind === "dev" || childKind === "dev") return "dev";
    if (parentKind === "build" || childKind === "build") return "build";
    return "runtime";
  }
  function collectEdges(reachable, publishedOnly) {
    const edges = [];
    const anchors = [metadata.resolve.root, ...[...byId.keys()].filter((id) => reachable.has(id))];
    for (const anchorId of anchors) {
      const anchor = anchorId === metadata.resolve.root ? root : byId.get(anchorId);
      const anchorNode = nodes.get(anchorId);
      if (!anchor || !anchorNode) throw new Error(`Cargo metadata is missing graph anchor ${anchorId}`);
      function visit(dependencyId, inheritedKind, localPath) {
        if (!reachable.has(dependencyId)) return;
        const external = byId.get(dependencyId);
        if (external) {
          edges.push({ from: anchor.purl, to: external.purl, kind: inheritedKind });
          return;
        }
        if (localPath.has(dependencyId)) throw new Error(`Cargo path dependency cycle at ${dependencyId}`);
        const localNode = nodes.get(dependencyId);
        if (!localNode) throw new Error(`Cargo metadata is missing local dependency ${dependencyId}`);
        const nextPath = new Set(localPath).add(dependencyId);
        for (const dependency of localNode.deps ?? []) {
          const kind = dependencyKind(dependency);
          if (publishedOnly && kind === "dev") continue;
          visit(dependency.pkg, combineKinds(inheritedKind, kind), nextPath);
        }
      }
      for (const dependency of anchorNode.deps ?? []) {
        const kind = dependencyKind(dependency);
        if (publishedOnly && kind === "dev") continue;
        visit(dependency.pkg, kind, new Set([anchorId]));
      }
    }
    return uniqueEdges(edges);
  }
  return {
    source: { root, components: sourceComponents, edges: collectEdges(sourceReachable, false) },
    distribution: {
      root,
      components: distributionComponents,
      edges: collectEdges(distributionReachable, true),
    },
  };
}

function cargoMetadata(repoRoot, manifest) {
  return JSON.parse(run(
    "cargo",
    ["metadata", "--manifest-path", path.join(repoRoot, manifest), "--locked", "--all-features", "--format-version=1"],
    repoRoot,
  ));
}

function collectSwiftContext(repoRoot, packageRoot, policy, releaseVersion) {
  const swiftLicenses = policy.swift;
  const pins = normalizeSwiftPins(readJson(path.join(packageRoot, "Package.resolved")));
  const components = pins.map((pin) => {
    const license = swiftLicenses[pin.identity];
    if (!license) throw new Error(`Swift package ${pin.identity} is missing reviewed license metadata`);
    return makeComponent({
      ecosystem: "swift",
      name: pin.identity,
      version: pin.state.version,
      license,
      source: pin.location,
      purl: `pkg:swift/${pin.identity}@${pin.state.version}`,
      policy,
      sourceEvidence: { kind: "swift-package-revision", value: pin.state.revision },
    });
  }).sort(compareComponents);
  const root = rootComponent(
    "swift",
    packageRoot === repoRoot ? "Flowersec" : "FlowersecSwiftClientExample",
    releaseVersion,
    `pkg:swift/${packageRoot === repoRoot ? "Flowersec" : "FlowersecSwiftClientExample"}@${releaseVersion}`,
  );
  const byIdentity = new Map(components.map((component) => [component.name, component]));
  const dependencyTree = withSwiftSecurityCache(repoRoot, (cachePath) => (
    resolveSwiftDependencyTree(packageRoot, cachePath)
  ));
  const edges = [];
  function visit(node, parentRef) {
    const component = byIdentity.get(node.identity);
    const currentRef = component?.purl ?? parentRef;
    if (component && parentRef !== component.purl) {
      edges.push({ from: parentRef, to: component.purl, kind: "runtime" });
    }
    for (const dependency of node.dependencies ?? []) visit(dependency, currentRef);
  }
  for (const dependency of dependencyTree.dependencies ?? []) visit(dependency, root.purl);
  const referenced = new Set(edges.flatMap((edge) => [edge.from, edge.to]));
  for (const component of components) {
    if (!referenced.has(component.purl)) {
      throw new Error(`Swift dependency graph omitted locked package ${component.name}`);
    }
  }
  return { root, components, edges: uniqueEdges(edges) };
}

function spdxId(component) {
  return `SPDXRef-Package-${sha256(componentKey(component)).slice(0, 20)}`;
}

function rootSpdxPackage(root, inventoryDigest) {
  return {
    name: root.name,
    SPDXID: spdxId(root),
    versionInfo: root.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    copyrightText: "NOASSERTION",
    comment: `Flowersec source inventory SHA-256: ${inventoryDigest}`,
    externalRefs: [{
      referenceCategory: "PACKAGE-MANAGER",
      referenceType: "purl",
      referenceLocator: root.purl,
    }],
  };
}

function dependencyMap(graph) {
  const references = [graph.root.purl, ...graph.components.map((component) => component.purl)];
  const known = new Set(references);
  const dependencies = new Map(references.map((reference) => [reference, new Set()]));
  for (const edge of graph.edges) {
    if (!known.has(edge.from) || !known.has(edge.to)) {
      throw new Error(`dependency edge references unknown component: ${edge.from} -> ${edge.to}`);
    }
    dependencies.get(edge.from).add(edge.to);
  }
  return dependencies;
}

function dependencyPairs(graph) {
  const dependencies = dependencyMap(graph);
  return [...dependencies].flatMap(([from, targets]) => (
    [...targets].map((to) => ({ from, to }))
  )).sort((left, right) => left.from.localeCompare(right.from) || left.to.localeCompare(right.to));
}

export function validateDependencyGraph(graph) {
  if (!graph?.root?.purl || !Array.isArray(graph.components) || !Array.isArray(graph.edges)) {
    throw new Error("dependency graph has no root, components, or edges");
  }
  const references = [graph.root.purl, ...graph.components.map((component) => component.purl)];
  if (references.some((reference) => typeof reference !== "string")
    || new Set(references).size !== references.length) {
    throw new Error("dependency graph has invalid or duplicate component references");
  }
  const dependencies = dependencyMap(graph);
  const reachable = new Set([graph.root.purl]);
  const pending = [graph.root.purl];
  while (pending.length > 0) {
    for (const target of dependencies.get(pending.shift())) {
      if (!reachable.has(target)) {
        reachable.add(target);
        pending.push(target);
      }
    }
  }
  const unreachable = graph.components.filter((component) => !reachable.has(component.purl));
  if (unreachable.length > 0) {
    throw new Error(`dependency graph has unreachable components: ${unreachable.map((component) => component.purl).join(", ")}`);
  }
  return graph;
}

export function renderSpdx(name, graph, inventoryDigest) {
  validateDependencyGraph(graph);
  const sorted = [...graph.components].sort(compareComponents);
  const packages = [
    rootSpdxPackage(graph.root, inventoryDigest),
    ...sorted.map((component) => ({
      name: component.name,
      SPDXID: spdxId(component),
      versionInfo: component.version,
      downloadLocation: component.source,
      filesAnalyzed: false,
      licenseConcluded: component.concludedLicense,
      licenseDeclared: component.declaredLicense,
      copyrightText: "NOASSERTION",
      externalRefs: [{
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: component.purl,
      }],
    })),
  ];
  const byPurl = new Map([
    [graph.root.purl, spdxId(graph.root)],
    ...sorted.map((component) => [component.purl, spdxId(component)]),
  ]);
  dependencyMap(graph);
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name,
    documentNamespace: `https://github.com/floegence/flowersec/sbom/${encodeURIComponent(name)}/${inventoryDigest}`,
    creationInfo: {
      created: "1970-01-01T00:00:00Z",
      creators: ["Tool: flowersec-source-inventory-1"],
    },
    packages,
    relationships: [{
      spdxElementId: "SPDXRef-DOCUMENT",
      relationshipType: "DESCRIBES",
      relatedSpdxElement: spdxId(graph.root),
    }, ...dependencyPairs(graph).map((edge) => ({
      spdxElementId: byPurl.get(edge.from),
      relationshipType: "DEPENDS_ON",
      relatedSpdxElement: byPurl.get(edge.to),
    }))],
  };
}

function deterministicUuid(seed) {
  const hex = [...sha256(seed).slice(0, 32)];
  hex[12] = "5";
  hex[16] = "8";
  const value = hex.join("");
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

export function renderCycloneDx(name, graph, inventoryDigest) {
  validateDependencyGraph(graph);
  const dependencies = dependencyMap(graph);
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${deterministicUuid(`${name}\0${inventoryDigest}`)}`,
    version: 1,
    metadata: {
      component: {
        type: "library",
        name: graph.root.name,
        version: graph.root.version,
        purl: graph.root.purl,
        "bom-ref": graph.root.purl,
      },
      properties: [{ name: "flowersec:source-inventory-sha256", value: inventoryDigest }],
    },
    components: [...graph.components].sort(compareComponents).map((component) => ({
      type: "library",
      name: component.name,
      version: component.version,
      purl: component.purl,
      "bom-ref": component.purl,
      licenses: [{ expression: component.concludedLicense }],
      externalReferences: [{ type: "distribution", url: component.source }],
      properties: [
        { name: "flowersec:declared-license", value: component.declaredLicense },
        { name: "flowersec:source-offer-required", value: String(component.sourceOfferRequired) },
      ],
    })),
    dependencies: [...dependencies].map(([reference, targets]) => ({
      ref: reference,
      dependsOn: [...targets].sort(),
    })),
  };
}

function validateSpdxExpressionSyntax(expression, field) {
  if (expression === "NOASSERTION" || expression === "NONE") return;
  const tokens = tokenizeSpdxExpression(expression);
  let index = 0;
  function primary() {
    if (tokens[index] === "(") {
      index += 1;
      disjunction();
      if (tokens[index] !== ")") throw new Error(`${field} is not a valid SPDX expression`);
      index += 1;
      return;
    }
    const token = tokens[index];
    if (!token || [")", "AND", "OR", "WITH"].includes(token)) {
      throw new Error(`${field} is not a valid SPDX expression`);
    }
    index += 1;
  }
  function withExpression() {
    primary();
    if (tokens[index] === "WITH") {
      index += 1;
      const exception = tokens[index];
      if (!exception || ["(", ")", "AND", "OR", "WITH"].includes(exception)) {
        throw new Error(`${field} is not a valid SPDX expression`);
      }
      index += 1;
    }
  }
  function conjunction() {
    withExpression();
    while (tokens[index] === "AND") {
      index += 1;
      withExpression();
    }
  }
  function disjunction() {
    conjunction();
    while (tokens[index] === "OR") {
      index += 1;
      conjunction();
    }
  }
  disjunction();
  if (index !== tokens.length) throw new Error(`${field} is not a valid SPDX expression`);
}

function assertExactDependencyPairs(actual, expected, label) {
  const actualKeys = [...new Set(actual.map((edge) => `${edge.from}\0${edge.to}`))].sort();
  const expectedKeys = dependencyPairs(expected).map((edge) => `${edge.from}\0${edge.to}`).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error(`${label} dependency graph does not exactly match the source graph`);
  }
}

export function validateSpdxDocument(document, expectedGraph) {
  if (document?.spdxVersion !== "SPDX-2.3" || document.dataLicense !== "CC0-1.0") {
    throw new Error("invalid SPDX document schema");
  }
  if (typeof document.documentNamespace !== "string"
    || !document.documentNamespace.startsWith("https://")
    || typeof document.name !== "string"
    || document.SPDXID !== "SPDXRef-DOCUMENT"
    || !document.creationInfo?.created
    || !Array.isArray(document.creationInfo?.creators)) {
    throw new Error("invalid SPDX document namespace or creation schema");
  }
  if (!Array.isArray(document.packages) || document.packages.length === 0
    || !Array.isArray(document.relationships)) {
    throw new Error("invalid SPDX package or relationship collection");
  }
  const identifiers = new Set(["SPDXRef-DOCUMENT"]);
  for (const pkg of document.packages) {
    if (!pkg?.name || !pkg?.versionInfo || !pkg?.SPDXID || identifiers.has(pkg.SPDXID)) {
      throw new Error("invalid or duplicate SPDX package");
    }
    identifiers.add(pkg.SPDXID);
    validateSpdxExpressionSyntax(pkg.licenseDeclared, "licenseDeclared");
    validateSpdxExpressionSyntax(pkg.licenseConcluded, "licenseConcluded");
    const purl = pkg.externalRefs?.find((reference) => reference.referenceType === "purl")?.referenceLocator;
    if (typeof purl !== "string" || !purl.startsWith("pkg:")) throw new Error("SPDX package has no purl");
  }
  const describes = document.relationships.filter((relationship) => relationship.relationshipType === "DESCRIBES");
  if (describes.length !== 1 || describes[0].spdxElementId !== "SPDXRef-DOCUMENT") {
    throw new Error("SPDX document must describe exactly one root package");
  }
  const dependencyRelationships = document.relationships.filter((relationship) => (
    relationship.relationshipType === "DEPENDS_ON"
  ));
  if (document.packages.length > 1 && dependencyRelationships.length === 0) {
    throw new Error("SPDX dependency graph is incomplete");
  }
  const describedPackage = document.packages.find((pkg) => pkg.SPDXID === describes[0].relatedSpdxElement);
  const inventoryDigest = /Flowersec source inventory SHA-256: (\S+)/.exec(describedPackage?.comment ?? "")?.[1];
  if (!inventoryDigest || describedPackage.versionInfo === inventoryDigest) {
    throw new Error("SPDX root package version must not be the inventory digest");
  }
  for (const relationship of document.relationships) {
    if (!identifiers.has(relationship.spdxElementId)
      || !identifiers.has(relationship.relatedSpdxElement)) {
      throw new Error("SPDX relationship references an unknown package");
    }
  }
  if (expectedGraph) {
    const purlByIdentifier = new Map(document.packages.map((pkg) => [
      pkg.SPDXID,
      pkg.externalRefs.find((reference) => reference.referenceType === "purl").referenceLocator,
    ]));
    assertExactDependencyPairs(dependencyRelationships.map((relationship) => ({
      from: purlByIdentifier.get(relationship.spdxElementId),
      to: purlByIdentifier.get(relationship.relatedSpdxElement),
    })), expectedGraph, "SPDX");
  }
  return document;
}

export function validateCycloneDxDocument(document, expectedGraph) {
  if (document?.bomFormat !== "CycloneDX" || document.specVersion !== "1.5" || document.version !== 1) {
    throw new Error("invalid CycloneDX document schema");
  }
  if (!/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/.test(document.serialNumber ?? "")) {
    throw new Error("invalid CycloneDX serial number");
  }
  const root = document.metadata?.component;
  const inventoryDigest = document.metadata?.properties?.find((property) => (
    property.name === "flowersec:source-inventory-sha256"
  ))?.value;
  if (root?.type !== "library" || !root?.name || !root?.["bom-ref"] || !root?.version || !inventoryDigest
    || root.version === inventoryDigest || root.purl !== root["bom-ref"]) {
    throw new Error("invalid CycloneDX root component version or inventory digest property");
  }
  const references = new Set([root["bom-ref"]]);
  for (const component of document.components ?? []) {
    if (component?.type !== "library" || !component?.name || !component?.version
      || !component?.["bom-ref"] || component.purl !== component["bom-ref"]
      || references.has(component["bom-ref"])) {
      throw new Error("invalid or duplicate CycloneDX component");
    }
    references.add(component["bom-ref"]);
  }
  if (!Array.isArray(document.dependencies) || document.dependencies.length !== references.size) {
    throw new Error("CycloneDX dependency graph is incomplete");
  }
  const dependencyReferences = new Set();
  for (const dependency of document.dependencies) {
    if (!references.has(dependency.ref) || dependencyReferences.has(dependency.ref)
      || !Array.isArray(dependency.dependsOn)
      || dependency.dependsOn.some((reference) => !references.has(reference))) {
      throw new Error("invalid CycloneDX dependency graph");
    }
    dependencyReferences.add(dependency.ref);
  }
  if (expectedGraph) {
    assertExactDependencyPairs(document.dependencies.flatMap((dependency) => (
      dependency.dependsOn.map((target) => ({ from: dependency.ref, to: target }))
    )), expectedGraph, "CycloneDX");
  }
  return document;
}

export function renderNotice(name, components) {
  const lines = [
    "# Third Party Notices",
    "",
    `This file is generated from the canonical Flowersec source dependency inventory for ${name}.`,
    "Do not edit it manually. License decisions are reviewed by the repository source license policy.",
    "",
  ];
  for (const component of [...components].sort(compareComponents)) {
    lines.push(
      `- ${component.name} ${component.version} (Declared: ${component.declaredLicense}; selected: ${component.concludedLicense}; source: ${component.source})`,
    );
  }
  const distributed = [...components].filter((component) => (
    component.bundledNotice || component.licenseFiles?.length > 0
  )).sort(compareComponents);
  if (distributed.length > 0) {
    lines.push(
      "## Distributed Dependency License Materials",
      "",
      "The following dependencies are incorporated into distributed Flowersec files or binaries.",
      "Their reviewed upstream license, notice, copyright, and patent materials are reproduced below.",
      "",
    );
    for (const component of distributed) {
      lines.push(
        `### ${component.name} ${component.version}`,
        "",
      );
      if (component.bundledNotice) {
        lines.push(
          "#### Reviewed bundled license text",
          "",
          component.bundledNotice.licenseText.trimEnd(),
          "",
        );
      }
      for (const file of component.licenseFiles ?? []) {
        lines.push(
          `#### ${file.path}`,
          "",
          file.contents.trimEnd(),
          "",
        );
      }
    }
  }
  return `${lines.join("\n").trimEnd()}\n`;
}

export function assertReleaseNoticeLicenseClosure(notice, graph) {
  if (typeof notice !== "string" || notice === "") {
    throw new Error("release third-party notice is missing");
  }
  const goComponents = graph.components.filter((component) => component.ecosystem === "go");
  if (goComponents.length === 0) throw new Error("release graph has no Go components");
  for (const component of goComponents) {
    if (!Array.isArray(component.licenseFiles) || component.licenseFiles.length === 0) {
      throw new Error(`release notice has no full license material for ${component.purl}`);
    }
    const heading = `### ${component.name} ${component.version}\n`;
    const start = notice.indexOf(heading);
    if (start < 0 || notice.indexOf(heading, start + heading.length) >= 0) {
      throw new Error(`release notice component section is missing or duplicated: ${component.purl}`);
    }
    const next = notice.indexOf("\n### ", start + heading.length);
    const section = notice.slice(start, next < 0 ? notice.length : next);
    const seenPaths = new Set();
    for (const file of component.licenseFiles) {
      if (typeof file.path !== "string" || seenPaths.has(file.path)
        || !/^[A-Za-z0-9._-]+$/.test(file.path)) {
        throw new Error(`release notice has invalid license file metadata for ${component.purl}`);
      }
      seenPaths.add(file.path);
      if (typeof file.contents !== "string" || file.contents.trim() === ""
        || sha256(file.contents) !== file.sha256) {
        throw new Error(`release notice license digest is invalid for ${component.purl} ${file.path}`);
      }
      const marker = `#### ${file.path}\n\n${file.contents.trimEnd()}`;
      if (!section.includes(marker)) {
        throw new Error(`release notice is missing full license material for ${component.purl} ${file.path}`);
      }
    }
  }
}

function addDistributionArtifacts(artifacts, repoRoot, prefix, name, graph, digest, includeNotice = true) {
  if (includeNotice) {
    const notice = renderNotice(name, graph.components);
    if (graph.components.some((component) => component.ecosystem === "go" && component.licenseFiles)) {
      assertReleaseNoticeLicenseClosure(notice, graph);
    }
    artifacts.set(`${prefix}THIRD_PARTY_NOTICES.md`, notice);
  }
  const spdx = renderSpdx(name, graph, digest);
  const cyclonedx = renderCycloneDx(name, graph, digest);
  validateSpdxDocument(spdx, graph);
  validateCycloneDxDocument(cyclonedx, graph);
  validateOfficialSbomSchema(repoRoot, "spdx", spdx);
  validateOfficialSbomSchema(repoRoot, "cyclonedx", cyclonedx);
  artifacts.set(`${prefix}sbom/spdx.json`, stableJson(spdx));
  artifacts.set(`${prefix}sbom/cyclonedx.json`, stableJson(cyclonedx));
}

function mergeDistributionGraphs(root, graphs) {
  const components = mergeComponents(graphs.map((graph) => graph.components));
  const componentPurls = new Set(components.map((component) => component.purl));
  const edges = uniqueEdges(graphs.flatMap((graph) => graph.edges.map((edge) => ({
    ...edge,
    from: edge.from === graph.root.purl ? root.purl : edge.from,
  })).filter((edge) => (
    (edge.from === root.purl || componentPurls.has(edge.from)) && componentPurls.has(edge.to)
  ))));
  return validateDependencyGraph({ root, components, edges });
}

function renderSbomScope(kind) {
  if (!releaseComplianceKinds.includes(kind)) throw new Error(`unknown release SBOM scope: ${kind}`);
  const lines = [
    "# SBOM Scope",
    "",
    `The SPDX and CycloneDX documents in \`sbom/\` describe the runtime dependency union for the exact ${kind} targets and platforms declared in \`scripts/release-go-targets.json\`.`,
  ];
  lines.push("Build-only, test-only, and unrelated module dependencies are excluded.");
  if (kind.endsWith("-image")) {
    lines.push(
      "These embedded application documents do not describe container-base-image files.",
      "The container release also publishes a BuildKit SPDX SBOM attestation for the complete final OCI image, including its base image.",
    );
  } else {
    lines.push("The archive does not contain operating-system or container-base-image files.");
  }
  lines.push("");
  return lines.join("\n");
}

export function generateSourceArtifacts(repoRoot) {
  const policy = loadLicensePolicy(repoRoot);
  const releaseVersion = readReleaseVersion(repoRoot);
  const goContexts = collectGoContexts(repoRoot, policy, releaseVersion);
  const npmContext = collectNpmContext(
    readJson(path.join(repoRoot, "flowersec-ts/package-lock.json")),
    policy,
  );
  const rustDefinitions = [
    ["rust:flowersec-rust", "flowersec-rust/Cargo.toml", "flowersec-rust/Cargo.lock"],
    ["rust:flowersec-rust/fuzz", "flowersec-rust/fuzz/Cargo.toml", "flowersec-rust/fuzz/Cargo.lock"],
    ["rust:examples/rust", "examples/rust/Cargo.toml", "examples/rust/Cargo.lock"],
  ];
  const rustMetadata = new Map(rustDefinitions.map(([id, manifest, lockfile]) => [id, {
    metadata: cargoMetadata(repoRoot, manifest),
    lockfile: path.join(repoRoot, lockfile),
  }]));
  const rustContexts = rustDefinitions.map(([id]) => ({
    id,
    ecosystem: "cargo",
    ...collectRustContext(rustMetadata.get(id).metadata, policy, rustMetadata.get(id).lockfile).source,
  }));
  const swiftRootContext = collectSwiftContext(
    repoRoot,
    repoRoot,
    policy,
    releaseVersion,
  );
  const swiftExampleContext = collectSwiftContext(
    repoRoot,
    path.join(repoRoot, "examples/swift"),
    policy,
    releaseVersion,
  );
  const contexts = [
    ...goContexts,
    { id: "npm:flowersec-ts", ecosystem: "npm", ...npmContext.source },
    ...rustContexts,
    { id: "swift:root", ecosystem: "swift", ...swiftRootContext },
    { id: "swift:examples/swift", ecosystem: "swift", ...swiftExampleContext },
  ];
  for (const context of contexts) validateDependencyGraph(context);
  const allComponents = mergeComponents(contexts.map((context) => context.components));
  const sourceRoot = rootComponent(
    "generic",
    "flowersec-source",
    releaseVersion,
    `pkg:generic/flowersec-source@${releaseVersion}`,
  );
  const componentPurls = new Set(allComponents.map((component) => component.purl));
  const allEdges = uniqueEdges(contexts.flatMap((context) => context.edges.map((edge) => ({
    ...edge,
    from: edge.from === context.root.purl ? sourceRoot.purl : edge.from,
  })).filter((edge) => (
    (edge.from === sourceRoot.purl || componentPurls.has(edge.from)) && componentPurls.has(edge.to)
  ))));
  const sourceGraph = { root: sourceRoot, components: allComponents, edges: allEdges };
  validateDependencyGraph(sourceGraph);
  const inventory = {
    schema: "flowersec.source-dependencies.v2",
    contexts,
    components: allComponents,
    edges: allEdges,
  };
  const inventoryText = stableJson(inventory);
  const digest = sha256(inventoryText);
  const goDistribution = goContexts.find((context) => context.id === "go:flowersec-go");
  if (!goDistribution) throw new Error("missing flowersec-go dependency context");
  const rustInput = rustMetadata.get("rust:flowersec-rust");
  const rustDistribution = collectRustContext(rustInput.metadata, policy, rustInput.lockfile).distribution;
  const releaseDistributions = collectGoReleaseDistributionsWithInputs(
    repoRoot,
    policy,
    releaseVersion,
    npmContext.distribution,
  );

  const artifacts = new Map();
  artifacts.set("THIRD_PARTY_NOTICES.md", renderNotice("Flowersec source tree", allComponents));
  artifacts.set("sbom/source-inventory.json", inventoryText);
  const sourceSpdx = renderSpdx("flowersec-source", sourceGraph, digest);
  const sourceCycloneDx = renderCycloneDx("flowersec-source", sourceGraph, digest);
  validateSpdxDocument(sourceSpdx, sourceGraph);
  validateCycloneDxDocument(sourceCycloneDx, sourceGraph);
  validateOfficialSbomSchema(repoRoot, "spdx", sourceSpdx);
  validateOfficialSbomSchema(repoRoot, "cyclonedx", sourceCycloneDx);
  artifacts.set("sbom/source.spdx.json", stableJson(sourceSpdx));
  artifacts.set("sbom/source.cyclonedx.json", stableJson(sourceCycloneDx));
  addDistributionArtifacts(artifacts, repoRoot, "flowersec-go/", "flowersec-go", goDistribution, digest);
  addDistributionArtifacts(artifacts, repoRoot, "flowersec-ts/", "flowersec-ts", npmContext.distribution, digest);
  addDistributionArtifacts(artifacts, repoRoot, "flowersec-rust/", "flowersec-rust", rustDistribution, digest);
  addDistributionArtifacts(artifacts, repoRoot, "", "flowersec-swift", swiftRootContext, digest, false);
  artifacts.set("sbom/swift/spdx.json", artifacts.get("sbom/spdx.json"));
  artifacts.set("sbom/swift/cyclonedx.json", artifacts.get("sbom/cyclonedx.json"));
  artifacts.delete("sbom/spdx.json");
  artifacts.delete("sbom/cyclonedx.json");
  for (const [kind, graph] of releaseDistributions) {
    addDistributionArtifacts(
      artifacts,
      repoRoot,
      `release-compliance/${kind}/`,
      `flowersec-${kind}`,
      graph,
      digest,
    );
    artifacts.set(`release-compliance/${kind}/SBOM_SCOPE.md`, renderSbomScope(kind));
  }
  return artifacts;
}

function walkFiles(root) {
  if (!fs.existsSync(root)) return [];
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolute);
      else files.push(path.relative(root, absolute).split(path.sep).join("/"));
    }
  }
  return files;
}

export function assertOwnedOutputClosure(repoRoot, artifacts) {
  for (const [relative, expected] of artifacts) {
    const output = path.join(repoRoot, relative);
    if (!fs.existsSync(output)) throw new Error(`missing owned source inventory output ${relative}`);
    const contents = readRegularFile(
      output,
      `owned source inventory output must be a regular file: ${relative}`,
    );
    if (contents !== expected) {
      throw new Error(`stale owned source inventory output ${relative}`);
    }
  }
  const expected = new Set(artifacts.keys());
  const prefixes = [
    "",
    "flowersec-go/",
    "flowersec-ts/",
    "flowersec-rust/",
    ...releaseComplianceKinds.map((kind) => `release-compliance/${kind}/`),
  ];
  const owned = prefixes.flatMap((prefix) => {
    const notice = `${prefix}THIRD_PARTY_NOTICES.md`;
    const noticePaths = fs.existsSync(path.join(repoRoot, notice)) ? [notice] : [];
    const scope = `${prefix}SBOM_SCOPE.md`;
    const scopePaths = fs.existsSync(path.join(repoRoot, scope)) ? [scope] : [];
    const sbomRoot = `${prefix}sbom`;
    return [
      ...noticePaths,
      ...scopePaths,
      ...walkFiles(path.join(repoRoot, sbomRoot)).map((relative) => `${sbomRoot}/${relative}`),
    ];
  });
  const unexpected = owned.filter((relative) => !expected.has(relative));
  if (unexpected.length > 0) {
    throw new Error(`unexpected owned source inventory output: ${unexpected.sort().join(", ")}`);
  }
}

export function validateDistributionConfiguration(repoRoot, overrides = {}) {
  const npmPackage = overrides.npmPackage
    ?? readJson(path.join(repoRoot, "flowersec-ts/package.json"));
  for (const required of ["THIRD_PARTY_NOTICES.md", "sbom/**"]) {
    if (!npmPackage.files?.includes(required)) {
      throw new Error(`npm package files must include ${required}`);
    }
  }
  const cargoToml = overrides.cargoToml
    ?? fs.readFileSync(path.join(repoRoot, "flowersec-rust/Cargo.toml"), "utf8");
  const include = /^include\s*=\s*\[([^\n]+)\]$/m.exec(cargoToml)?.[1] ?? "";
  for (const required of ["THIRD_PARTY_NOTICES.md", "sbom/**"]) {
    if (!include.includes(`"${required}"`)) {
      throw new Error(`Rust package include must contain ${required}`);
    }
  }
}

function main() {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  validateDistributionConfiguration(repoRoot);
  const artifacts = generateSourceArtifacts(repoRoot);
  if (process.argv.length === 2) {
    for (const [relativePath, content] of artifacts) {
      const output = path.join(repoRoot, relativePath);
      fs.mkdirSync(path.dirname(output), { recursive: true });
      fs.writeFileSync(output, content);
    }
    process.stdout.write(`updated ${artifacts.size} source inventory artifacts\n`);
    return;
  }
  if (process.argv.length === 3 && process.argv[2] === "--check") {
    assertOwnedOutputClosure(repoRoot, artifacts);
    process.stdout.write(`verified ${artifacts.size} source inventory artifacts\n`);
    return;
  }
  throw new Error("usage: generate-source-inventory.mjs [--check]");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
