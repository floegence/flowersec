#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const ENTRY_KEYS = [
  "boundary",
  "conformanceTests",
  "ecosystem",
  "package",
  "platforms",
  "protocol",
  "publicApiOnly",
  "requiredCapabilities",
  "scope",
  "upgradeGroup",
];
const ECOSYSTEMS = new Set(["cargo", "gomod", "npm", "swiftpm", "vendored-cargo"]);
const QUINN_RELEASES = new Map([
  ["quinn", ["0.11.11", "0c1a41e437b6bbd489372cd4971de128e85c855f56c57f283d20ff016cf7c0a8"]],
  ["quinn-proto", ["0.11.19", "0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe"]],
]);
const SQLITE_DRIVER = "modernc.org/sqlite";
const VENDORED_SOURCES = new Map([
  ["snow", ["test-support/snow", "0.10.0", "599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82", "src/lib.rs"]],
]);
const SQLITE_BOUNDARIES = new Map([
  ["go-optional-credential-store-v5", "protocol/v5-credential-sqlite-go"],
  ["go-durable-admission-ledger-v4", "protocol/v4-admission-sqlite-go"],
]);
const RETIRED_CAPABILITY_TEST_IDS = [
  "carrier/typescript-raw-quic-direct",
  "carrier/typescript-raw-quic-tunnel",
  "carrier/rust-webtransport-direct",
  "carrier/rust-webtransport-tunnel",
  "integration/typescript/node-webtransport",
  "carrier/typescript-webtransport-tunnel-runtime",
  "interop/typescript-go/webtransport/direct",
  "interop/typescript-go/webtransport/tunnel",
];
const HIGH_IMPACT = {
  cargo: new Set([
    "curve25519-dalek",
    "aes-gcm", "hkdf", "hmac", "idna", "idna_adapter", "idna_mapping", "p256", "quinn",
    "napi", "napi-build", "napi-derive", "quinn-proto", "quinn-udp", "ring", "rustls", "tokio-tungstenite", "unicode-normalization",
    "wtransport", "x25519-dalek", "yamux",
  ]),
  gomod: new Set([
    SQLITE_DRIVER,
    "filippo.io/edwards25519",
    "github.com/gorilla/websocket", "github.com/libp2p/go-yamux/v5", "github.com/quic-go/quic-go",
    "github.com/quic-go/webtransport-go", "golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys",
    "golang.org/x/text",
  ]),
  npm: new Set([
    "@fails-components/webtransport", "@fails-components/webtransport-transport-http3-quiche", "@matrixai/quic",
    "@floegence/flowersec-node-native", "@noble/ciphers", "@noble/curves", "@noble/hashes", "tr46", "ws",
  ]),
  swiftpm: new Set(["async-http-client", "swift-crypto", "swift-nio", "swift-nio-ssl", "swift-sodium"]),
  "vendored-cargo": new Set(),
};

function fail(message) {
  throw new Error(message);
}

function read(root, relativePath) {
  return fs.readFileSync(path.join(root, relativePath), "utf8");
}

function readJSON(root, relativePath) {
  try {
    return JSON.parse(read(root, relativePath));
  } catch (error) {
    fail(`${relativePath} is not valid JSON: ${error.message}`);
  }
}

function assertStringList(value, label) {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    fail(`${label} must be a non-empty string array`);
  }
  if (new Set(value).size !== value.length) fail(`${label} must not contain duplicates`);
}

function validateContract(contract) {
  if (contract === null || typeof contract !== "object" || Array.isArray(contract)) fail("dependency contract must be an object");
  const keys = Object.keys(contract).sort();
  if (JSON.stringify(keys) !== JSON.stringify(["dependencies", "version"])) {
    fail("dependency contract must contain exactly version and dependencies");
  }
  if (contract.version !== 1) fail("dependency contract version must be 1");
  if (!Array.isArray(contract.dependencies) || contract.dependencies.length === 0) fail("dependency contract dependencies must be non-empty");
  const identities = new Set();
  for (const [index, entry] of contract.dependencies.entries()) {
    const label = `dependencies[${index}]`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) fail(`${label} must be an object`);
    const entryKeys = Object.keys(entry).sort();
    if (JSON.stringify(entryKeys) !== JSON.stringify([...ENTRY_KEYS].sort())) fail(`${label} has invalid keys`);
    if (!ECOSYSTEMS.has(entry.ecosystem)) fail(`${label}.ecosystem is invalid`);
    for (const key of ["package", "boundary", "scope", "protocol"]) {
      if (typeof entry[key] !== "string" || entry[key].length === 0) fail(`${label}.${key} must be a non-empty string`);
    }
    if (entry.scope !== "production" && entry.scope !== "tooling") fail(`${label}.scope is invalid`);
    if (entry.publicApiOnly !== true) fail(`${label}.publicApiOnly must be true`);
    if (entry.upgradeGroup !== null && (typeof entry.upgradeGroup !== "string" || entry.upgradeGroup.length === 0)) {
      fail(`${label}.upgradeGroup must be a non-empty string or null`);
    }
    assertStringList(entry.requiredCapabilities, `${label}.requiredCapabilities`);
    assertStringList(entry.platforms, `${label}.platforms`);
    assertStringList(entry.conformanceTests, `${label}.conformanceTests`);
    let identity = `${entry.ecosystem}:${entry.package}`;
    if (entry.ecosystem === "gomod" && entry.package === SQLITE_DRIVER) {
      const testID = SQLITE_BOUNDARIES.get(entry.boundary);
      if (!testID) fail(`${label} has unknown SQLite boundary ${entry.boundary}`);
      if (!entry.conformanceTests.includes(testID) || [...SQLITE_BOUNDARIES.values()].some((id) => id !== testID && entry.conformanceTests.includes(id))) {
        fail(`${entry.boundary} must use its own SQLite conformance test ${testID}`);
      }
      identity += `:${entry.boundary}`;
    }
    if (identities.has(identity)) fail(`duplicate dependency contract ${identity}`);
    identities.add(identity);
  }
}

function parseGoDependencies(source) {
  const dependencies = new Map();
  let inRequire = false;
  for (const rawLine of source.split("\n")) {
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    if (line === "require (") {
      inRequire = true;
      continue;
    }
    if (inRequire && line === ")") {
      inRequire = false;
      continue;
    }
    const match = inRequire ? /^(\S+)\s+v\S+/.exec(line) : /^require\s+(\S+)\s+v\S+/.exec(line);
    if (match !== null) {
      const version = line.split(/\s+/).at(-1);
      dependencies.set(match[1], version);
    }
  }
  return dependencies;
}

function parseCargoDependencies(source) {
  const dependencies = new Map();
  let dependencySection = false;
  for (const rawLine of source.split("\n")) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (/^\[.*\]$/.test(line)) {
      dependencySection = line === "[dependencies]" || line === "[build-dependencies]";
      continue;
    }
    if (!dependencySection || line.length === 0) continue;
    const match = /^([A-Za-z0-9_-]+)\s*=/.exec(line);
    if (match !== null) {
      const declaration = line.slice(line.indexOf("=") + 1).trim();
      const name = /(?:\{|,)\s*package\s*=\s*["']([A-Za-z0-9_-]+)["']/.exec(declaration)?.[1] ?? match[1];
      dependencies.set(name, declaration);
    }
  }
  return dependencies;
}

const cargoManifestContexts = [
  ["flowersec-rust/Cargo.toml", "flowersec-rust/Cargo.lock"],
  ["flowersec-native-transport/Cargo.toml", "flowersec-native-transport/Cargo.lock"],
  ["flowersec-node-native/Cargo.toml", "flowersec-node-native/Cargo.lock"],
];

function cargoContexts(root) {
  return cargoManifestContexts.flatMap(([manifest, lockfile]) => {
    if (!fs.existsSync(path.join(root, manifest))) return [];
    if (!fs.existsSync(path.join(root, lockfile))) {
      fail(`cargo manifest ${manifest} is missing its lockfile ${lockfile}`);
    }
    return [{ manifest, lockfile }];
  });
}

function localNpmPackages(root) {
  const result = new Map();
  for (const relative of [
    "flowersec-node-native/package.json",
    "flowersec-node-native/npm/darwin-arm64/package.json",
    "flowersec-node-native/npm/darwin-x64/package.json",
    "flowersec-node-native/npm/linux-arm64-gnu/package.json",
    "flowersec-node-native/npm/linux-x64-gnu/package.json",
  ]) {
    const file = path.join(root, relative);
    if (!fs.existsSync(file)) continue;
    const metadata = readJSON(root, relative);
    if (typeof metadata.name !== "string" || typeof metadata.version !== "string") {
      fail(`${relative} must declare an exact npm name and version`);
    }
    result.set(metadata.name, { relative, version: metadata.version });
  }
  return result;
}

function parseCargoLockPackages(source) {
  const packages = new Set();
  for (const block of source.split("[[package]]").slice(1)) {
    const match = /^\s*name\s*=\s*"([^"]+)"/m.exec(block);
    if (match !== null) packages.add(match[1]);
  }
  return packages;
}

function checkQuinnLock(root, lockfile, errors) {
  const packages = read(root, lockfile).split("[[package]]").slice(1);
  for (const [name, [version, checksum]] of QUINN_RELEASES) {
    const matches = packages.filter((block) => block.split("\n").includes(`name = "${name}"`));
    const fields = matches[0]?.split("\n") ?? [];
    if (matches.length !== 1 || !fields.includes(`version = "${version}"`) || !fields.includes(`checksum = "${checksum}"`)
      || !fields.includes('source = "registry+https://github.com/rust-lang/crates.io-index"')) {
      errors.push(`${lockfile} must lock the reviewed crates.io release of ${name}@${version}`);
    }
  }
}

function vendoredCargo(root) {
  const result = new Map();
  const inventoryPath = "sbom/source-inventory.json";
  const components = fs.existsSync(path.join(root, inventoryPath)) ? readJSON(root, inventoryPath).components : [];
  for (const component of components) {
    if (component.ecosystem !== "cargo" || !component.vendored) continue;
    const expected = VENDORED_SOURCES.get(component.name);
    if (!expected || result.has(component.name)) fail(`unexpected vendored Cargo component ${component.name}`);
    const [directory, version, upstreamHash, entryPoint] = expected;
    const evidence = component.vendored;
    if (evidence.directory !== directory || component.version !== version || evidence.upstreamArchiveSha256 !== upstreamHash
      || component.source !== `https://static.crates.io/crates/${component.name}/${component.name}-${version}.crate`
      || component.review?.decision !== "approved" || component.review.sourceEvidenceKind !== "modified-vendored-cargo-source"
      || component.review.sourceEvidenceValue !== `${JSON.stringify(evidence, null, 2)}\n`) {
      fail(`invalid vendored Cargo provenance for ${component.name}`);
    }
    const tree = path.join(fs.realpathSync(root), directory);
    if (fs.realpathSync(tree) !== tree) fail(`vendored Cargo directory cannot be a symlink: ${directory}`);
    const pending = [""];
    const files = [];
    while (pending.length > 0) {
      const relative = pending.pop();
      for (const entry of fs.readdirSync(path.join(tree, relative), { withFileTypes: true })) {
        const file = path.posix.join(relative, entry.name);
        if (entry.isDirectory()) pending.push(file);
        else if (entry.isFile()) files.push(file);
        else fail(`unexpected vendored Cargo source: ${directory}/${file}`);
      }
    }
    const hash = (contents) => createHash("sha256").update(contents).digest("hex");
    const entries = files.sort().map((file) => [file, hash(fs.readFileSync(path.join(tree, file)))]);
    if (!files.includes(entryPoint) || hash(`${JSON.stringify(entries, null, 2)}\n`) !== evidence.sourceTreeSha256) {
      fail(`vendored Cargo source tree differs from reviewed ${component.name} provenance`);
    }
    result.set(component.name, version);
  }
  for (const [name, [directory]] of VENDORED_SOURCES) {
    if (!result.has(name) && fs.existsSync(path.join(root, directory))) {
      fail(`missing vendored Cargo provenance for ${name}`);
    }
  }
  return result;
}

function parseGoSumSelections(source) {
  const selections = new Set();
  for (const line of source.split("\n")) {
    const match = /^(\S+)\s+(v\S+)\s+h1:/.exec(line);
    if (match !== null) selections.add(`${match[1]}@${match[2]}`);
  }
  return selections;
}

function swiftPins(lock) {
  const result = new Map();
  for (const pin of lock.pins ?? []) {
    if (typeof pin.identity !== "string" || pin.state === null || typeof pin.state !== "object") continue;
    result.set(pin.identity, `${pin.state.version ?? ""}@${pin.state.revision ?? ""}`);
  }
  return result;
}

function versionTuple(value) {
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?$/.exec(value);
  return match === null ? null : [Number(match[1]), Number(match[2] ?? 0), Number(match[3] ?? 0)];
}

function compareVersions(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function minimumEngine(engine, label) {
  if (typeof engine !== "string") fail(`${label} has no Node engine`);
  const versions = [...engine.matchAll(/(?:^|[<>=~^|\s])v?(\d+(?:\.\d+){0,2})/g)]
    .map((match) => versionTuple(match[1]))
    .filter((value) => value !== null)
    .sort(compareVersions);
  if (versions.length === 0) fail(`${label} has unsupported Node engine ${engine}`);
  return versions[0];
}

function walkFiles(directory, predicate) {
  if (!fs.existsSync(directory)) return [];
  const result = [];
  const pending = [directory];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if ([".git", "node_modules", "target", ".build", "dist"].includes(entry.name)) continue;
      const target = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(target);
      else if (entry.isFile() && predicate(target)) result.push(target);
    }
  }
  return result;
}

function registeredTestIDs(source) {
  const result = new Set();
  for (const match of source.matchAll(/(?:commandEntry|commandEntryWithEnvironment|vitestEntry|browserSmokeEntry|browserCompatibilityEntry|privilegedGoTestEntry|throughputEntry|flowersecWeaknetEntry)\(\s*"([^"]+)"/g)) {
    result.add(match[1]);
  }
  return result;
}

function check(root) {
  const errors = [];
  const record = (callback) => {
    try {
      callback();
    } catch (error) {
      errors.push(error.message);
    }
  };
  const contract = readJSON(root, "stability/dependency_contracts.json");
  validateContract(contract);

  const goCore = parseGoDependencies(read(root, "flowersec-go/go.mod"));
  if (goCore.has(SQLITE_DRIVER)) errors.push(`${SQLITE_DRIVER} must not be required by the Go core module`);
  const sqliteModule = "flowersec-go/adapters/sqlite";
  const goSQLite = fs.existsSync(path.join(root, sqliteModule, "go.mod"))
    ? parseGoDependencies(read(root, `${sqliteModule}/go.mod`)) : new Map();
  const npmManifest = readJSON(root, "flowersec-ts/package.json");
  const npmLock = readJSON(root, "flowersec-ts/package-lock.json");
  const rootSwiftPins = swiftPins(readJSON(root, "Package.resolved"));
  const exampleSwiftPins = swiftPins(readJSON(root, "examples/swift/Package.resolved"));
  const npmDependencies = new Map([
    ...Object.entries(npmManifest.dependencies ?? {}),
    ...Object.entries(npmManifest.optionalDependencies ?? {}),
  ]);
  const cargoSources = cargoContexts(root);
  if (fs.existsSync(path.join(root, "flowersec-native-transport/Cargo.toml"))) {
    for (const lockfile of [...cargoSources.map(({ lockfile }) => lockfile), "flowersec-rust/fuzz/Cargo.lock", "examples/rust/Cargo.lock"]) {
      if (fs.existsSync(path.join(root, lockfile))) checkQuinnLock(root, lockfile, errors);
    }
    for (const directory of ["quic_proto", "quic_provider"]) {
      if (fs.existsSync(path.join(root, "flowersec-native-transport/src", directory))) errors.push(`embedded Quinn source is forbidden: ${directory}`);
    }
  }
  const cargoDependencies = new Map();
  for (const context of cargoSources) {
    const manifest = read(root, context.manifest);
    const locked = parseCargoLockPackages(read(root, context.lockfile));
    if (/\[patch\.crates-io\]/.test(manifest)) errors.push(`local Cargo protocol patch is forbidden in ${context.manifest}`);
    for (const [name, version] of parseCargoDependencies(manifest)) {
      cargoDependencies.set(name, version);
      if (!locked.has(name)) errors.push(`cargo dependency ${name} is missing from ${context.lockfile}`);
    }
  }
  const manifests = {
    cargo: cargoDependencies,
    gomod: goCore,
    npm: npmDependencies,
    swiftpm: rootSwiftPins,
    "vendored-cargo": vendoredCargo(root),
  };
  const goSumSelections = parseGoSumSelections(read(root, "flowersec-go/go.sum"));
  const sqliteSumPath = `${sqliteModule}/go.sum`;
  const sqliteSumSelections = goSQLite.has(SQLITE_DRIVER) ? parseGoSumSelections(read(root, sqliteSumPath)) : new Set();
  const contracts = new Set(contract.dependencies.map((entry) => `${entry.ecosystem}:${entry.package}`));
  const localPackages = localNpmPackages(root);

  for (const entry of contract.dependencies) {
    const stagedNativeOptional = entry.ecosystem === "npm"
      && entry.package === "@floegence/flowersec-node-native"
      && localPackages.has(entry.package)
      && !npmDependencies.has(entry.package);
    const optionalSQLite = entry.ecosystem === "gomod" && entry.package === SQLITE_DRIVER;
    const declarations = optionalSQLite ? goSQLite : manifests[entry.ecosystem];
    if (!declarations.has(entry.package) && !stagedNativeOptional) {
      errors.push(`${entry.ecosystem} dependency ${entry.package} is not present in its production manifest`);
    }
    if (entry.ecosystem === "gomod") {
      const version = declarations.get(entry.package);
      const sumPath = optionalSQLite ? sqliteSumPath : "flowersec-go/go.sum";
      if (version !== undefined && !(optionalSQLite ? sqliteSumSelections : goSumSelections).has(`${entry.package}@${version}`)) {
        errors.push(`gomod dependency ${entry.package}@${version} is missing from ${sumPath}`);
      }
    }
    if (entry.ecosystem === "npm") {
      const metadata = npmLock.packages?.[`node_modules/${entry.package}`];
      if (metadata === undefined) {
        if (!stagedNativeOptional) errors.push(`npm dependency ${entry.package} is missing from flowersec-ts/package-lock.json`);
        continue;
      }
      if (typeof metadata.version !== "string" || typeof metadata.integrity !== "string") {
        const local = localPackages.get(entry.package);
        if (local === undefined) {
          errors.push(`npm dependency ${entry.package} has no exact version and integrity in flowersec-ts/package-lock.json`);
        } else if (metadata.version !== undefined && metadata.version !== local.version) {
          errors.push(`npm dependency ${entry.package} lock version differs from ${local.relative}`);
        }
      }
    }
  }
  if (goSQLite.has(SQLITE_DRIVER) || fs.existsSync(path.join(root, "flowersec-go/internal/v4build/go.work"))) {
    const boundaries = new Set(contract.dependencies.filter((entry) => entry.ecosystem === "gomod" && entry.package === SQLITE_DRIVER).map((entry) => entry.boundary));
    for (const boundary of SQLITE_BOUNDARIES.keys()) {
      if (!boundaries.has(boundary)) errors.push(`${SQLITE_DRIVER} has no dependency contract for ${boundary}`);
    }
  }
  for (const [ecosystem, packages] of Object.entries(manifests)) {
    for (const packageName of packages.keys()) {
      const highImpact = HIGH_IMPACT[ecosystem].has(packageName)
        || ecosystem === "cargo" && /(?:quic|webtransport|websocket|rustls|crypto|idna|yamux|url)/i.test(packageName)
        || ecosystem === "npm" && /(?:quic|webtransport|websocket|crypto|cipher|curve|hash|idna)/i.test(packageName);
      if (highImpact && !contracts.has(`${ecosystem}:${packageName}`)) {
        errors.push(`high-impact ${ecosystem} dependency ${packageName} has no contract`);
      }
    }
  }

  const registryIDs = registeredTestIDs(read(root, "flowersec-go/internal/cmd/flowersec-test/registry.go"));
  for (const testID of RETIRED_CAPABILITY_TEST_IDS) {
    if (registryIDs.has(testID)) errors.push(`retired unsupported capability test ID ${testID} remains registered`);
  }
  for (const entry of contract.dependencies) {
    for (const testID of entry.conformanceTests) {
      if (!registryIDs.has(testID)) errors.push(`unknown conformance test ID ${testID} for ${entry.ecosystem}:${entry.package}`);
    }
  }

  const groups = new Map();
  for (const entry of contract.dependencies) {
    if (entry.upgradeGroup === null) continue;
    const members = groups.get(entry.upgradeGroup) ?? [];
    members.push(`${entry.ecosystem}:${entry.package}`);
    groups.set(entry.upgradeGroup, members);
  }
  for (const [group, members] of groups) {
    if (members.length < 2) errors.push(`upgrade group ${group} must contain at least two dependencies`);
  }

  const vendorRoot = path.join(root, "flowersec-rust/vendor");
  if (fs.existsSync(vendorRoot)) {
    const entries = walkFiles(vendorRoot, () => true);
    if (entries.length > 0) errors.push("vendored transport/protocol stack is forbidden");
  }

  const productionTypeScript = walkFiles(path.join(root, "flowersec-ts/src"), (file) => file.endsWith(".ts") && !file.endsWith(".test.ts"));
  for (const file of productionTypeScript) {
    const source = fs.readFileSync(file, "utf8");
    if (/from\s+["']@matrixai\/quic\/(?!package\.json)[^"']+["']|import\(["']@matrixai\/quic\//.test(source)) {
      errors.push(`private dependency subpath in ${path.relative(root, file)}`);
    }
    if (source.includes("@matrixai/quic") && /\.(?:conn|send|dgramSendVec|dgramRecvVec|dgramMaxWritableLen)\b/.test(source)) {
      errors.push(`private native field in ${path.relative(root, file)}`);
    }
  }

  record(() => {
    const projectMinimum = minimumEngine(npmManifest.engines?.node, "flowersec-ts");
    for (const packageName of Object.keys(npmManifest.dependencies ?? {})) {
      const metadata = npmLock.packages?.[`node_modules/${packageName}`];
      if (metadata?.engines?.node === undefined) continue;
      const dependencyMinimum = minimumEngine(metadata.engines.node, packageName);
      if (compareVersions(projectMinimum, dependencyMinimum) < 0) {
        fail(`Node engine ${projectMinimum.join(".")} is below ${packageName} minimum ${dependencyMinimum.join(".")}`);
      }
    }
  });

  for (const [identity, rootPin] of rootSwiftPins) {
    const examplePin = exampleSwiftPins.get(identity);
    if (examplePin !== undefined && examplePin !== rootPin) errors.push(`Swift shared pin ${identity} differs: ${rootPin} != ${examplePin}`);
  }

  const legacyFiles = [
    ...walkFiles(path.join(root, "flowersec-rust"), (file) => /\.(?:rs|toml|md)$/.test(file)),
    ...walkFiles(path.join(root, "flowersec-ts/src"), (file) => /\.(?:ts|js|mjs)$/.test(file) && !file.endsWith(".test.ts")),
    ...walkFiles(path.join(root, "scripts"), (file) => /\.(?:js|mjs)$/.test(file) && !path.basename(file).startsWith("check-dependency-contracts.")),
  ];
  for (const file of legacyFiles) {
    const source = fs.readFileSync(file, "utf8");
    if (/:protocol\s*(?:=|",|"\s*:\s*)\s*["']?webtransport["']?(?!-h3)|sec-webtransport-http3-draft[^\n]*draft02/i.test(source)) {
      errors.push(`legacy WebTransport wire in ${path.relative(root, file)}`);
    }
    if (/legacy\w*(?:parser|wire|fallback)|(?:parser|wire|fallback)\w*legacy/i.test(source)) {
      errors.push(`legacy parser or fallback in ${path.relative(root, file)}`);
    }
  }

  for (const forbidden of ["wtransport", "@fails-components/webtransport", "@fails-components/webtransport-transport-http3-quiche"]) {
    const ecosystem = forbidden.startsWith("@") ? "npm" : "cargo";
    if (manifests[ecosystem].has(forbidden)) errors.push(`forbidden protocol dependency ${ecosystem}:${forbidden}`);
  }

  if (errors.length > 0) fail(errors.join("\n"));
}

function parseRoot(arguments_) {
  if (arguments_.length === 0) return path.resolve(import.meta.dirname, "..");
  if (arguments_.length === 2 && arguments_[0] === "--root") return path.resolve(arguments_[1]);
  fail("usage: check-dependency-contracts.mjs [--root <repository-root>]");
}

try {
  const root = parseRoot(process.argv.slice(2));
  check(root);
  process.stdout.write("Dependency contracts are satisfied.\n");
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
