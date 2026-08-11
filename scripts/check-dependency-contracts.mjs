#!/usr/bin/env node

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
const ECOSYSTEMS = new Set(["cargo", "gomod", "npm", "swiftpm"]);
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
    "aes-gcm", "hkdf", "hmac", "idna", "idna_adapter", "idna_mapping", "p256", "quinn",
    "ring", "rustls", "tokio-tungstenite", "unicode-normalization", "wtransport", "x25519-dalek", "yamux",
  ]),
  gomod: new Set([
    "github.com/gorilla/websocket", "github.com/libp2p/go-yamux/v5", "github.com/quic-go/quic-go",
    "github.com/quic-go/webtransport-go", "golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys",
    "golang.org/x/text",
  ]),
  npm: new Set([
    "@fails-components/webtransport", "@fails-components/webtransport-transport-http3-quiche", "@matrixai/quic",
    "@noble/ciphers", "@noble/curves", "@noble/hashes", "tr46", "ws",
  ]),
  swiftpm: new Set(["async-http-client", "swift-crypto", "swift-nio", "swift-nio-ssl"]),
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
    const identity = `${entry.ecosystem}:${entry.package}`;
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
  let inDependencies = false;
  for (const rawLine of source.split("\n")) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (/^\[.*\]$/.test(line)) {
      inDependencies = line === "[dependencies]";
      continue;
    }
    if (!inDependencies || line.length === 0) continue;
    const match = /^([A-Za-z0-9_-]+)\s*=/.exec(line);
    if (match !== null) dependencies.set(match[1], line.slice(line.indexOf("=") + 1).trim());
  }
  return dependencies;
}

function parseCargoLockPackages(source) {
  const packages = new Set();
  for (const block of source.split("[[package]]").slice(1)) {
    const match = /^\s*name\s*=\s*"([^"]+)"/m.exec(block);
    if (match !== null) packages.add(match[1]);
  }
  return packages;
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
  for (const match of source.matchAll(/(?:commandEntry|commandEntryWithEnvironment|vitestEntry|browserSmokeEntry|browserCompatibilityEntry|privilegedGoTestEntry)\(\s*"([^"]+)"/g)) {
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

  const goSource = read(root, "flowersec-go/go.mod");
  const cargoSource = read(root, "flowersec-rust/Cargo.toml");
  const npmManifest = readJSON(root, "flowersec-ts/package.json");
  const npmLock = readJSON(root, "flowersec-ts/package-lock.json");
  const rootSwiftPins = swiftPins(readJSON(root, "Package.resolved"));
  const exampleSwiftPins = swiftPins(readJSON(root, "examples/swift/Package.resolved"));
  const npmDependencies = new Map(Object.entries(npmManifest.dependencies ?? {}));
  const manifests = {
    cargo: parseCargoDependencies(cargoSource),
    gomod: parseGoDependencies(goSource),
    npm: npmDependencies,
    swiftpm: rootSwiftPins,
  };
  const cargoLockPackages = parseCargoLockPackages(read(root, "flowersec-rust/Cargo.lock"));
  const goSumSelections = parseGoSumSelections(read(root, "flowersec-go/go.sum"));
  const contracts = new Map(contract.dependencies.map((entry) => [`${entry.ecosystem}:${entry.package}`, entry]));

  for (const entry of contract.dependencies) {
    if (!manifests[entry.ecosystem].has(entry.package)) {
      errors.push(`${entry.ecosystem} dependency ${entry.package} is not present in its production manifest`);
    }
    if (entry.ecosystem === "cargo" && !cargoLockPackages.has(entry.package)) {
      errors.push(`cargo dependency ${entry.package} is missing from flowersec-rust/Cargo.lock`);
    }
    if (entry.ecosystem === "gomod") {
      const version = manifests.gomod.get(entry.package);
      if (version !== undefined && !goSumSelections.has(`${entry.package}@${version}`)) {
        errors.push(`gomod dependency ${entry.package}@${version} is missing from flowersec-go/go.sum`);
      }
    }
    if (entry.ecosystem === "npm" && npmLock.packages?.[`node_modules/${entry.package}`] === undefined) {
      errors.push(`npm dependency ${entry.package} is missing from flowersec-ts/package-lock.json`);
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

  if (/\[patch\.crates-io\]/.test(cargoSource)) errors.push("local Cargo protocol patch is forbidden");
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
