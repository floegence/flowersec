#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const schema = "flowersec-main-gate-receipt-v1";
const gateFiles = [
  "Makefile",
  ".githooks/pre-push",
  "scripts/check-security-makefile.mjs",
  "scripts/check-transport-v2-evidence.sh",
  "scripts/main-gate-receipt.mjs",
  "scripts/push-main.sh",
  "scripts/release.sh",
  "scripts/run-final-lanes.mjs",
  "scripts/run-final-stage.mjs",
];

function fail(message, status = 1) {
  console.error(message);
  process.exit(status);
}

function git(args, cwd) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    fail(`git ${args.join(" ")} failed: ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

function parseArguments(argv) {
  const command = argv[0];
  if (command !== "write" && command !== "verify") {
    fail("usage: main-gate-receipt.mjs <write|verify> --head SHA [options]", 2);
  }
  const options = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined || options.has(name)) {
      fail("main gate receipt arguments must be unique --name value pairs", 2);
    }
    options.set(name, value);
  }
  const allowed = new Set([
    "--head",
    "--origin-main",
    "--remote-main",
    "--evidence-report",
    "--evidence-base",
  ]);
  for (const name of options.keys()) {
    if (!allowed.has(name)) fail(`unknown main gate receipt option: ${name}`, 2);
  }
  return { command, options };
}

function requireSHA(value, name) {
  if (!/^[0-9a-f]{40}$/.test(value ?? "")) {
    fail(`${name} must be a full lowercase Git SHA`, 2);
  }
  return value;
}

function digestBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function digestFile(file) {
  const hash = createHash("sha256");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const descriptor = fs.openSync(file, "r");
  try {
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      hash.update(buffer.subarray(0, count));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest("hex");
}

function evidenceDigest(reportPath) {
  if (!path.isAbsolute(reportPath ?? "") || path.basename(reportPath) !== "report.json") {
    fail("--evidence-report must name an absolute report.json", 2);
  }
  let stat;
  try {
    stat = fs.lstatSync(reportPath);
  } catch {
    fail("signed evidence report does not exist", 2);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail("signed evidence report must be a regular non-symlink file", 2);
  }
  return digestBytes(fs.readFileSync(reportPath));
}

function evidenceClosureDigest(reportPath) {
  const root = path.dirname(reportPath);
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail("signed evidence directory must be a real directory", 2);
  }
  const records = [];
  const walk = (directory, relativeDirectory = "") => {
    const entries = fs.readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      Buffer.compare(Buffer.from(left.name), Buffer.from(right.name))
    );
    for (const entry of entries) {
      const relative = relativeDirectory === "" ? entry.name : `${relativeDirectory}/${entry.name}`;
      const absolute = path.join(directory, entry.name);
      const stat = fs.lstatSync(absolute);
      if (stat.isSymbolicLink()) fail(`signed evidence closure contains a symlink: ${relative}`, 2);
      if (stat.isDirectory()) {
        walk(absolute, relative);
      } else if (stat.isFile()) {
        records.push(JSON.stringify([relative, stat.size, digestFile(absolute)]));
      } else {
        fail(`signed evidence closure contains a non-regular entry: ${relative}`, 2);
      }
    }
  };
  walk(root);
  return digestBytes(`${records.join("\n")}\n`);
}

function repositoryState() {
  const root = git(["rev-parse", "--show-toplevel"], process.cwd());
  const commonDirectory = git(
    ["rev-parse", "--path-format=absolute", "--git-common-dir"],
    root,
  );
  return { root, commonDirectory };
}

function gateGraphDigest(root, head) {
  const listing = git(
    ["ls-tree", "-r", "--full-tree", head, "--", ...gateFiles],
    root,
  );
  const listedFiles = listing
    .split("\n")
    .filter(Boolean)
    .map((line) => line.slice(line.indexOf("\t") + 1));
  if (listedFiles.length !== gateFiles.length) {
    fail("main gate graph inventory is incomplete");
  }
  for (const file of gateFiles) {
    if (!listedFiles.includes(file)) fail(`main gate graph omits ${file}`);
  }
  return digestBytes(`${listing}\n`);
}

function receiptLocation(commonDirectory, head) {
  const directory = path.join(commonDirectory, "flowersec", "main-gate-receipts");
  return { directory, receipt: path.join(directory, `${head}.json`) };
}

function readReceipt(receiptPath, allowMissing = false) {
  let stat;
  try {
    stat = fs.lstatSync(receiptPath);
  } catch (error) {
    if (allowMissing && error?.code === "ENOENT") fail("main gate receipt is missing", 3);
    fail("main gate receipt is missing");
  }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o400) {
    fail("main gate receipt must be a read-only regular non-symlink file");
  }
  let value;
  try {
    value = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  } catch {
    fail("main gate receipt is not valid JSON");
  }
  const expectedKeys = [
    "completedAt",
    "evidenceBaseSHA",
    "evidenceClosureSHA256",
    "evidenceReportSHA256",
    "gateCommand",
    "gateGraphSHA256",
    "headSHA",
    "originMainAtStart",
    "result",
    "schema",
    "treeSHA",
  ];
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== "object"
    || Object.keys(value).sort().join("\n") !== expectedKeys.join("\n")
  ) {
    fail("main gate receipt has an invalid closed schema");
  }
  return value;
}

function expectedState(root, head, options, requireEvidence) {
  const actualHead = git(["rev-parse", "HEAD"], root);
  if (actualHead !== head) fail("main gate receipt HEAD does not match the checkout");
  const expected = {
    headSHA: head,
    treeSHA: git(["rev-parse", `${head}^{tree}`], root),
    gateGraphSHA256: gateGraphDigest(root, head),
  };
  const report = options.get("--evidence-report");
  const base = options.get("--evidence-base");
  if (requireEvidence || report !== undefined || base !== undefined) {
    expected.evidenceReportSHA256 = evidenceDigest(report);
    expected.evidenceClosureSHA256 = evidenceClosureDigest(report);
    expected.evidenceBaseSHA = requireSHA(base, "--evidence-base");
  }
  return expected;
}

function verifyReceipt(value, expected, options) {
  if (value.schema !== schema || value.result !== "success" || value.gateCommand !== "make check") {
    fail("main gate receipt does not record a successful complete gate");
  }
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (value[key] !== expectedValue) fail(`main gate receipt ${key} mismatch`);
  }
  if (!/^[0-9a-f]{40}$/.test(value.originMainAtStart)) {
    fail("main gate receipt originMainAtStart is invalid");
  }
  if (!/^[0-9a-f]{64}$/.test(value.evidenceReportSHA256)) {
    fail("main gate receipt evidenceReportSHA256 is invalid");
  }
  if (!/^[0-9a-f]{64}$/.test(value.evidenceClosureSHA256)) {
    fail("main gate receipt evidenceClosureSHA256 is invalid");
  }
  if (!/^[0-9a-f]{40}$/.test(value.evidenceBaseSHA)) {
    fail("main gate receipt evidenceBaseSHA is invalid");
  }
  const remoteMain = options.get("--remote-main");
  if (remoteMain !== undefined) {
    requireSHA(remoteMain, "--remote-main");
    if (remoteMain !== value.originMainAtStart && remoteMain !== value.headSHA) {
      fail("main gate receipt does not match the remote main boundary");
    }
  }
}

const { command, options } = parseArguments(process.argv.slice(2));
const head = requireSHA(options.get("--head"), "--head");
const { root, commonDirectory } = repositoryState();
const { directory, receipt } = receiptLocation(commonDirectory, head);

if (command === "verify") {
  const value = readReceipt(receipt, true);
  verifyReceipt(value, expectedState(root, head, options, false), options);
  console.log(`verified main gate receipt for ${head}`);
  process.exit(0);
}

const originMain = requireSHA(options.get("--origin-main"), "--origin-main");
const expected = expectedState(root, head, options, true);
const value = {
  schema,
  headSHA: head,
  treeSHA: expected.treeSHA,
  originMainAtStart: originMain,
  gateGraphSHA256: expected.gateGraphSHA256,
  gateCommand: "make check",
  result: "success",
  evidenceReportSHA256: expected.evidenceReportSHA256,
  evidenceClosureSHA256: expected.evidenceClosureSHA256,
  evidenceBaseSHA: expected.evidenceBaseSHA,
  completedAt: new Date().toISOString(),
};

fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
const directoryStat = fs.lstatSync(directory);
if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) {
  fail("main gate receipt directory must be a real directory");
}
if (fs.existsSync(receipt)) {
  const existing = readReceipt(receipt);
  verifyReceipt(existing, expected, options);
  console.log(`reused main gate receipt for ${head}`);
  process.exit(0);
}

const temporary = path.join(directory, `.${head}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`);
let temporaryCreated = false;
try {
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  temporaryCreated = true;
  fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
  fs.fsyncSync(descriptor);
  fs.closeSync(descriptor);
  fs.chmodSync(temporary, 0o400);
  fs.linkSync(temporary, receipt);
  fs.unlinkSync(temporary);
  temporaryCreated = false;
  const directoryDescriptor = fs.openSync(directory, "r");
  fs.fsyncSync(directoryDescriptor);
  fs.closeSync(directoryDescriptor);
} finally {
  if (temporaryCreated) fs.rmSync(temporary, { force: true });
}
console.log(`wrote main gate receipt for ${head}`);
