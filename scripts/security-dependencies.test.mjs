import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const sourceRoot = path.resolve(import.meta.dirname, "..");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
    env: { ...process.env, ...options.env },
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout;
}

function parseReleaseVersion(actual, label) {
  const match = /^(?:v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(actual);
  assert.ok(match, `${label} has invalid release version ${actual}`);
  return match.slice(1).map(Number);
}

function assertVersionAtLeast(actual, minimum, label) {
  const actualParts = parseReleaseVersion(actual, label);
  const minimumParts = parseReleaseVersion(minimum, `${label} minimum`);
  for (let index = 0; index < minimumParts.length; index += 1) {
    if (actualParts[index] > minimumParts[index]) return;
    if (actualParts[index] < minimumParts[index]) {
      assert.fail(`${label} ${actual} is below the patched minimum ${minimum}`);
    }
  }
}

function effectiveGoModuleVersion(metadata, label) {
  const selected = metadata.Replace ?? metadata;
  assert.equal(typeof selected.Version, "string", `${label} has no selected version`);
  return selected.Version;
}

function readGoModuleVersion(moduleDir, modulePath, label, extraEnvironment = {}) {
  const metadata = JSON.parse(run(
    "go",
    ["list", "-m", "-json", "-mod=readonly", modulePath],
    {
      cwd: moduleDir,
      env: { ...extraEnvironment, GOWORK: "off" },
    },
  ));
  return effectiveGoModuleVersion(metadata, label);
}

function assertPatchedBraceExpansion(actual, label) {
  const major = Number(actual.split(".")[0]);
  if (major === 1) {
    assertVersionAtLeast(actual, "1.1.16", label);
    return;
  }
  if (major === 2) {
    assertVersionAtLeast(actual, "2.1.2", label);
    return;
  }
  assert.fail(`${label} has an unreviewed major version ${actual}`);
}

function assertPatchedJsYaml(actual, label) {
  const major = Number(actual.split(".")[0]);
  if (major === 3) {
    assertVersionAtLeast(actual, "3.15.0", label);
    return;
  }
  if (major === 4) {
    assertVersionAtLeast(actual, "4.3.0", label);
    return;
  }
  assert.fail(`${label} has an unreviewed major version ${actual}`);
}

test("security-sensitive Go modules stay at patched versions", () => {
  const flowersecGo = path.join(sourceRoot, "flowersec-go");
  const transportCheck = path.join(sourceRoot, "tools/transportcheck");

  assertVersionAtLeast(
    readGoModuleVersion(flowersecGo, "golang.org/x/crypto", "golang.org/x/crypto"),
    "0.52.0",
    "golang.org/x/crypto",
  );
  assertVersionAtLeast(
    readGoModuleVersion(flowersecGo, "golang.org/x/net", "golang.org/x/net"),
    "0.56.0",
    "golang.org/x/net",
  );
  assertVersionAtLeast(
    readGoModuleVersion(flowersecGo, "golang.org/x/sys", "golang.org/x/sys"),
    "0.46.0",
    "golang.org/x/sys",
  );
  assertVersionAtLeast(
    readGoModuleVersion(transportCheck, "filippo.io/edwards25519", "filippo.io/edwards25519"),
    "1.1.1",
    "filippo.io/edwards25519",
  );
});

test("npm lock contains no vulnerable brace-expansion or js-yaml selection", () => {
  const packageLock = JSON.parse(
    fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package-lock.json"), "utf8"),
  );
  let braceExpansionCount = 0;
  let jsYamlCount = 0;

  for (const [packagePath, metadata] of Object.entries(packageLock.packages)) {
    if (packagePath.endsWith("/brace-expansion")) {
      braceExpansionCount += 1;
      assertPatchedBraceExpansion(metadata.version, packagePath);
    }
    if (packagePath.endsWith("/js-yaml")) {
      jsYamlCount += 1;
      assertPatchedJsYaml(metadata.version, packagePath);
    }
  }

  assert.ok(braceExpansionCount > 0, "package lock must contain brace-expansion");
  assert.ok(jsYamlCount > 0, "package lock must contain js-yaml");
});

test("npm audit includes build-time dependencies and fails on every severity", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(
    makefile,
    /^ts-audit:\n\tcd flowersec-ts && npm audit --audit-level=info --include=prod --include=dev --include=optional --include=peer$/m,
    "ts-audit must override environment omissions and fail on every npm severity",
  );
  assert.doesNotMatch(makefile, /^ts-audit:[^\n]*\n\t.*--omit=/m);
});

test("clean security gates install every pinned SBOM schema validator", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  for (const packageName of ["ajv", "ajv-formats", "ajv-formats-draft2019"]) {
    assert.match(
      makefile,
      new RegExp(`flowersec-ts/node_modules/${packageName}/package\\.json`),
      `${packageName} must be part of ts-ensure-deps`,
    );
  }
});

test("security dependency checks stay wired into local gates", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(
    makefile,
    /^security-dependency-check: ts-build\n\tnode --test .*scripts\/security-makefile\.test\.mjs.*\n\tnode scripts\/generate-source-inventory\.mjs --check$/m,
  );
  assert.match(
    makefile,
    /^precommit: security-makefile-check security-dependency-check$/m,
  );
  assert.match(
    makefile,
    /^check: security-makefile-check security-dependency-check$/m,
  );
});

test("module-local Go checks cannot be masked by workspace MVS", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-security-version-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const vulnerableModule = path.join(root, "vulnerable");
  const maskingModule = path.join(root, "masking");
  fs.mkdirSync(vulnerableModule);
  fs.mkdirSync(maskingModule);
  const proxy = path.join(root, "proxy");
  const modulePath = "example.com/securitydep";
  const moduleProxy = path.join(proxy, "example.com/securitydep/@v");
  fs.mkdirSync(moduleProxy, { recursive: true });
  fs.writeFileSync(path.join(moduleProxy, "list"), "v0.51.0\nv0.52.0\n");
  for (const version of ["v0.51.0", "v0.52.0"]) {
    fs.writeFileSync(
      path.join(moduleProxy, `${version}.info`),
      `${JSON.stringify({ Version: version, Time: "2026-01-01T00:00:00Z" })}\n`,
    );
    fs.writeFileSync(path.join(moduleProxy, `${version}.mod`), `module ${modulePath}\n\ngo 1.26.5\n`);
  }
  fs.writeFileSync(
    path.join(vulnerableModule, "go.mod"),
    `module example.com/vulnerable\n\ngo 1.26.5\n\nrequire ${modulePath} v0.51.0\n`,
  );
  fs.writeFileSync(
    path.join(maskingModule, "go.mod"),
    `module example.com/masking\n\ngo 1.26.5\n\nrequire ${modulePath} v0.52.0\n`,
  );
  const workspace = path.join(root, "go.work");
  fs.writeFileSync(workspace, "go 1.26.5\n\nuse (\n\t./vulnerable\n\t./masking\n)\n");

  const offlineEnvironment = {
    GOPROXY: pathToFileURL(proxy).href,
    GOSUMDB: "off",
    GOPRIVATE: "",
  };
  const workspaceMetadata = JSON.parse(run(
    "go",
    ["list", "-m", "-json", "-mod=readonly", modulePath],
    { cwd: vulnerableModule, env: { ...offlineEnvironment, GOWORK: workspace } },
  ));
  assert.equal(effectiveGoModuleVersion(workspaceMetadata, "workspace crypto"), "v0.52.0");
  assert.throws(
    () => assertVersionAtLeast(
      readGoModuleVersion(vulnerableModule, modulePath, "module dependency", offlineEnvironment),
      "0.52.0",
      modulePath,
    ),
    /below the patched minimum/,
  );
});

test("security version helpers reject prereleases and downgraded replacements", () => {
  assert.throws(
    () => assertVersionAtLeast("v0.52.0-rc.1", "0.52.0", "golang.org/x/crypto"),
    /invalid release version/,
  );
  assert.throws(
    () => assertVersionAtLeast(
      effectiveGoModuleVersion(
        { Version: "v0.52.0", Replace: { Version: "v0.51.0" } },
        "golang.org/x/crypto",
      ),
      "0.52.0",
      "golang.org/x/crypto",
    ),
    /below the patched minimum/,
  );
});
