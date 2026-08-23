import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
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

function extractShellFunction(source, name) {
  const match = new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}\\n`, "m").exec(source);
  assert.ok(match, `missing shell function ${name}`);
  return match[0];
}

function architectureCaseBlock(source, selector) {
  const start = `  ${selector})\n`;
  const startIndex = source.indexOf(start);
  assert.notEqual(startIndex, -1, `missing architecture case ${selector}`);
  const endIndex = source.indexOf("    ;;\n", startIndex + start.length);
  assert.notEqual(endIndex, -1, `unterminated architecture case ${selector}`);
  return source.slice(startIndex + start.length, endIndex);
}

function assertHostArchitectureBindings(source) {
  const expectations = [
    {
      selector: "x86_64|amd64",
      architecture: "amd64",
      tuples: {
        Go: "    go_arch=amd64\n    go_sha256=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89\n",
        Node: "    node_arch=x64\n    node_sha256=84d38715d449447117d05c3e71acd78daa49d5b1bfa8aacf610303920c3322be\n",
        Rust: "    rustup_target=x86_64-unknown-linux-gnu\n    rustup_sha256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c\n    rust_archive_sha256=7b5437c1d18a174faae253a18eac22c32288dccfc09ff78d5ee99b7467e21bca\n",
        Swiftly: "    swiftly_arch=x86_64\n    swiftly_sha256=4c4adb7b7ad7910f38c52b94a938c309586fe395e1fe1538c397384ee36bfff0\n    swiftly_binary_sha256=e7ce91d07b4419ea779da6b575721c17eb7c44f932e63b6e2d03a9afe75cce61\n",
        Playwright: "    playwright_chromium_archive=builds/cft/${playwright_chromium_version}/linux64/chrome-linux64.zip\n    playwright_chromium_sha256=ae8736ac28bc69278551500f219fc749575648263c43ec5990749eff43b9fcf8\n    playwright_chromium_executable=chrome-linux64/chrome\n    playwright_headless_archive=builds/cft/${playwright_chromium_version}/linux64/chrome-headless-shell-linux64.zip\n    playwright_headless_sha256=3cfc2bd00d1bafcf8a68dc74c9c92bb7150ddc8d26ade948a776316e1cec4f14\n    playwright_headless_executable=chrome-headless-shell-linux64/chrome-headless-shell\n    playwright_ffmpeg_archive=builds/ffmpeg/${playwright_ffmpeg_revision}/ffmpeg-linux.zip\n    playwright_ffmpeg_sha256=ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc\n",
      },
    },
    {
      selector: "aarch64|arm64",
      architecture: "arm64",
      tuples: {
        Go: "    go_arch=arm64\n    go_sha256=d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e\n",
        Node: "    node_arch=arm64\n    node_sha256=71e427e28b78846f201d4d5ecc30cb13d1508ca099ef3871889a1256c7d6f67e\n",
        Rust: "    rustup_target=aarch64-unknown-linux-gnu\n    rustup_sha256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c\n    rust_archive_sha256=d5decc46123eb888f809f2ee3b118d13586a37ffad38afaefe56aa7139481d34\n",
        Swiftly: "    swiftly_arch=aarch64\n    swiftly_sha256=cc4f912fff6c7f53704fc6d22f9e8ee7fdf6bd574ad276998f7502418bf5a45a\n    swiftly_binary_sha256=6531421eeb80eb69db21e41b1ed94bac1467548972eb82861fc4beb6664bd6aa\n",
        Playwright: "    playwright_chromium_archive=builds/chromium/${playwright_chromium_revision}/chromium-linux-arm64.zip\n    playwright_chromium_sha256=b5ad7d8fe70f230b34198ddb5626d717c016db2f627cb44b922babbcaf3479b9\n    playwright_chromium_executable=chrome-linux/chrome\n    playwright_headless_archive=builds/chromium/${playwright_chromium_revision}/chromium-headless-shell-linux-arm64.zip\n    playwright_headless_sha256=b03443e1e1a60d06e07b6cdfe650b8c2bfcbb3db497d2b652f73dc6912f4ae15\n    playwright_headless_executable=chrome-linux/headless_shell\n    playwright_ffmpeg_archive=builds/ffmpeg/${playwright_ffmpeg_revision}/ffmpeg-linux-arm64.zip\n    playwright_ffmpeg_sha256=2628c03f05318ff812c8c9baaf207dea2ddf53e818c0dc936714b0fbe3afb009\n",
      },
    },
  ];
  for (const { selector, architecture, tuples } of expectations) {
    const block = architectureCaseBlock(source, selector);
    for (const [label, tuple] of Object.entries(tuples)) {
      assert.ok(block.includes(tuple), `${architecture} ${label} tuple is not bound`);
    }
  }
}

function swapLiterals(source, first, second) {
  const placeholder = "__FLOWERSEC_DIGEST_SWAP__";
  assert.ok(!source.includes(placeholder));
  return source.replace(first, placeholder).replace(second, first).replace(placeholder, second);
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
  if (major === 5) {
    assertVersionAtLeast(actual, "5.0.8", label);
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
});

test("npm lock contains no vulnerable brace-expansion or js-yaml selection", () => {
  const packageLock = JSON.parse(
    fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package-lock.json"), "utf8"),
  );
  let braceExpansionCount = 0;

  for (const [packagePath, metadata] of Object.entries(packageLock.packages)) {
    if (packagePath.endsWith("/brace-expansion")) {
      braceExpansionCount += 1;
      assertPatchedBraceExpansion(metadata.version, packagePath);
    }
    if (packagePath.endsWith("/js-yaml")) {
      assertPatchedJsYaml(metadata.version, packagePath);
    }
  }

  assert.ok(braceExpansionCount > 0, "package lock must contain brace-expansion");
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
  assert.match(
    makefile,
    /flowersec-ts\/node_modules\/\.bin\/tsx/,
    "the TypeScript peer runner must be part of ts-ensure-deps",
  );
});

test("security dependency checks stay wired into local gates", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  assert.match(
    makefile,
    /^security-dependency-check:\n\tnode --test .*scripts\/go-toolchain-policy\.test\.mjs.*scripts\/security-makefile\.test\.mjs.*\n\tnode scripts\/check-go-toolchain-policy\.mjs\n\tnode scripts\/generate-source-inventory\.mjs --check$/m,
  );
  assert.match(
    makefile,
    /^precommit:\n\t\$\(MAKE\) precommit-source$/m,
  );
  assert.match(makefile, /^precommit-source:\n(?:\tnode scripts\/run-precommit-wave\.mjs .*\n){4}$/m);
  assert.match(makefile, /^\tnode scripts\/run-precommit-wave\.mjs static \$\(MAKE\) security-makefile-check security-dependency-check /m);
  assert.match(
    makefile,
    /^check: security-makefile-check$/m,
  );
  assert.match(makefile, /^final-offline-contracts:\n\t\$\(MAKE\) security-dependency-check$/m);
});

test("privileged host bootstrap verifies every root-executed toolchain download", () => {
  const source = fs.readFileSync(path.join(sourceRoot, "scripts/test-host-init.sh"), "utf8");
  const browserEnsure = fs.readFileSync(path.join(sourceRoot, "flowersec-ts/scripts/ensure-playwright-browsers.mjs"), "utf8");
  const hostEntry = fs.readFileSync(path.join(sourceRoot, "scripts/test-host.sh"), "utf8");
  assertHostArchitectureBindings(source);
  for (const digest of [
    "708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89",
    "d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e",
    "84d38715d449447117d05c3e71acd78daa49d5b1bfa8aacf610303920c3322be",
    "71e427e28b78846f201d4d5ecc30cb13d1508ca099ef3871889a1256c7d6f67e",
    "4c4adb7b7ad7910f38c52b94a938c309586fe395e1fe1538c397384ee36bfff0",
    "cc4f912fff6c7f53704fc6d22f9e8ee7fdf6bd574ad276998f7502418bf5a45a",
    "e7ce91d07b4419ea779da6b575721c17eb7c44f932e63b6e2d03a9afe75cce61",
    "6531421eeb80eb69db21e41b1ed94bac1467548972eb82861fc4beb6664bd6aa",
    "7b5437c1d18a174faae253a18eac22c32288dccfc09ff78d5ee99b7467e21bca",
    "d5decc46123eb888f809f2ee3b118d13586a37ffad38afaefe56aa7139481d34",
    "ae8736ac28bc69278551500f219fc749575648263c43ec5990749eff43b9fcf8",
    "b5ad7d8fe70f230b34198ddb5626d717c016db2f627cb44b922babbcaf3479b9",
    "3cfc2bd00d1bafcf8a68dc74c9c92bb7150ddc8d26ade948a776316e1cec4f14",
    "b03443e1e1a60d06e07b6cdfe650b8c2bfcbb3db497d2b652f73dc6912f4ae15",
    "ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc",
    "2628c03f05318ff812c8c9baaf207dea2ddf53e818c0dc936714b0fbe3afb009",
  ]) assert.match(source, new RegExp(digest));
  assert.match(source, /rustup\/archive\/1\.28\.2\/\$\{rustup_target\}\/rustup-init/);
  assert.match(source, /rustup_sha256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c/);
  assert.match(source, /rustup_sha256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c/);
  assert.match(source, /sha256sum -c/);
  assert.match(source, /--connect-timeout 20 --max-time 900/);
  for (const label of [
    "Go archive", "Node archive", "Rustup installer", "Rust distribution archive",
    "Swiftly archive", "Swiftly extracted binary", "Swiftly binary",
  ]) {
    assert.match(source, new RegExp(`verify_download [^\\n]*"${label}"`));
  }
  for (const label of ["Playwright Chromium archive", "Playwright Chromium headless archive", "Playwright FFmpeg archive"]) {
    assert.match(source, new RegExp(`install_verified_playwright_archive "${label}"`));
  }
  assert.match(source, /--default-toolchain none/);
  assert.match(source, /rust-\$\{rust_version\}-\$\{rustup_target\}\.tar\.xz/);
  assert.match(source, /authentication_marker_matches "\$rust_archive_sha256"/);
  assert.match(source, /authentication_marker_matches "\$swift_verification_marker"/);
  assert.match(source, /authentication_marker_matches "\$expected" "\$marker"/);
  assert.equal((hostEntry.match(/SWIFTLY_TOOLCHAINS_DIR="\$host_swift_toolchains"/g) ?? []).length, 2);
  assert.match(source, /swiftly" init --overwrite --assume-yes --skip-install/);
  assert.doesNotMatch(source, /npm --prefix "\$source_root\/flowersec-ts" run ensure:browser/);
  assert.doesNotMatch(hostEntry, /RUSTUP_DIST_SERVER|RUSTUP_UPDATE_ROOT|PLAYWRIGHT_DOWNLOAD_HOST|PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT/);
  assert.match(browserEnsure, /process\.getuid\?\.\(\) === 0[\s\S]*not authenticated/);
  assert.match(source, /swiftly" install "\$swift_version" --use --verify/);
  assert.doesNotMatch(source, /curl[^\n]*\|\s*(?:bash|sh)\b/);
});

test("privileged archive tuples reject cross-architecture digest swaps", () => {
  const source = fs.readFileSync(path.join(sourceRoot, "scripts/test-host-init.sh"), "utf8");
  const rustSwap = swapLiterals(
    source,
    "7b5437c1d18a174faae253a18eac22c32288dccfc09ff78d5ee99b7467e21bca",
    "d5decc46123eb888f809f2ee3b118d13586a37ffad38afaefe56aa7139481d34",
  );
  assert.throws(() => assertHostArchitectureBindings(rustSwap), /amd64 Rust tuple is not bound/);
  const chromiumSwap = swapLiterals(
    source,
    "ae8736ac28bc69278551500f219fc749575648263c43ec5990749eff43b9fcf8",
    "b5ad7d8fe70f230b34198ddb5626d717c016db2f627cb44b922babbcaf3479b9",
  );
  assert.throws(() => assertHostArchitectureBindings(chromiumSwap), /amd64 Playwright tuple is not bound/);
});

test("privileged archive verification rejects corrupt bytes before the next action", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-host-download-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const archive = path.join(root, "archive");
  const reached = path.join(root, "reached");
  fs.writeFileSync(archive, "corrupt archive");
  const source = fs.readFileSync(path.join(sourceRoot, "scripts/test-host-init.sh"), "utf8");
  const result = spawnSync("bash", ["-s", "--", "0".repeat(64), archive, reached], {
    encoding: "utf8",
    input: `set -e\n${extractShellFunction(source, "verify_download")}\nverify_download "$1" "$2" "Injected archive"\nprintf reached >"$3"\n`,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Injected archive checksum mismatch/);
  assert.equal(fs.existsSync(reached), false);
});

test("authentication markers reject missing, mismatched, and symlinked legacy state", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-auth-marker-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const marker = path.join(root, "marker");
  const linked = path.join(root, "linked");
  const expected = "a".repeat(64);
  const source = fs.readFileSync(path.join(sourceRoot, "scripts/test-host-init.sh"), "utf8");
  const check = (pathValue) => spawnSync("bash", ["-s", "--", expected, pathValue], {
    encoding: "utf8",
    input: `${extractShellFunction(source, "authentication_marker_matches")}\nauthentication_marker_matches "$1" "$2"\n`,
  }).status;
  assert.notEqual(check(marker), 0);
  fs.writeFileSync(marker, `${"b".repeat(64)}\n`);
  assert.notEqual(check(marker), 0);
  fs.writeFileSync(marker, `${expected}\n`);
  assert.equal(check(marker), 0);
  fs.symlinkSync(marker, linked);
  assert.notEqual(check(linked), 0);
});

test("generic Playwright installation refuses unauthenticated root downloads", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-root-browser-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const ensure = path.join(sourceRoot, "flowersec-ts/scripts/ensure-playwright-browsers.mjs");
  const result = spawnSync(process.execPath, [
    "--import", "data:text/javascript,process.getuid=()=>0", ensure, "chromium",
  ], {
    encoding: "utf8",
    env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: root },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /is not authenticated/);
  assert.deepEqual(fs.readdirSync(root), []);
});

test("fresh Swiftly bootstrap initializes configuration before version validation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-swiftly-bootstrap-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const hostHome = path.join(root, "home");
  const bin = path.join(hostHome, ".local/bin");
  const bootstrap = path.join(root, "swiftly");
  const installed = path.join(bin, "swiftly");
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(bootstrap, `#!/bin/sh
if [ "$1" = init ]; then
  mkdir -p "$SWIFTLY_HOME_DIR" "$SWIFTLY_BIN_DIR"
  printf '{}\\n' >"$SWIFTLY_HOME_DIR/config.json"
  cp "$0" "$SWIFTLY_BIN_DIR/swiftly"
  chmod 0755 "$SWIFTLY_BIN_DIR/swiftly"
  exit 0
fi
if [ "$1" = --version ] && [ -f "$SWIFTLY_HOME_DIR/config.json" ]; then
  printf '1.1.3\\n'
  exit 0
fi
exit 1
`);
  fs.chmodSync(bootstrap, 0o755);
  const digest = createHash("sha256").update(fs.readFileSync(bootstrap)).digest("hex");
  const source = fs.readFileSync(path.join(sourceRoot, "scripts/test-host-init.sh"), "utf8");
  const result = spawnSync("bash", ["-s", "--", hostHome, bootstrap, installed, digest], {
    encoding: "utf8",
    env: {
      ...process.env,
      SWIFTLY_HOME_DIR: path.join(hostHome, ".swiftly"),
      SWIFTLY_BIN_DIR: bin,
    },
    input: `set -e\n${extractShellFunction(source, "verify_download")}\n${extractShellFunction(source, "initialize_swiftly_binary")}\nhost_home="$1"\nswiftly_binary_sha256="$4"\nswiftly_version=1.1.3\ninitialize_swiftly_binary "$2" "$3"\n`,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.existsSync(path.join(hostHome, ".swiftly/config.json")), true);
  assert.equal(run(installed, ["--version"], {
    env: { SWIFTLY_HOME_DIR: path.join(hostHome, ".swiftly"), SWIFTLY_BIN_DIR: bin },
  }), "1.1.3\n");
});

test("Swiftly stale configuration is reset into the canonical toolchain directory", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-swiftly-stale-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const hostHome = path.join(root, "home");
  const hostTmp = path.join(root, "tmp");
  const bin = path.join(hostHome, ".local/bin");
  const swiftlyHome = path.join(hostHome, ".swiftly");
  const toolchains = path.join(root, "cache/toolchains/swift");
  const swiftly = path.join(bin, "swiftly");
  const swift = path.join(bin, "swift");
  const log = path.join(root, "swiftly.log");
  const stale = path.join(toolchains, "6.1.3/stale");
  fs.mkdirSync(path.dirname(stale), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });
  fs.mkdirSync(swiftlyHome, { recursive: true });
  fs.mkdirSync(hostTmp, { recursive: true });
  fs.writeFileSync(stale, "unauthenticated\n");
  fs.writeFileSync(path.join(swiftlyHome, "config.json"), '{"installedToolchains":["6.1.3"],"inUse":"6.1.3"}\n');
  fs.writeFileSync(swiftly, `#!/bin/sh
set -eu
if [ "$(basename "$0")" = swift ]; then
  [ -f "$SWIFTLY_TOOLCHAINS_DIR/swift-ready" ] || exit 1
  printf 'Swift version 6.1.3 (swift-6.1.3-RELEASE)\\n'
  exit 0
fi
case "$1" in
  --version)
    printf '1.1.3\\n'
    ;;
  init)
    case " $* " in *" --overwrite "*) ;; *) exit 20 ;; esac
    [ "$SWIFTLY_TOOLCHAINS_DIR" = "$EXPECTED_SWIFTLY_TOOLCHAINS_DIR" ]
    printf 'init\\n' >>"$FLOWERSEC_TEST_LOG"
    printf '{"installedToolchains":[]}\\n' >"$SWIFTLY_HOME_DIR/config.json"
    ;;
  install)
    case " $* " in *" --verify "*) ;; *) exit 21 ;; esac
    [ "$SWIFTLY_TOOLCHAINS_DIR" = "$EXPECTED_SWIFTLY_TOOLCHAINS_DIR" ]
    printf 'install\\n' >>"$FLOWERSEC_TEST_LOG"
    mkdir -p "$SWIFTLY_TOOLCHAINS_DIR"
    printf ready >"$SWIFTLY_TOOLCHAINS_DIR/swift-ready"
    ;;
  *) exit 22 ;;
esac
`);
  fs.chmodSync(swiftly, 0o755);
  fs.symlinkSync("swiftly", swift);
  const digest = createHash("sha256").update(fs.readFileSync(swiftly)).digest("hex");
  const markerValue = "c".repeat(64);
  const source = fs.readFileSync(path.join(sourceRoot, "scripts/test-host-init.sh"), "utf8");
  const result = spawnSync("bash", ["-s", "--", hostHome, hostTmp, toolchains, digest, markerValue], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${bin}:${process.env.PATH}`,
      SWIFTLY_HOME_DIR: swiftlyHome,
      SWIFTLY_BIN_DIR: bin,
      SWIFTLY_TOOLCHAINS_DIR: toolchains,
      EXPECTED_SWIFTLY_TOOLCHAINS_DIR: toolchains,
      FLOWERSEC_TEST_LOG: log,
    },
    input: `set -e\n${extractShellFunction(source, "verify_download")}\n${extractShellFunction(source, "checksum_matches")}\n${extractShellFunction(source, "authentication_marker_matches")}\n${extractShellFunction(source, "install_swift")}\nhost_home="$1"\nhost_tmp="$2"\nhost_swift_toolchains="$3"\nswiftly_binary_sha256="$4"\nswift_verification_marker="$5"\nswiftly_version=1.1.3\nswift_version=6.1.3\ntemporary_paths=()\ninstall_swift\n`,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readFileSync(log, "utf8"), "init\ninstall\n");
  assert.equal(fs.existsSync(stale), false);
  assert.equal(
    fs.readFileSync(path.join(swiftlyHome, ".flowersec-6.1.3-pgp-verified"), "utf8"),
    `${markerValue}\n`,
  );
  assert.equal(run(swift, ["--version"], {
    env: { SWIFTLY_HOME_DIR: swiftlyHome, SWIFTLY_BIN_DIR: bin, SWIFTLY_TOOLCHAINS_DIR: toolchains },
  }), "Swift version 6.1.3 (swift-6.1.3-RELEASE)\n");
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
    fs.writeFileSync(path.join(moduleProxy, `${version}.mod`), `module ${modulePath}\n\ngo 1.26.6\n`);
  }
  fs.writeFileSync(
    path.join(vulnerableModule, "go.mod"),
    `module example.com/vulnerable\n\ngo 1.26.6\n\nrequire ${modulePath} v0.51.0\n`,
  );
  fs.writeFileSync(
    path.join(maskingModule, "go.mod"),
    `module example.com/masking\n\ngo 1.26.6\n\nrequire ${modulePath} v0.52.0\n`,
  );
  const workspace = path.join(root, "go.work");
  fs.writeFileSync(workspace, "go 1.26.6\n\nuse (\n\t./vulnerable\n\t./masking\n)\n");

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
