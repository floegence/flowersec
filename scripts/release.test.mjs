import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { execFileBounded, fetchResponseBody } from "./release-readback.mjs";

const sourceRoot = path.resolve(import.meta.dirname, "..");
const testImageDigest = `sha256:${"0".repeat(64)}`;
const releaseMutationConcurrency = 4;
const mainGateGraphFiles = [
  "Makefile",
  ".githooks/pre-push",
  "scripts/check-security-makefile.mjs",
  "scripts/push-main.sh",
  "scripts/release.sh",
  "scripts/run-final-lanes.mjs",
  "scripts/run-final-stage.mjs",
];
const releasePolicyFixtureFiles = [
  "Makefile",
  ".github/dependabot.yml",
  ".githooks/pre-push",
  ".github/workflows/ci.yml",
  ".github/workflows/codeql.yml",
  ".github/workflows/release.yml",
  ".github/workflows/rust-release.yml",
  ".github/workflows/scorecard.yml",
  "docker/flowersec-runtime/Dockerfile",
  "scripts/check-release-version-consistency.mjs",
  "scripts/check-release-version-consistency.test.mjs",
  "scripts/check-container-release-policy.mjs",
  "scripts/check-release-workflows.rb",
  "scripts/check-release-workflow-policy.sh",
  "scripts/check-security-makefile.mjs",
  "scripts/run-final-lanes.mjs",
  "scripts/run-final-stage.mjs",
  "scripts/run-final-stage.test.mjs",
  "scripts/run-precommit-wave.mjs",
  "scripts/run-precommit-wave.test.mjs",
  "scripts/release.sh",
  "scripts/push-main.sh",
  "scripts/release.test.mjs",
];
const repositoryLocalEnvironmentVariables = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_CONFIG",
  "GIT_CONFIG_COUNT",
  "GIT_CONFIG_PARAMETERS",
  "GIT_DIR",
  "GIT_GRAFT_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_INTERNAL_SUPER_PREFIX",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_OBJECT_DIRECTORY",
  "GIT_PREFIX",
  "GIT_QUARANTINE_PATH",
  "GIT_REPLACE_REF_BASE",
  "GIT_SHALLOW_FILE",
  "GIT_WORK_TREE",
];

function isolatedEnvironment(overrides = {}) {
  const env = { ...process.env, ...overrides };
  for (const variable of repositoryLocalEnvironmentVariables) {
    delete env[variable];
  }
  return env;
}

function extractWorkflowStepRun(workflowFile, jobName, stepName) {
  const ruby = [
    'require "psych"',
    'workflow = Psych.safe_load(File.read(ARGV.fetch(0)), aliases: false)',
    'step = workflow.fetch("jobs").fetch(ARGV.fetch(1)).fetch("steps").find { |entry| entry["name"] == ARGV.fetch(2) }',
    'abort "missing workflow step" unless step',
    'print step.fetch("run")',
  ].join("\n");
  const extracted = spawnSync("ruby", ["-W0", "-rpsych", "-e", ruby, workflowFile, jobName, stepName], {
    cwd: sourceRoot,
    encoding: "utf8",
  });
  assert.equal(extracted.status, 0, `${extracted.stdout}${extracted.stderr}`);
  return extracted.stdout;
}

function validGhcrProvenance() {
  const releaseSHA = "88d8064370733ca512b7994479d52fae33d91665";
  return Object.fromEntries(["linux/amd64", "linux/arm64"].map((platform) => [platform, {
    SLSA: {
      buildDefinition: {
        buildType: "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        externalParameters: {
          request: {
            args: {
              "build-arg:COMMIT": releaseSHA,
              "build-arg:VERSION": "v3.0.1",
            },
            root: {
              request: {
                args: {
                  "vcs:revision": releaseSHA,
                  "vcs:source": "https://github.com/floegence/flowersec",
                },
              },
            },
          },
        },
      },
    },
  }]));
}

function runGhcrDigestVerificationHarness(t, mode = {}) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "release",
    "Verify GHCR runtime digest",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-ghcr-digest-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
phase=manifest
if [[ " $* " == *" cosign verify "* ]]; then phase=signature; fi
if [[ " $* " == *" .Provenance"* ]]; then phase=provenance; fi
if [[ "\${FAKE_TIMEOUT_PHASE:-}" == "$phase" ]]; then
  if [[ -n "\${TIMEOUT_MARKER:-}" ]]; then printf timeout > "$TIMEOUT_MARKER"; fi
  exit "$FAKE_TIMEOUT_EXIT"
fi
while [[ "$1" == --* ]]; do shift; done
shift
"$@"
`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *" --format "* ]]; then
  if [[ "$FAKE_PROVENANCE_MODE" == failure ]]; then
    printf 'provenance unavailable\n' >&2
    exit 69
  fi
  printf '%s\n' "$FAKE_PROVENANCE"
  exit 0
fi
count_file="$FAKE_COUNT_FILE"
count=0
if [[ -f "$count_file" ]]; then count="$(<"$count_file")"; fi
count=$((count + 1))
printf '%s' "$count" > "$count_file"
case "\${FAKE_DOCKER_MODE:-match}" in
  match) printf 'Digest: %s\\n' "$IMAGE_DIGEST" ;;
  eventual) if (( count == 2 )); then printf 'Digest: %s\\n' "$IMAGE_DIGEST"; else printf 'Digest: sha256:stale\\n'; fi ;;
  failure) printf 'inspect failed\\n' >&2; exit 69 ;;
  mismatch) printf 'Digest: sha256:stale\\n' ;;
esac
`);
  writeExecutable(path.join(fakeBin, "cosign"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_COSIGN_LOG"
case "$FAKE_SIGNATURE_MODE" in
  success-main)
    [[ "$*" == *"refs/heads/main"* ]] || exit 1
    ;;
  success-tag)
    [[ "$*" == *"refs/tags/flowersec-go/v3.0.1"* ]] || exit 1
    ;;
  reject) exit 1 ;;
esac
`);
  writeExecutable(path.join(fakeBin, "sleep"), `#!/usr/bin/env bash
printf '%s\\n' "$1" >> "$FAKE_SLEEP_FILE"
`);
  const countFile = path.join(root, "count");
  const sleepFile = path.join(root, "sleep");
  const cosignLog = path.join(root, "cosign.log");
  const releaseSHA = "88d8064370733ca512b7994479d52fae33d91665";
  const provenance = mode.provenance ?? validGhcrProvenance();
  return {
    result: spawnSync("bash", ["-c", run], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: {
        ...isolatedEnvironment(),
        PATH: `${fakeBin}:${process.env.PATH}`,
        IMAGE_DIGEST: testImageDigest,
        IMAGE_REPOSITORY: "ghcr.io/test/flowersec-runtime",
        IMAGE_VERSION: "3.0.1",
        GITHUB_REPOSITORY: "floegence/flowersec",
        FAKE_TIMEOUT_PHASE: mode.timeoutPhase ?? "",
        FAKE_TIMEOUT_EXIT: String(mode.timeoutExit ?? 124),
        FAKE_DOCKER_MODE: mode.docker ?? "match",
        FAKE_COUNT_FILE: countFile,
        FAKE_COSIGN_LOG: cosignLog,
        FAKE_PROVENANCE: JSON.stringify(provenance),
        FAKE_PROVENANCE_MODE: mode.provenanceMode ?? "success",
        FAKE_SIGNATURE_MODE: mode.signature ?? "success-main",
        FAKE_SLEEP_FILE: sleepFile,
        RELEASE_SHA: releaseSHA,
      },
    }),
    countFile,
    cosignLog,
    sleepFile,
  };
}

function runGhcrTagReadbackHarness(t, mode = {}) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "release",
    "Verify GHCR runtime tag readback",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-ghcr-tags-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do shift; done
shift
if [[ "\${FAKE_TIMEOUT_MODE:-}" == timeout ]]; then
  printf timeout > "$TIMEOUT_MARKER"
  exit "$FAKE_TIMEOUT_EXIT"
fi
"$@"
`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "$FAKE_COUNT_FILE" ]] || count="$(<"$FAKE_COUNT_FILE")"
count=$((count + 1))
printf '%s' "$count" > "$FAKE_COUNT_FILE"
case "$FAKE_DOCKER_MODE" in
  match) printf 'Digest: %s\n' "$IMAGE_DIGEST" ;;
  eventual) if (( count % 2 == 0 )); then printf 'Digest: %s\n' "$IMAGE_DIGEST"; else printf 'Digest: sha256:stale\n'; fi ;;
  failure) printf 'inspect failed\n' >&2; exit 69 ;;
esac
`);
  writeExecutable(path.join(fakeBin, "sleep"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$1\" >> \"$FAKE_SLEEP_FILE\"\n");
  const countFile = path.join(root, "count");
  const sleepFile = path.join(root, "sleep");
  return {
    result: spawnSync("bash", ["-c", run], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: isolatedEnvironment({
        PATH: `${fakeBin}:${process.env.PATH}`,
        IMAGE_DIGEST: testImageDigest,
        IMAGE_REPOSITORY: "ghcr.io/test/flowersec-runtime",
        IMAGE_VERSION: "3.0.1",
        FAKE_COUNT_FILE: countFile,
        FAKE_DOCKER_MODE: mode.docker ?? "match",
        FAKE_SLEEP_FILE: sleepFile,
        FAKE_TIMEOUT_EXIT: String(mode.timeoutExit ?? 124),
        FAKE_TIMEOUT_MODE: mode.timeout ? "timeout" : "",
      }),
    }),
    countFile,
    sleepFile,
  };
}

function writeExecutable(filename, source) {
  fs.writeFileSync(filename, source);
  fs.chmodSync(filename, 0o755);
}

function extractShellFunction(source, name) {
  const start = source.indexOf(`${name}() {`);
  assert.notEqual(start, -1, `missing shell function ${name}`);
  const relativeEnd = source.slice(start).search(/^}$/m);
  assert.notEqual(relativeEnd, -1, `unterminated shell function ${name}`);
  return source.slice(start, start + relativeEnd + 1);
}

function runGhcrVersionStateHarness(t, { docker, githubReleaseExists, timeoutExit = 124 }) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "release",
    "Inspect immutable GHCR version tag",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-ghcr-state-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do shift; done
shift
if [[ "$FAKE_DOCKER_MODE" == timeout ]]; then exit "$FAKE_TIMEOUT_EXIT"; fi
"$@"
`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/usr/bin/env bash
set -euo pipefail
case "$FAKE_DOCKER_MODE" in
  existing) printf 'Digest: sha256:%064d\n' 0 ;;
  invalid-digest) printf 'Digest: sha256:invalid\n' ;;
  missing) printf 'manifest unknown\n' >&2; exit 1 ;;
  failure) printf 'registry unavailable\n' >&2; exit 70 ;;
  *) printf 'unexpected fake docker mode\n' >&2; exit 71 ;;
esac
`);
  const outputFile = path.join(root, "github-output");
  const result = spawnSync("bash", ["-c", run], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_DOCKER_MODE: docker,
      FAKE_TIMEOUT_EXIT: String(timeoutExit),
      GITHUB_OUTPUT: outputFile,
      GITHUB_RELEASE_EXISTS: githubReleaseExists ? "true" : "false",
      IMAGE_REPOSITORY: "ghcr.io/floegence/flowersec-runtime",
      IMAGE_VERSION: "3.0.1",
      PATH: `${fakeBin}:${process.env.PATH}`,
    }),
  });
  return {
    result,
    output: fs.existsSync(outputFile) ? fs.readFileSync(outputFile, "utf8") : "",
  };
}

function runGhcrSigningHarness(t, { timeoutExit = 0, workflowRef = "floegence/flowersec/.github/workflows/release.yml@refs/heads/main" } = {}) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "release",
    "Sign new GHCR runtime digest",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-ghcr-sign-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  const cosignLog = path.join(root, "cosign.log");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$FAKE_TIMEOUT_EXIT" != 0 ]]; then exit "$FAKE_TIMEOUT_EXIT"; fi
while [[ "$1" == --* ]]; do shift; done
shift
"$@"
`);
  writeExecutable(path.join(fakeBin, "cosign"), "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$FAKE_COSIGN_LOG\"\n");
  const result = spawnSync("bash", ["-c", run], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_COSIGN_LOG: cosignLog,
      FAKE_TIMEOUT_EXIT: String(timeoutExit),
      GITHUB_REPOSITORY: "floegence/flowersec",
      GITHUB_WORKFLOW_REF: workflowRef,
      IMAGE_DIGEST: testImageDigest,
      IMAGE_REPOSITORY: "ghcr.io/floegence/flowersec-runtime",
      IMAGE_VERSION: "3.0.1",
      PATH: `${fakeBin}:${process.env.PATH}`,
    }),
  });
  return { result, cosignLog };
}

function runGhcrTagMutationHarness(t, stepName, { dockerMode = "missing", timeoutPhase = "", timeoutExit = 124 } = {}) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "release",
    stepName,
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-ghcr-tag-mutation-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  const dockerLog = path.join(root, "docker.log");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
phase=create
if [[ " $* " == *" imagetools inspect "* ]]; then phase=inspect; fi
if [[ "$FAKE_TIMEOUT_PHASE" == "$phase" ]]; then exit "$FAKE_TIMEOUT_EXIT"; fi
while [[ "$1" == --* ]]; do shift; done
shift
"$@"
`);
  writeExecutable(path.join(fakeBin, "docker"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ " $* " == *" imagetools inspect "* ]]; then
  case "$FAKE_DOCKER_MODE" in
    existing) printf 'Digest: %s\n' "$IMAGE_DIGEST" ;;
    missing) printf 'manifest unknown\n' >&2; exit 1 ;;
    failure) printf 'registry unavailable\n' >&2; exit 69 ;;
  esac
fi
`);
  const result = spawnSync("bash", ["-c", run], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_DOCKER_LOG: dockerLog,
      FAKE_DOCKER_MODE: dockerMode,
      FAKE_TIMEOUT_EXIT: String(timeoutExit),
      FAKE_TIMEOUT_PHASE: timeoutPhase,
      IMAGE_DIGEST: testImageDigest,
      IMAGE_REPOSITORY: "ghcr.io/floegence/flowersec-runtime",
      IMAGE_VERSION: "3.0.1",
      PATH: `${fakeBin}:${process.env.PATH}`,
    }),
  });
  return {
    result,
    dockerLog: fs.existsSync(dockerLog) ? fs.readFileSync(dockerLog, "utf8") : "",
  };
}

function runNpmRecoveryAssetTimeoutHarness(t, timeoutExit) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "npm-recovery",
    "Publish or recover npm registry packages from immutable release assets",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-assets-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "git"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == rev-parse ]]; then printf '%s\n' "$FAKE_RELEASE_SHA"; fi
`);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash\nexit ${timeoutExit}\n`);
  fs.mkdirSync(path.join(root, "scripts"));
  writeExecutable(path.join(root, "scripts/verify-release-tags.sh"), "#!/usr/bin/env bash\nexit 0\n");
  return spawnSync("bash", ["-c", run], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_RELEASE_SHA: "88d8064370733ca512b7994479d52fae33d91665",
      GITHUB_REPOSITORY: "floegence/flowersec",
      GITHUB_SHA: "a4a96fac92e63d21d2086902f7c4ae62dcfa6be1",
      PATH: `${fakeBin}:${process.env.PATH}`,
      RELEASE_VERSION: "3.0.1",
    }),
  });
}

function runNpmRecoveryValidationHarness(t, mode) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "npm-recovery",
    "Publish or recover npm registry packages from immutable release assets",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `flowersec-npm-recovery-${mode}-`));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "git"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == rev-parse ]]; then printf '%s\n' "$FAKE_RELEASE_SHA"; fi
`);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do shift; done
shift
"$@"
`);
  writeExecutable(path.join(fakeBin, "gh"), `#!/usr/bin/env bash
set -euo pipefail
destination=""
while (( $# > 0 )); do
  if [[ "$1" == --dir ]]; then destination="$2"; shift 2; else shift; fi
done
test -n "$destination"
archives=(
  "floegence-flowersec-node-native-darwin-arm64-\${RELEASE_VERSION}.tgz"
  "floegence-flowersec-node-native-darwin-x64-\${RELEASE_VERSION}.tgz"
  "floegence-flowersec-node-native-linux-arm64-gnu-\${RELEASE_VERSION}.tgz"
  "floegence-flowersec-node-native-linux-x64-gnu-\${RELEASE_VERSION}.tgz"
  "floegence-flowersec-node-native-\${RELEASE_VERSION}.tgz"
  "floegence-flowersec-core-\${RELEASE_VERSION}.tgz"
  "flowersec-runtime_\${RELEASE_VERSION}_linux_amd64.tar.gz"
  "flowersec-runtime_\${RELEASE_VERSION}_linux_arm64.tar.gz"
)
: > "$destination/checksums.txt"
touch "$destination/checksums.txt.sig" "$destination/checksums.txt.pem"
for archive in "\${archives[@]}"; do
  printf archive > "$destination/$archive"
  touch "$destination/$archive.sig" "$destination/$archive.pem"
  printf '%064d  %s\n' 0 "$archive" >> "$destination/checksums.txt"
done
if [[ "$FAKE_RECOVERY_MODE" == asset-closure ]]; then
  rm "$destination/\${archives[0]}.pem"
fi
`);
  writeExecutable(path.join(fakeBin, "cosign"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$FAKE_RECOVERY_MODE" == signature ]]; then
  printf 'injected signature mismatch\n' >&2
  exit 1
fi
`);
  writeExecutable(path.join(fakeBin, "sha256sum"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$FAKE_RECOVERY_MODE" == checksum ]]; then
  printf 'injected checksum mismatch\n' >&2
  exit 1
fi
`);
  writeExecutable(path.join(fakeBin, "find"), `#!/usr/bin/env bash
set -euo pipefail
for file in "$1"/*; do basename "$file"; done
`);
  writeExecutable(path.join(fakeBin, "jq"), `#!/usr/bin/env bash
set -euo pipefail
query=""
for value in "$@"; do
  if [[ "$value" == *'.name == $package'* || "$value" == *'.os == [$os]'* ]]; then query="$value"; fi
done
if [[ "$FAKE_RECOVERY_MODE" == source-manifest && "$query" == *'.name == $package'* ]]; then
  printf 'injected source manifest mismatch\n' >&2
  exit 1
fi
if [[ "$FAKE_RECOVERY_MODE" == platform-manifest && "$query" == *'.os == [$os]'* ]]; then
  printf 'injected platform manifest mismatch\n' >&2
  exit 1
fi
`);
  writeExecutable(path.join(fakeBin, "tar"), `#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  -xOf) printf '{}\n' ;;
  -tzf)
    archive="$(basename "$2")"
    printf 'package/package.json\n'
    case "$archive" in
      *node-native-darwin-arm64*) member='package/flowersec-node-native.darwin-arm64.node' ;;
      *node-native-darwin-x64*) member='package/flowersec-node-native.darwin-x64.node' ;;
      *node-native-linux-arm64-gnu*) member='package/flowersec-node-native.linux-arm64-gnu.node' ;;
      *node-native-linux-x64-gnu*) member='package/flowersec-node-native.linux-x64-gnu.node' ;;
      *flowersec-core*)
        if [[ "$FAKE_RECOVERY_MODE" != archive-member ]]; then
          printf 'package/dist/node/index.js\npackage/dist/browser/index.js\n'
        fi
        exit 0
        ;;
      *) exit 0 ;;
    esac
    printf '%s\n' "$member"
    ;;
  *) exit 2 ;;
esac
`);
  fs.mkdirSync(path.join(root, "scripts"));
  writeExecutable(path.join(root, "scripts/verify-release-tags.sh"), "#!/usr/bin/env bash\nexit 0\n");
  const bash3Mapfile = `mapfile() {
  local target
  if [[ "$1" == -t ]]; then target="$2"; else target="$1"; fi
  eval "$target=()"
  while IFS= read -r line; do eval "$target+=(\\"\\$line\\")"; done
}
`;
  return spawnSync("bash", ["-c", `${bash3Mapfile}\n${run}`], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_RECOVERY_MODE: mode,
      FAKE_RELEASE_SHA: "88d8064370733ca512b7994479d52fae33d91665",
      GITHUB_REPOSITORY: "floegence/flowersec",
      GITHUB_SHA: "a4a96fac92e63d21d2086902f7c4ae62dcfa6be1",
      PATH: `${fakeBin}:${process.env.PATH}`,
      RELEASE_VERSION: "3.0.1",
    }),
  });
}

function runNpmCommandTimeoutHarness(t, phase, timeoutExit) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "npm-recovery",
    "Publish or recover npm registry packages from immutable release assets",
  );
  const publishFunction = extractShellFunction(run, "publish_archive_if_missing");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `flowersec-npm-${phase}-`));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do shift; done
shift
if [[ "$1" == npm && "$2" == view ]]; then
  if [[ "$FAKE_TIMEOUT_PHASE" == view ]]; then exit "$FAKE_TIMEOUT_EXIT"; fi
  printf '{"error":{"code":"E404"}}\n'
  exit 1
fi
if [[ "$1" == npx && "$FAKE_TIMEOUT_PHASE" == publish ]]; then exit "$FAKE_TIMEOUT_EXIT"; fi
printf 'unexpected timeout command: %s\n' "$*" >&2
exit 70
`);
  writeExecutable(path.join(fakeBin, "tar"), "#!/usr/bin/env bash\nprintf '{}\\n'\n");
  const archive = path.join(root, "package.tgz");
  fs.writeFileSync(archive, "release archive");
  const shell = `set -euo pipefail
VERSION=3.0.1
SHA=88d8064370733ca512b7994479d52fae33d91665
${publishFunction}
set +e
publish_archive_if_missing '@floegence/test-package' "$1"
status=$?
set -e
exit "$status"
`;
  return spawnSync("bash", ["-c", shell, "--", archive], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_TIMEOUT_PHASE: phase,
      FAKE_TIMEOUT_EXIT: String(timeoutExit),
      PATH: `${fakeBin}:${process.env.PATH}`,
    }),
  });
}

function runCargoPublishTimeoutHarness(t, stepName, timeoutExit) {
  const run = extractWorkflowStepRun(
    path.join(sourceRoot, ".github/workflows/rust-release.yml"),
    "publish",
    stepName,
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-cargo-publish-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  writeExecutable(path.join(fakeBin, "timeout"), `#!/usr/bin/env bash\nexit ${timeoutExit}\n`);
  return spawnSync("bash", ["-c", run], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({ PATH: `${fakeBin}:${process.env.PATH}` }),
  });
}

function createRegistryReadbackHarness(t, options) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-registry-readback-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  const fetchCountFile = path.join(root, "fetch-count");
  const commandCountFile = path.join(root, "command-count");
  const tarCountFile = path.join(root, "tar-count");
  const descendantMarker = path.join(root, "descendant-marker");
  const preload = path.join(root, "fetch-preload.mjs");
  fs.writeFileSync(preload, `
import fs from "node:fs";
const originalSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (callback, delay, ...args) => originalSetTimeout(
  callback,
  delay === 10_000 ? 1 : (process.env.FAKE_CLAMP_OPERATION_TIMEOUT === "true" && delay === 30_000 ? 300 : delay),
  ...args,
);
globalThis.fetch = async (input) => {
  const countFile = process.env.FAKE_FETCH_COUNT_FILE;
  const count = fs.existsSync(countFile) ? Number(fs.readFileSync(countFile, "utf8")) : 0;
  const responses = JSON.parse(process.env.FAKE_FETCH_RESPONSES);
  const response = responses[count];
  fs.writeFileSync(countFile, String(count + 1));
  if (response === undefined) throw new Error("unexpected fake registry request");
  if (response.error !== undefined) {
    const error = new Error(response.error.message);
    error.code = response.error.code;
    throw error;
  }
  const bytes = Buffer.from(response.body ?? "", response.encoding ?? "utf8");
  return {
    status: response.status,
    ok: response.status >= 200 && response.status < 300,
    url: response.url ?? String(input),
    headers: new Headers(response.headers ?? {}),
    body: new ReadableStream({
      start(controller) {
        if (bytes.length > 0) controller.enqueue(bytes);
        controller.close();
      },
    }),
  };
};
`);
  writeExecutable(path.join(fakeBin, "npm"), `#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "$FAKE_COMMAND_COUNT_FILE" ]] || count="$(<"$FAKE_COMMAND_COUNT_FILE")"
count=$((count + 1))
printf '%s' "$count" > "$FAKE_COMMAND_COUNT_FILE"
if (( count <= FAKE_COMMAND_FAILURES )); then
  printf '%s: injected npm failure\n' "$FAKE_COMMAND_ERROR" >&2
  exit 1
fi
if [[ "$FAKE_COMMAND_MODE" == invalid-json ]]; then
  printf '{\n'
else
  printf '%s\n' "$FAKE_NPM_METADATA"
fi
`);
  writeExecutable(path.join(fakeBin, "cargo"), `#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "$FAKE_COMMAND_COUNT_FILE" ]] || count="$(<"$FAKE_COMMAND_COUNT_FILE")"
count=$((count + 1))
printf '%s' "$count" > "$FAKE_COMMAND_COUNT_FILE"
if [[ "$FAKE_COMMAND_MODE" == cargo-retry && "$1" == add && $count -le 2 ]]; then
  printf 'registry temporarily unavailable\n' >&2
  exit 1
fi
`);
  writeExecutable(path.join(fakeBin, "tar"), `#!/usr/bin/env bash
set -euo pipefail
count=0
[[ ! -f "$FAKE_TAR_COUNT_FILE" ]] || count="$(<"$FAKE_TAR_COUNT_FILE")"
count=$((count + 1))
printf '%s' "$count" > "$FAKE_TAR_COUNT_FILE"
if [[ "$FAKE_TAR_MODE" == timeout && $count -eq 1 ]]; then
  ( sleep 1; printf leaked > "$FAKE_DESCENDANT_MARKER" ) &
  sleep 10
fi
if [[ "$FAKE_TAR_MODE" == output-entry && $count -ge 3 ]]; then
  ( sleep 0.2; printf leaked > "$FAKE_DESCENDANT_MARKER" ) &
  head -c "$FAKE_TAR_OUTPUT_BYTES" /dev/zero
  sleep 10
fi
case "$1" in
  -tzf) printf '%s\n' "$FAKE_TAR_LISTING" ;;
  -tvzf)
    if [[ -n "$FAKE_TAR_DETAILS" ]]; then
      printf '%s\n' "$FAKE_TAR_DETAILS"
    else
      while IFS= read -r entry; do printf -- '- %s\n' "$entry"; done <<<"$FAKE_TAR_LISTING"
    fi
    ;;
  -xOzf)
    case "$3" in
      */Cargo.toml) printf '%s\n' "$FAKE_CARGO_MANIFEST" ;;
      */.cargo_vcs_info.json) printf '%s\n' "$FAKE_VCS_INFO" ;;
      package/package.json) printf '%s\n' "$FAKE_NPM_MANIFEST" ;;
      *) printf 'unexpected archive entry: %s\n' "$3" >&2; exit 2 ;;
    esac
    ;;
  *) printf 'unexpected tar mode: %s\n' "$1" >&2; exit 2 ;;
esac
`);

  const archive = Buffer.from(options.archiveBody ?? "hermetic registry archive");
  const version = "3.0.1";
  const sourceSHA = "88d8064370733ca512b7994479d52fae33d91665";
  const npmPackage = "@floegence/flowersec-node-native";
  const npmTarball = "https://registry.npmjs.org/@floegence/flowersec-node-native/-/flowersec-node-native-3.0.1.tgz";
  const npmManifest = JSON.stringify({
    name: npmPackage,
    version,
    flowersecSourceCommit: sourceSHA,
    optionalDependencies: Object.fromEntries(
      ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]
        .map((platform) => [`@floegence/flowersec-node-native-${platform}`, version]),
    ),
    ...options.manifestOverrides,
  });
  const npmMetadata = JSON.stringify({
    name: npmPackage,
    version,
    dist: {
      tarball: npmTarball,
      integrity: `sha512-${crypto.createHash("sha512").update(archive).digest("base64")}`,
      ...options.npmDistOverrides,
    },
    ...options.npmMetadataOverrides,
  });
  const crateName = "flowersec-native-transport";
  const crateRoot = `${crateName}-${version}`;
  const crateMetadata = JSON.stringify({
    version: { num: version, checksum: crypto.createHash("sha256").update(archive).digest("hex") },
  });
  const env = isolatedEnvironment({
    PATH: `${fakeBin}:${process.env.PATH}`,
    NODE_OPTIONS: `--import=${preload}`,
    FAKE_FETCH_COUNT_FILE: fetchCountFile,
    FAKE_FETCH_RESPONSES: JSON.stringify(options.fetchResponses ?? []),
    FAKE_CLAMP_OPERATION_TIMEOUT: options.clampOperationTimeout ? "true" : "false",
    FAKE_COMMAND_COUNT_FILE: commandCountFile,
    FAKE_COMMAND_FAILURES: String(options.commandFailures ?? 0),
    FAKE_COMMAND_ERROR: options.commandError ?? "E404",
    FAKE_COMMAND_MODE: options.commandMode ?? "success",
    FAKE_NPM_METADATA: npmMetadata,
    FAKE_TAR_COUNT_FILE: tarCountFile,
    FAKE_TAR_MODE: options.tarMode ?? "normal",
    FAKE_TAR_OUTPUT_BYTES: options.kind === "npm" ? "20000000" : "3000000",
    FAKE_TAR_LISTING: options.tarListing ?? (options.kind === "crates"
      ? `${crateRoot}/Cargo.toml\n${crateRoot}/.cargo_vcs_info.json`
      : "package/package.json"),
    FAKE_TAR_DETAILS: options.tarDetails ?? "",
    FAKE_CARGO_MANIFEST: options.cargoManifest ?? `[package]\nname = "${crateName}"\nversion = "${version}"`,
    FAKE_VCS_INFO: options.vcsInfo ?? JSON.stringify({ git: { sha1: sourceSHA } }),
    FAKE_NPM_MANIFEST: npmManifest,
    FAKE_DESCENDANT_MARKER: descendantMarker,
  });
  const script = options.kind === "crates"
    ? "scripts/verify-crates-release-package.mjs"
    : options.kind === "cargo"
      ? "scripts/verify-crates-release-consumer.mjs"
      : "scripts/verify-npm-release-package.mjs";
  const args = options.kind === "npm"
    ? [npmPackage, version, sourceSHA]
    : options.kind === "crates"
      ? [crateName, version, sourceSHA]
      : [crateName, version];
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: sourceRoot,
    encoding: "utf8",
    env,
    timeout: 30_000,
  });
  const readCount = (filename) => Number(fs.existsSync(filename) ? fs.readFileSync(filename, "utf8") : "0");
  return { result, fetchCount: readCount(fetchCountFile), commandCount: readCount(commandCountFile), descendantMarker };
}

test("release test helpers use literal executables", () => {
  const source = fs.readFileSync(import.meta.filename, "utf8");
  assert.doesNotMatch(source, /spawnSync\(\s*command\s*,/);
});

test("release policy assertions use anchored mirror URL matching", () => {
  const source = fs.readFileSync(import.meta.filename, "utf8");
  const unsafeMirrorAssertion = [
    "assert.match(containerfile, /https:",
    String.raw`\/\/mirrors\.aliyun\.com\/ubuntu-ports\//);`,
  ].join("");
  const unsafeMirrorSubstringAssertion = [
    "assert.ok(containerfile.",
    'includes("https://mirrors.aliyun.com/ubuntu-ports/"));',
  ].join("");
  assert.equal(
    source.includes(unsafeMirrorAssertion),
    false,
  );
  assert.equal(
    source.includes(unsafeMirrorSubstringAssertion),
    false,
  );
});

test("Rust publication installs the shared native driver before the SDK", () => {
  const nativeManifest = fs.readFileSync(path.join(sourceRoot, "flowersec-native-transport/Cargo.toml"), "utf8");
  const sdkManifest = fs.readFileSync(path.join(sourceRoot, "flowersec-rust/Cargo.toml"), "utf8");
  const releaseVersion = nativeManifest.match(/^version\s*=\s*"(\d+\.\d+\.\d+)"$/m)?.[1];
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const rustWorkflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/rust-release.yml"), "utf8");
  const releaseWorkflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");

  assert.doesNotMatch(nativeManifest, /^publish\s*=\s*false$/m);
  for (const field of ["description", "license", "repository", "readme", "include"]) {
    assert.match(nativeManifest, new RegExp(`^${field}\\s*=`, "m"), `native driver misses ${field} package metadata`);
  }
  assert.ok(releaseVersion, "native driver package version is missing");
  assert.match(
    sdkManifest,
    new RegExp(`flowersec-native-transport\\s*=\\s*\\{\\s*version\\s*=\\s*"=${releaseVersion.replaceAll(".", "\\.")}",\\s*path\\s*=\\s*"\\.\\.\\/flowersec-native-transport"\\s*\\}`),
  );
  assert.match(makefile, /cargo package --manifest-path flowersec-native-transport\/Cargo\.toml --locked --allow-dirty/);
  assert.match(makefile, /cargo publish --manifest-path flowersec-native-transport\/Cargo\.toml --locked --dry-run --allow-dirty/);
  assert.match(makefile, /cargo package --manifest-path flowersec-rust\/Cargo\.toml --locked --allow-dirty --list/);
  assert.match(rustWorkflow, /name: Publish native transport crate[\s\S]*working-directory: flowersec-native-transport[\s\S]*timeout --kill-after=5s 600s cargo publish --locked/);
  assert.match(rustWorkflow, /name: Wait for native transport registry readback/);
  assert.match(rustWorkflow, /name: Publish Flowersec Rust SDK[\s\S]*working-directory: flowersec-rust[\s\S]*timeout --kill-after=5s 600s cargo publish --locked/);
  assert.match(rustWorkflow, /name: Verify Flowersec Rust SDK registry readback/);
  assert.match(rustWorkflow, /verify-crates-release-package\.mjs flowersec-native-transport/);
  assert.match(rustWorkflow, /verify-crates-release-package\.mjs flowersec /);
  assert.match(rustWorkflow, /verify-crates-release-consumer\.mjs flowersec-native-transport/);
  assert.match(rustWorkflow, /verify-crates-release-consumer\.mjs flowersec /);
  assert.match(releaseWorkflow, /release:\n\s+needs: \[prepare, rust-publish, native-prebuilt\]/);
});

test("crates registry readback sends a compliant User-Agent for metadata and downloads", () => {
  const readback = fs.readFileSync(path.join(sourceRoot, "scripts/verify-crates-release-package.mjs"), "utf8");
  assert.match(
    readback,
    /const requestHeaders = Object\.freeze\(\{\s*"User-Agent": `flowersec-release-readback\/\$\{version\} \(https:\/\/github\.com\/floegence\/flowersec\)`,\s*\}\);/,
  );
  assert.equal(
    [...readback.matchAll(/fetchResponseBody\([\s\S]*?\{ headers: requestHeaders \}/g)].length,
    2,
    "metadata and crate download requests must both send the reviewed User-Agent",
  );
});

test("registry package readback avoids dynamic regex and network-derived archive files", () => {
  for (const filename of ["verify-crates-release-package.mjs", "verify-npm-release-package.mjs"]) {
    const readback = fs.readFileSync(path.join(sourceRoot, "scripts", filename), "utf8");
    assert.doesNotMatch(readback, /new RegExp\(/, `${filename} must not compile registry-derived regular expressions`);
    assert.doesNotMatch(readback, /fs\.writeFile\(/, `${filename} must not write registry response bytes to a path`);
    assert.match(readback, /MAX_ARCHIVE_BYTES/, `${filename} must bound downloaded archive bytes`);
    assert.doesNotMatch(readback, /"-C"/, `${filename} must not extract registry content into a directory`);
    assert.match(readback, /"-tzf", "-"/, `${filename} must validate the archive entry inventory from standard input`);
    assert.match(readback, /"-xOzf", "-"/, `${filename} must read only exact archive entries from standard input`);
    assert.match(readback, /assertSafeArchive/, `${filename} must reject unsafe paths, links, and duplicates`);
    assert.match(readback, /assertRegistryURL/, `${filename} must bind downloads to the reviewed registry hosts`);
    assert.match(readback, /tar readback timed out after/, `${filename} must classify tar timeouts`);
    assert.match(readback, /detached: true/, `${filename} must isolate tar process groups`);
  }
});

test("npm registry readback CLI enforces retries, status classes, JSON, and redirect policy", (t) => {
  const archiveBody = "hermetic registry archive";
  const tarballURL = "https://registry.npmjs.org/@floegence/flowersec-node-native/-/flowersec-node-native-3.0.1.tgz";
  const success = [{ status: 200, url: tarballURL, body: archiveBody }];
  for (const code of ["E404", "E408", "E429", "E500"]) {
    const harness = createRegistryReadbackHarness(t, {
      kind: "npm", commandFailures: 1, commandError: code, fetchResponses: success,
    });
    assert.equal(harness.result.status, 0, `${code}: ${harness.result.stdout}${harness.result.stderr}`);
    assert.equal(harness.commandCount, 2, `${code} must retry exactly once before success`);
  }

  const exhausted = createRegistryReadbackHarness(t, {
    kind: "npm", commandFailures: 99, commandError: "E404", fetchResponses: [],
  });
  assert.notEqual(exhausted.result.status, 0);
  assert.equal(exhausted.commandCount, 6);

  const forbidden = createRegistryReadbackHarness(t, {
    kind: "npm", commandFailures: 99, commandError: "E403", fetchResponses: [],
  });
  assert.notEqual(forbidden.result.status, 0);
  assert.equal(forbidden.commandCount, 1);

  const invalidJSON = createRegistryReadbackHarness(t, {
    kind: "npm", commandMode: "invalid-json", fetchResponses: [],
  });
  assert.notEqual(invalidJSON.result.status, 0);
  assert.equal(invalidJSON.commandCount, 1);

  for (const status of [408, 429, 503]) {
    const retried = createRegistryReadbackHarness(t, {
      kind: "npm",
      fetchResponses: [
        { status, url: tarballURL },
        { status: 200, url: tarballURL, body: archiveBody },
      ],
    });
    assert.equal(retried.result.status, 0, `${status}: ${retried.result.stdout}${retried.result.stderr}`);
    assert.equal(retried.fetchCount, 2);
  }

  const downloadForbidden = createRegistryReadbackHarness(t, {
    kind: "npm", fetchResponses: [{ status: 403, url: tarballURL }],
  });
  assert.notEqual(downloadForbidden.result.status, 0);
  assert.equal(downloadForbidden.fetchCount, 1);

  const trustedRedirect = createRegistryReadbackHarness(t, {
    kind: "npm",
    fetchResponses: [
      { status: 302, url: tarballURL, headers: { location: "/final.tgz" } },
      { status: 200, url: "https://registry.npmjs.org/final.tgz", body: archiveBody },
    ],
  });
  assert.equal(trustedRedirect.result.status, 0, `${trustedRedirect.result.stdout}${trustedRedirect.result.stderr}`);
  assert.equal(trustedRedirect.fetchCount, 2);

  const untrustedRedirect = createRegistryReadbackHarness(t, {
    kind: "npm",
    fetchResponses: [{ status: 302, url: tarballURL, headers: { location: "https://evil.invalid/archive.tgz" } }],
  });
  assert.notEqual(untrustedRedirect.result.status, 0);
  assert.match(untrustedRedirect.result.stderr, /unexpected registry download host/);
  assert.equal(untrustedRedirect.fetchCount, 1);
});

test("crates registry readback CLI enforces retries, status classes, JSON, and redirect policy", (t) => {
  const archiveBody = "hermetic registry archive";
  const metadataURL = "https://crates.io/api/v1/crates/flowersec-native-transport/3.0.1";
  const downloadURL = `${metadataURL}/download`;
  const staticURL = "https://static.crates.io/crates/flowersec-native-transport/flowersec-native-transport-3.0.1.crate";
  const metadata = JSON.stringify({
    version: {
      num: "3.0.1",
      checksum: crypto.createHash("sha256").update(archiveBody).digest("hex"),
    },
  });
  const successfulReadback = [
    { status: 200, url: metadataURL, body: metadata },
    { status: 302, url: downloadURL, headers: { location: staticURL } },
    { status: 200, url: staticURL, body: archiveBody },
  ];

  for (const status of [404, 408, 429, 503]) {
    const retried = createRegistryReadbackHarness(t, {
      kind: "crates",
      fetchResponses: [{ status, url: metadataURL }, ...successfulReadback],
    });
    assert.equal(retried.result.status, 0, `${status}: ${retried.result.stdout}${retried.result.stderr}`);
    assert.equal(retried.fetchCount, 4);
  }

  const exhausted = createRegistryReadbackHarness(t, {
    kind: "crates",
    fetchResponses: Array.from({ length: 6 }, () => ({ status: 404, url: metadataURL })),
  });
  assert.notEqual(exhausted.result.status, 0);
  assert.equal(exhausted.fetchCount, 6);

  const forbidden = createRegistryReadbackHarness(t, {
    kind: "crates", fetchResponses: [{ status: 403, url: metadataURL }],
  });
  assert.notEqual(forbidden.result.status, 0);
  assert.equal(forbidden.fetchCount, 1);

  const invalidJSON = createRegistryReadbackHarness(t, {
    kind: "crates", fetchResponses: [{ status: 200, url: metadataURL, body: "{" }],
  });
  assert.notEqual(invalidJSON.result.status, 0);
  assert.equal(invalidJSON.fetchCount, 1);

  for (const status of [408, 429, 503]) {
    const downloadRetried = createRegistryReadbackHarness(t, {
      kind: "crates",
      fetchResponses: [
        { status: 200, url: metadataURL, body: metadata },
        { status, url: downloadURL },
        { status: 302, url: downloadURL, headers: { location: staticURL } },
        { status: 200, url: staticURL, body: archiveBody },
      ],
    });
    assert.equal(
      downloadRetried.result.status,
      0,
      `${status}: ${downloadRetried.result.stdout}${downloadRetried.result.stderr}`,
    );
    assert.equal(downloadRetried.fetchCount, 4);
  }

  const untrustedRedirect = createRegistryReadbackHarness(t, {
    kind: "crates",
    fetchResponses: [
      { status: 200, url: metadataURL, body: metadata },
      { status: 302, url: downloadURL, headers: { location: "https://evil.invalid/archive.crate" } },
    ],
  });
  assert.notEqual(untrustedRedirect.result.status, 0);
  assert.match(untrustedRedirect.result.stderr, /unexpected registry download host/);
  assert.equal(untrustedRedirect.fetchCount, 2);
});

test("npm registry readback fails closed on unsafe archives, integrity, and manifest identity", (t) => {
  const archiveBody = "hermetic registry archive";
  const tarballURL = "https://registry.npmjs.org/@floegence/flowersec-node-native/-/flowersec-node-native-3.0.1.tgz";
  const fetchResponses = [{ status: 200, url: tarballURL, body: archiveBody }];
  const cases = [
    ["path escape", { tarListing: "package/package.json\npackage/../escape" }, /escapes the package root|true !== false/],
    ["duplicate path", { tarListing: "package/package.json\npackage/package.json" }, /duplicate archive entry/],
    ["symbolic link", {
      tarListing: "package/package.json\npackage/link",
      tarDetails: "- package/package.json\nl package/link",
    }, /archive links are not allowed/],
    ["integrity mismatch", { npmDistOverrides: { integrity: `sha512-${Buffer.from("wrong").toString("base64")}` } }, /tarball integrity mismatch/],
    ["manifest name mismatch", { manifestOverrides: { name: "@floegence/wrong" } }, /Expected values to be strictly equal/],
    ["manifest version mismatch", { manifestOverrides: { version: "9.9.9" } }, /Expected values to be strictly equal/],
    ["manifest source mismatch", { manifestOverrides: { flowersecSourceCommit: "f".repeat(40) } }, /source commit mismatch/],
  ];
  for (const [name, options, expected] of cases) {
    const harness = createRegistryReadbackHarness(t, { kind: "npm", fetchResponses, ...options });
    assert.notEqual(harness.result.status, 0, `${name} was accepted`);
    assert.match(harness.result.stderr, expected, `${name}: ${harness.result.stderr}`);
  }
});

test("crates registry readback fails closed on unsafe archives, checksum, and manifest identity", (t) => {
  const archiveBody = "hermetic registry archive";
  const crateRoot = "flowersec-native-transport-3.0.1";
  const metadataURL = "https://crates.io/api/v1/crates/flowersec-native-transport/3.0.1";
  const downloadURL = `${metadataURL}/download`;
  const staticURL = "https://static.crates.io/crates/flowersec-native-transport/flowersec-native-transport-3.0.1.crate";
  const responses = (checksum = crypto.createHash("sha256").update(archiveBody).digest("hex")) => [
    { status: 200, url: metadataURL, body: JSON.stringify({ version: { num: "3.0.1", checksum } }) },
    { status: 302, url: downloadURL, headers: { location: staticURL } },
    { status: 200, url: staticURL, body: archiveBody },
  ];
  const cases = [
    ["path escape", { tarListing: `${crateRoot}/Cargo.toml\n${crateRoot}/../escape\n${crateRoot}/.cargo_vcs_info.json` }, /escapes the package root|true !== false/],
    ["duplicate path", { tarListing: `${crateRoot}/Cargo.toml\n${crateRoot}/Cargo.toml\n${crateRoot}/.cargo_vcs_info.json` }, /duplicate archive entry/],
    ["symbolic link", {
      tarListing: `${crateRoot}/Cargo.toml\n${crateRoot}/.cargo_vcs_info.json\n${crateRoot}/link`,
      tarDetails: `- ${crateRoot}/Cargo.toml\n- ${crateRoot}/.cargo_vcs_info.json\nl ${crateRoot}/link`,
    }, /archive links are not allowed/],
    ["checksum mismatch", { fetchResponses: responses("f".repeat(64)) }, /Expected values to be strictly equal/],
    ["manifest name mismatch", { cargoManifest: '[package]\nname = "flowersec"\nversion = "3.0.1"' }, /Expected values to be strictly equal/],
    ["manifest version mismatch", { cargoManifest: '[package]\nname = "flowersec-native-transport"\nversion = "9.9.9"' }, /Expected values to be strictly equal/],
    ["manifest source mismatch", { vcsInfo: JSON.stringify({ git: { sha1: "f".repeat(40) } }) }, /Expected values to be strictly equal/],
  ];
  for (const [name, options, expected] of cases) {
    const harness = createRegistryReadbackHarness(t, {
      kind: "crates",
      fetchResponses: responses(),
      ...options,
    });
    assert.notEqual(harness.result.status, 0, `${name} was accepted`);
    assert.match(harness.result.stderr, expected, `${name}: ${harness.result.stderr}`);
  }
});

test("Cargo consumer readback CLI retries a failed dependency resolution attempt", (t) => {
  const harness = createRegistryReadbackHarness(t, {
    kind: "cargo", commandMode: "cargo-retry",
  });
  assert.equal(harness.result.status, 0, `${harness.result.stdout}${harness.result.stderr}`);
  assert.equal(harness.commandCount, 5);
});

test("registry archive CLI kills tar descendants on timeout and output cap", async (t) => {
  const archiveBody = "hermetic registry archive";
  const metadataURL = "https://crates.io/api/v1/crates/flowersec-native-transport/3.0.1";
  const downloadURL = `${metadataURL}/download`;
  const staticURL = "https://static.crates.io/crates/flowersec-native-transport/flowersec-native-transport-3.0.1.crate";
  const metadata = JSON.stringify({
    version: {
      num: "3.0.1",
      checksum: crypto.createHash("sha256").update(archiveBody).digest("hex"),
    },
  });
  const cratesResponses = [
    { status: 200, url: metadataURL, body: metadata },
    { status: 302, url: downloadURL, headers: { location: staticURL } },
    { status: 200, url: staticURL, body: archiveBody },
  ];
  const npmURL = "https://registry.npmjs.org/@floegence/flowersec-node-native/-/flowersec-node-native-3.0.1.tgz";
  for (const [kind, fetchResponses] of [
    ["crates", cratesResponses],
    ["npm", [{ status: 200, url: npmURL, body: archiveBody }]],
  ]) {
    const timedOut = createRegistryReadbackHarness(t, {
      kind, fetchResponses, tarMode: "timeout", clampOperationTimeout: true,
    });
    assert.notEqual(timedOut.result.status, 0);
    assert.match(timedOut.result.stderr, /tar readback timed out after 30000ms/);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    assert.equal(fs.existsSync(timedOut.descendantMarker), false, `${kind} timed-out tar descendant survived process-group cleanup`);

    const outputCapped = createRegistryReadbackHarness(t, {
      kind, fetchResponses, tarMode: "output-entry",
    });
    assert.notEqual(outputCapped.result.status, 0);
    assert.match(outputCapped.result.stderr, /tar output exceeds the readback limit/);
    await new Promise((resolve) => setTimeout(resolve, 300));
    assert.equal(fs.existsSync(outputCapped.descendantMarker), false, `${kind} output-capped tar descendant survived process-group cleanup`);
  }
});

test("Rust registry publication waits for exact consumer resolution at each dependency layer", () => {
  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/rust-release.yml"), "utf8");
  const consumer = fs.readFileSync(path.join(sourceRoot, "scripts/verify-crates-release-consumer.mjs"), "utf8");
  assert.match(consumer, /cargo.*add/);
  assert.match(consumer, /@=\$\{version\}/);
  assert.match(consumer, /cargo.*check/);
  assert.match(consumer, /const MAX_ATTEMPTS = 12/);
  const nativeConsumer = workflow.indexOf("verify-crates-release-consumer.mjs flowersec-native-transport");
  const sdkPublish = workflow.indexOf("name: Publish Flowersec Rust SDK");
  const sdkConsumer = workflow.indexOf("verify-crates-release-consumer.mjs flowersec ");
  assert.ok(nativeConsumer >= 0 && nativeConsumer < sdkPublish, "native registry consumer must gate SDK publication");
  assert.ok(sdkConsumer > sdkPublish, "SDK registry consumer must run after SDK publication");
});

test("native prebuilt release only packages the built addon", () => {
  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  assert.doesNotMatch(workflow, /node scripts\/native-addon-smoke\.mjs/);
  const uploadIndex = workflow.indexOf("name: Upload native prebuilt");
  const buildIndex = workflow.indexOf("name: Build native addon");
  assert.ok(buildIndex >= 0 && buildIndex < uploadIndex, "native build must precede upload");
});

test("GHCR digest verification validates signature, provenance, and command failures", (t) => {
  const eventual = runGhcrDigestVerificationHarness(t, { docker: "eventual", signature: "success-tag" });
  assert.equal(eventual.result.status, 0, `${eventual.result.stdout}${eventual.result.stderr}`);
  assert.equal(Number(fs.readFileSync(eventual.countFile, "utf8")), 2);
  assert.equal(fs.readFileSync(eventual.sleepFile, "utf8").trim(), "5");
  const cosignCalls = fs.readFileSync(eventual.cosignLog, "utf8");
  assert.match(cosignCalls, /refs\/heads\/main/);
  assert.match(cosignCalls, /refs\/tags\/flowersec-go\/v3\.0\.1/);
  assert.match(cosignCalls, new RegExp(`ghcr\\.io/test/flowersec-runtime@${testImageDigest}`));

  const rejectedSignature = runGhcrDigestVerificationHarness(t, { signature: "reject" });
  assert.notEqual(rejectedSignature.result.status, 0);
  assert.match(rejectedSignature.result.stderr, /signature does not match the exact main or release-version-tag workflow identity/);

  for (const timeoutExit of [124, 137]) {
    const timedOutSignature = runGhcrDigestVerificationHarness(t, { timeoutPhase: "signature", timeoutExit });
    assert.equal(timedOutSignature.result.status, 124, timedOutSignature.result.stderr);
    assert.match(timedOutSignature.result.stderr, /signature verification timed out after 60s/);

    const timedOutProvenance = runGhcrDigestVerificationHarness(t, { timeoutPhase: "provenance", timeoutExit });
    assert.equal(timedOutProvenance.result.status, 124, timedOutProvenance.result.stderr);
    assert.match(timedOutProvenance.result.stderr, /provenance readback timed out after 30s/);
  }

  const failedProvenance = runGhcrDigestVerificationHarness(t, { provenanceMode: "failure" });
  assert.equal(failedProvenance.result.status, 69, failedProvenance.result.stderr);
  assert.match(failedProvenance.result.stderr, /provenance readback failed with exit 69/);

  const mutations = [
    ["missing platform", (value) => { delete value["linux/arm64"]; }],
    ["wrong source SHA", (value) => { value["linux/amd64"].SLSA.buildDefinition.externalParameters.request.args["build-arg:COMMIT"] = "f".repeat(40); }],
    ["wrong version", (value) => { value["linux/amd64"].SLSA.buildDefinition.externalParameters.request.args["build-arg:VERSION"] = "v9.9.9"; }],
    ["wrong VCS source", (value) => { value["linux/amd64"].SLSA.buildDefinition.externalParameters.request.root.request.args["vcs:source"] = "https://github.com/evil/fork"; }],
    ["wrong build type", (value) => { value["linux/amd64"].SLSA.buildDefinition.buildType = "https://example.invalid/build"; }],
  ];
  for (const [name, mutate] of mutations) {
    const provenance = structuredClone(validGhcrProvenance());
    mutate(provenance);
    const rejected = runGhcrDigestVerificationHarness(t, { provenance });
    assert.notEqual(rejected.result.status, 0, `${name} was accepted`);
  }
});

test("GHCR tag readback retries both promoted tags and classifies marker timeouts", (t) => {
  const eventual = runGhcrTagReadbackHarness(t, { docker: "eventual" });
  assert.equal(eventual.result.status, 0, `${eventual.result.stdout}${eventual.result.stderr}`);
  assert.match(eventual.result.stdout, /flowersec-runtime:3\.0\.1/);
  assert.match(eventual.result.stdout, /flowersec-runtime:latest/);
  assert.equal(Number(fs.readFileSync(eventual.countFile, "utf8")), 4);
  assert.deepEqual(fs.readFileSync(eventual.sleepFile, "utf8").trim().split("\n"), ["5", "5"]);

  for (const timeoutExit of [124, 137]) {
    const timedOut = runGhcrTagReadbackHarness(t, { timeout: true, timeoutExit });
    assert.notEqual(timedOut.result.status, 0);
    assert.match(timedOut.result.stderr, /inspect timed out after 30s \(killed after 5s grace\)/);
    assert.equal(Number(fs.existsSync(timedOut.countFile) ? fs.readFileSync(timedOut.countFile, "utf8") : "0"), 0);
    assert.deepEqual(fs.readFileSync(timedOut.sleepFile, "utf8").trim().split("\n"), ["5", "10", "15", "20", "25"]);
  }
});

test("GHCR version-state inspection distinguishes existing, missing, and timed-out tags", (t) => {
  const existing = runGhcrVersionStateHarness(t, { docker: "existing", githubReleaseExists: true });
  assert.equal(existing.result.status, 0, `${existing.result.stdout}${existing.result.stderr}`);
  assert.equal(existing.output, `exists=true\ndigest=sha256:${"0".repeat(64)}\n`);

  const missing = runGhcrVersionStateHarness(t, { docker: "missing", githubReleaseExists: false });
  assert.equal(missing.result.status, 0, `${missing.result.stdout}${missing.result.stderr}`);
  assert.equal(missing.output, "exists=false\ndigest=\n");

  for (const timeoutExit of [124, 137]) {
    const timedOut = runGhcrVersionStateHarness(t, { docker: "timeout", githubReleaseExists: true, timeoutExit });
    assert.equal(timedOut.result.status, 124, `${timedOut.result.stdout}${timedOut.result.stderr}`);
    assert.match(timedOut.result.stderr, /GHCR version-tag inspection timed out after 30s \(killed after 5s grace\)/);
    assert.equal(timedOut.output, "");
  }

  const recoveryMissing = runGhcrVersionStateHarness(t, { docker: "missing", githubReleaseExists: true });
  assert.equal(recoveryMissing.result.status, 0, recoveryMissing.result.stderr);
  assert.equal(recoveryMissing.output, "exists=false\ndigest=\n");

  const invalidDigest = runGhcrVersionStateHarness(t, { docker: "invalid-digest", githubReleaseExists: true });
  assert.notEqual(invalidDigest.result.status, 0);
  assert.match(invalidDigest.result.stderr, /no valid manifest digest/);
  assert.equal(invalidDigest.output, "");

  const registryFailure = runGhcrVersionStateHarness(t, { docker: "failure", githubReleaseExists: true });
  assert.equal(registryFailure.result.status, 70);
  assert.match(registryFailure.result.stderr, /registry unavailable/);
  assert.match(registryFailure.result.stderr, /inspection failed with exit 70/);
  assert.equal(registryFailure.output, "");
});

test("npm recovery fails closed for downloaded asset and package validation errors", (t) => {
  for (const [mode, evidence] of [
    ["asset-closure", ""],
    ["signature", "release asset signature does not match"],
    ["checksum", "injected checksum mismatch"],
    ["source-manifest", "injected source manifest mismatch"],
    ["platform-manifest", "injected platform manifest mismatch"],
    ["archive-member", ""],
  ]) {
    const result = runNpmRecoveryValidationHarness(t, mode);
    assert.notEqual(result.status, 0, `${mode} was accepted`);
    if (evidence !== "") assert.match(result.stderr, new RegExp(evidence));
  }
});

test("GHCR release is serialized and builds an unsigned digest before tag mutation", () => {
  const workflowFile = path.join(sourceRoot, ".github/workflows/release.yml");
  const ruby = [
    'require "psych"',
    'workflow = Psych.safe_load(File.read(ARGV.fetch(0)), aliases: false)',
    'print JSON.generate(workflow)',
  ].join("\n");
  const parsed = spawnSync("ruby", ["-W0", "-rpsych", "-rjson", "-e", ruby, workflowFile], { encoding: "utf8" });
  assert.equal(parsed.status, 0, parsed.stderr);
  const workflow = JSON.parse(parsed.stdout);
  assert.deepEqual(workflow.concurrency, { group: "flowersec-release", "cancel-in-progress": false });
  assert.deepEqual(workflow.jobs["rust-publish"].with, {
    version: "${{ needs.prepare.outputs.version }}",
    release_lock_held: true,
  });
  const steps = workflow.jobs.release.steps;
  const build = steps.find((step) => step.name === "Build and push runtime image by digest");
  assert.equal(build.if, "steps.runtime-state.outputs.exists == 'false'");
  assert.equal(build.with.outputs, "type=image,name=ghcr.io/${{ github.repository_owner }}/flowersec-runtime,push-by-digest=true,name-canonical=true,push=true");
  assert.equal(build.with.provenance, "mode=max");
  assert.equal(Object.hasOwn(build.with, "tags"), false);
  assert.equal(Object.hasOwn(build.with, "push"), false);
});

test("GHCR keyless signing is identity-bound and classifies both timeout exits", (t) => {
  const signed = runGhcrSigningHarness(t);
  assert.equal(signed.result.status, 0, `${signed.result.stdout}${signed.result.stderr}`);
  assert.match(fs.readFileSync(signed.cosignLog, "utf8"), new RegExp(`^sign --yes --use-signing-config=false ghcr\\.io/floegence/flowersec-runtime@${testImageDigest}`));

  const untrusted = runGhcrSigningHarness(t, {
    workflowRef: "floegence/flowersec/.github/workflows/release.yml@refs/heads/unreviewed",
  });
  assert.notEqual(untrusted.result.status, 0);
  assert.match(untrusted.result.stderr, /exact main or release-version-tag workflow identity/);
  assert.equal(fs.existsSync(untrusted.cosignLog), false);

  for (const timeoutExit of [124, 137]) {
    const timedOut = runGhcrSigningHarness(t, { timeoutExit });
    assert.equal(timedOut.result.status, 124, timedOut.result.stderr);
    assert.match(timedOut.result.stderr, /keyless signing timed out after 120s/);
  }
});

test("GHCR immutable publication and latest promotion use digest-only sources", (t) => {
  const published = runGhcrTagMutationHarness(t, "Publish immutable GHCR version tag");
  assert.equal(published.result.status, 0, `${published.result.stdout}${published.result.stderr}`);
  assert.match(published.dockerLog, /imagetools inspect ghcr\.io\/floegence\/flowersec-runtime:3\.0\.1/);
  assert.match(
    published.dockerLog,
    new RegExp(`imagetools create --tag ghcr\\.io/floegence/flowersec-runtime:3\\.0\\.1 ghcr\\.io/floegence/flowersec-runtime@${testImageDigest}`),
  );

  const existing = runGhcrTagMutationHarness(t, "Publish immutable GHCR version tag", { dockerMode: "existing" });
  assert.notEqual(existing.result.status, 0);
  assert.match(existing.result.stderr, /refusing to overwrite existing immutable GHCR version tag/);
  assert.doesNotMatch(existing.dockerLog, /imagetools create/);

  const promoted = runGhcrTagMutationHarness(t, "Promote GHCR latest tag");
  assert.equal(promoted.result.status, 0, `${promoted.result.stdout}${promoted.result.stderr}`);
  assert.equal(
    promoted.dockerLog.trim(),
    `buildx imagetools create --tag ghcr.io/floegence/flowersec-runtime:latest ghcr.io/floegence/flowersec-runtime@${testImageDigest}`,
  );

  for (const timeoutExit of [124, 137]) {
    for (const timeoutPhase of ["inspect", "create"]) {
      const timedOut = runGhcrTagMutationHarness(t, "Publish immutable GHCR version tag", { timeoutExit, timeoutPhase });
      assert.equal(timedOut.result.status, 124, timedOut.result.stderr);
      assert.match(timedOut.result.stderr, timeoutPhase === "inspect"
        ? /prepublication inspection timed out after 30s/
        : /version-tag publication timed out after 60s/);
    }
    const promotionTimeout = runGhcrTagMutationHarness(t, "Promote GHCR latest tag", { timeoutExit, timeoutPhase: "create" });
    assert.equal(promotionTimeout.result.status, 124, promotionTimeout.result.stderr);
    assert.match(promotionTimeout.result.stderr, /latest-tag promotion timed out after 60s/);
  }
});

test("release workflow reports bounded asset and registry publication timeouts", (t) => {
  for (const timeoutExit of [124, 137]) {
    const asset = runNpmRecoveryAssetTimeoutHarness(t, timeoutExit);
    assert.equal(asset.status, 124, `${asset.stdout}${asset.stderr}`);
    assert.match(asset.stderr, /GitHub Release asset download timed out after 120s \(killed after 5s grace\)/);

    const npmView = runNpmCommandTimeoutHarness(t, "view", timeoutExit);
    assert.equal(npmView.status, 124, `${npmView.stdout}${npmView.stderr}`);
    assert.match(npmView.stderr, /npm view timed out after 60s \(killed after 5s grace\): @floegence\/test-package@3\.0\.1/);

    const npmPublish = runNpmCommandTimeoutHarness(t, "publish", timeoutExit);
    assert.equal(npmPublish.status, 124, `${npmPublish.stdout}${npmPublish.stderr}`);
    assert.match(npmPublish.stderr, /npm publish timed out after 180s \(killed after 5s grace\): @floegence\/test-package@3\.0\.1/);

    for (const [stepName, crateName] of [
      ["Publish native transport crate", "flowersec-native-transport"],
      ["Publish Flowersec Rust SDK", "flowersec"],
    ]) {
      const cargo = runCargoPublishTimeoutHarness(t, stepName, timeoutExit);
      assert.equal(cargo.status, 124, `${stepName}: ${cargo.stdout}${cargo.stderr}`);
      assert.equal(
        cargo.stderr.trim(),
        `cargo publish timed out after 600s (killed after 5s grace): ${crateName}`,
      );
    }
  }
});

test("registry readback bounds chunked bodies and metadata deadlines", async (t) => {
  let mode = "stall";
  let closedConnections = 0;
  const server = createServer((request, response) => {
    if (mode === "redirect" && request.url !== "/final") {
      response.writeHead(302, { location: "/final" });
      response.end();
      return;
    }
    if (mode === "untrusted-redirect") {
      response.writeHead(302, { location: "https://evil.invalid/archive" });
      response.end();
      return;
    }
    if (mode === "header-oversize") {
      response.writeHead(200, { "content-type": "application/octet-stream", "content-length": "999" });
      response.write("partial");
      return;
    }
    response.writeHead(200, { "content-type": "application/octet-stream" });
    if (mode === "stall") {
      response.write("partial");
      return;
    }
    response.end("0123456789abcdef");
  });
  server.on("connection", (socket) => socket.once("close", () => { closedConnections += 1; }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}`;
  await assert.rejects(fetchResponseBody(url, {}, 64, 50), /timed out after 50ms/);
  const closedBeforeHeaderValidation = closedConnections;
  mode = "header-oversize";
  await assert.rejects(fetchResponseBody(url, {}, 8, 500), /invalid registry archive size/);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(closedConnections > closedBeforeHeaderValidation, "header validation failure must close the response connection");
  mode = "oversize";
  await assert.rejects(fetchResponseBody(url, {}, 8, 500), /exceeds 8-byte limit/);
  mode = "redirect";
  const redirected = await fetchResponseBody(url, {}, 64, 500, (candidate) => {
    assert.equal(new URL(candidate.url).hostname, "127.0.0.1");
  });
  assert.equal(redirected.body.toString("utf8"), "0123456789abcdef");
  mode = "untrusted-redirect";
  await assert.rejects(
    fetchResponseBody(url, {}, 64, 500, (candidate) => {
      assert.equal(new URL(candidate.url).hostname, "127.0.0.1");
    }),
    /127\.0\.0\.1|evil\.invalid/,
  );
});

test("bounded child readback classifies limits and kills background descendants", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-bounded-child-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const outputMarker = path.join(root, "output-marker");
  const timeoutMarker = path.join(root, "timeout-marker");
  await assert.rejects(
    execFileBounded("bash", ["-c", '(sleep 0.2; printf leaked > "$1") & while :; do printf xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done', "--", outputMarker], { maxStdoutBytes: 1024 }, 10_000),
    /output exceeded the bounded readback limit/,
  );
  await assert.rejects(
    execFileBounded("bash", ["-c", '(sleep 0.2; printf leaked > "$1") & sleep 2', "--", timeoutMarker], {}, 50),
    (error) => error.code === "ETIMEDOUT" && /timed out after 50ms/.test(error.message),
  );
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(fs.existsSync(outputMarker), false, "output-capped background descendant survived");
  assert.equal(fs.existsSync(timeoutMarker), false, "timed-out background descendant survived");
});

test("bounded child readback rejects unreviewed executables", async () => {
  await assert.rejects(
    execFileBounded("sh", ["-c", "exit 0"]),
    /unsupported release readback executable/,
  );
});

test("documentation distinguishes injector, real weaknet, required performance, and optional WebTransport", () => {
  const matrix = fs.readFileSync(path.join(sourceRoot, "docs/TEST_MATRIX.md"), "utf8");
  const architecture = fs.readFileSync(path.join(sourceRoot, "docs/TRANSPORT_V2_ARCHITECTURE.md"), "utf8");
  assert.match(matrix, /diagnostic\/flowersec-weaknet\/\{websocket,raw-quic\}\/direct/);
  assert.match(matrix, /diagnostic\/flowersec-weaknet\/\{websocket,raw-quic\}\/tunnel\/representative/);
  assert.match(matrix, /Go-owned/);
  assert.match(matrix, /performance\/throughput\/\{wss,raw-quic\}/);
  assert.match(matrix, /performance-optional/);
  assert.doesNotMatch(matrix, /Swift WSS against Go, Rust, and Node/);
  assert.match(architecture, /not multi-language performance parity/);
  assert.match(architecture, /not a supported endpoint-client\s+tunnel path or TunnelRuntime capability/);
  assert.doesNotMatch(architecture, /Linux system tests include[^\n]*real path migration[^\n]*IPv4\/IPv6 PMTUD/);
});

test("npm release readback verifies tarball integrity, manifest, platform metadata, and source commit", () => {
  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  const readback = fs.readFileSync(path.join(sourceRoot, "scripts/verify-npm-release-package.mjs"), "utf8");
  assert.match(workflow, /node scripts\/verify-npm-release-package\.mjs/);
  assert.match(readback, /npm.*view/);
  assert.match(readback, /EAI_AGAIN/);
  assert.match(readback, /dist\.tarball/);
  assert.match(readback, /dist\.integrity/);
  assert.match(workflow, /stage-npm-release-metadata\.mjs/);
  assert.match(readback, /flowersecSourceCommit/);
  assert.match(workflow, /scripts\/verify-npm-release-package\.mjs/);
  assert.match(readback, /optionalDependencies/);
  assert.match(readback, /os/);
  assert.match(readback, /cpu/);
  assert.match(readback, /libc/);
  assert.match(readback, /manifest\.main/);
  assert.match(readback, /flowersec-node-native/);
  assert.doesNotMatch(workflow, /npm-consumer-smoke:/);
  assert.doesNotMatch(workflow, /verify-npm-release-consumer\.mjs/);
  assert.match(workflow, /actions\/setup-go/);
  const goConsumer = fs.readFileSync(
    path.join(sourceRoot, "scripts/fixtures/npm-release-go-node-raw-quic/main.go"),
    "utf8",
  );
  assert.match(goConsumer, /NewRawQUICDirectListener/);
  assert.match(goConsumer, /NewAcceptor/);
  assert.match(goConsumer, /IssueDirect/);
  assert.match(goConsumer, /HandleRPC/);
  assert.match(goConsumer, /HandleStream/);
  assert.match(goConsumer, /SessionClosed/);
  assert.match(goConsumer, /accepted lease was not released/);
  assert.doesNotMatch(goConsumer, /\/internal\//);
});

test("release recovery restores readback scripts from the reviewed workflow SHA after immutable tag checkout", () => {
  const releaseWorkflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  const rustWorkflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/rust-release.yml"), "utf8");
  const npmRecovery = releaseWorkflow.slice(releaseWorkflow.indexOf("\n  npm-recovery:"));
  for (const [workflow, files, invocation] of [[npmRecovery, ["scripts/release-readback.mjs", "scripts/verify-npm-release-package.mjs"], "node scripts/verify-npm-release-package.mjs"], [rustWorkflow, ["scripts/release-readback.mjs", "scripts/verify-crates-release-package.mjs", "scripts/verify-crates-release-consumer.mjs"], "node scripts/verify-crates-release-package.mjs"]]) {
    const restore = workflow.indexOf("git checkout \"$GITHUB_SHA\" --");
    assert.ok(restore >= 0);
    const checkout = workflow.lastIndexOf("refs/tags/flowersec-", restore);
    assert.ok(checkout >= 0);
    for (const file of files) assert.match(workflow.slice(restore, restore + 500), new RegExp(file.replaceAll(".", "\\.")));
    assert.ok(workflow.indexOf(invocation) > restore);
  }
});

test("release recovery preserves immutable assets and publishes npm from those exact archives", () => {
  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  assert.match(workflow, /mode:\n\s+description: "Recovery scope"[\s\S]*default: npm-only[\s\S]*options:\n\s+- full\n\s+- npm-only/);
  assert.match(workflow, /release_exists: \$\{\{ steps\.release-state\.outputs\.exists \}\}/);
  assert.match(workflow, /release_complete: \$\{\{ steps\.release-state\.outputs\.complete \}\}/);
  assert.match(workflow, /name: Inspect immutable GitHub Release state/);
  assert.match(workflow, /npm-only recovery requires an existing immutable GitHub Release/);
  assert.match(workflow, /\.assets\[\].*\.name.*\.size.*\.state/);
  assert.match(workflow, /cmp -s "\$expected_file" "\$actual_file"/);
  assert.match(workflow, /existing GitHub Release failed content readback and will require full recovery/);
  assert.match(
    workflow,
    /native-prebuilt:[\s\S]*if: needs\.prepare\.outputs\.mode == 'full' && needs\.prepare\.outputs\.release_complete == 'false'/,
  );
  assert.match(
    workflow,
    /release:[\s\S]*needs\.prepare\.outputs\.release_complete == 'false' && needs\.native-prebuilt\.result == 'success'[\s\S]*needs\.prepare\.outputs\.release_complete == 'true' && needs\.native-prebuilt\.result == 'skipped'/,
  );
  for (const step of ["Download native prebuilt packages", "Build release artifacts", "Generate release notes", "Publish GitHub Release"]) {
    assert.match(
      workflow,
      new RegExp(`name: ${step}\\n\\s+if: needs\\.prepare\\.outputs\\.release_complete == 'false'`),
      `${step} must run only when the release is absent or failed content verification`,
    );
  }
  assert.match(workflow, /name: Publish GitHub Release[\s\S]*overwrite_files: true/);
  assert.match(workflow, /name: Verify GitHub Release asset readback/);
  assert.match(workflow, /GitHub Release full asset readback closure mismatch/);
  assert.match(workflow, /flowersec-runtime_\$\{VERSION\}_linux_amd64\.tar\.gz/);
  assert.match(workflow, /flowersec-runtime_\$\{VERSION\}_linux_arm64\.tar\.gz/);
  assert.match(workflow, /DATE="\$\(git show -s --format='%cI' HEAD\)"/);
  assert.doesNotMatch(workflow, /DATE="\$\(date|date -u/);
  assert.match(workflow, /npm-recovery:\n\s+needs: \[prepare, release\]/);
  assert.match(
    workflow,
    /npm-recovery:[\s\S]*needs\.prepare\.outputs\.mode == 'full' && needs\.release\.result == 'success'[\s\S]*needs\.prepare\.outputs\.mode == 'npm-only' && needs\.release\.result == 'skipped'/,
  );
  assert.match(workflow, /gh release download "flowersec-go\/v\$\{VERSION\}"/);
  assert.match(workflow, /sha256sum --check checksums\.txt/);
  assert.match(workflow, /cosign sign-blob --yes/);
  assert.match(workflow, /--output-signature "\$\{asset\}\.sig"/);
  assert.match(workflow, /--output-certificate "\$\{asset\}\.pem"/);
  assert.match(workflow, /cosign verify-blob/);
  assert.match(workflow, /--certificate-identity "\$certificate_identity"/);
  assert.match(workflow, /--certificate-identity "\$identity"/);
  assert.match(workflow, /release\.yml@refs\/heads\/main/);
  assert.match(workflow, /release\.yml@refs\/tags\/flowersec-go\/v\$\{VERSION\}/);
  assert.doesNotMatch(workflow, /certificate-identity-regexp/);
  assert.match(workflow, /certificate-oidc-issuer "https:\/\/token\.actions\.githubusercontent\.com"/);
  assert.match(workflow, /checksums\.txt\.sig/);
  assert.match(workflow, /checksums\.txt\.pem/);
  assert.equal(
    workflow.match(/uses: sigstore\/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6/g)?.length,
    3,
  );
  assert.equal(workflow.match(/cosign-release: v3\.0\.6/g)?.length, 3);
  assert.match(workflow, /downloaded\[\*\].*expected\[\*\]/);
  assert.match(workflow, /awk -v file="\$archive"/);
  assert.match(workflow, /validate_manifest "\$archive" "\$package"/);
  assert.match(workflow, /\.flowersecSourceCommit == \$sha/);
  assert.match(workflow, /\.optionalDependencies == \{/);
  assert.match(workflow, /\.os == \[\$os\] and \.cpu == \[\$cpu\]/);
  assert.match(workflow, /\.error\.code == "E404"/);
  assert.match(workflow, /npm@11\.5\.1 publish "\$\{publish_args\[\@\]\}" "\.\/\$archive"/);
  assert.match(workflow, /--provenance=false/);
  assert.match(workflow, /repository_url/);
  assert.match(workflow, /if \[\[ -z "\$repository_url" \]\]/);
  assert.match(workflow, /\.dist\.integrity == \$integrity/);
  assert.match(workflow, /return "\$view_status"/);
  assert.match(workflow, /unlink "\$npm_error"/);
  assert.doesNotMatch(workflow, /tar -tzf "\$archive" \| grep -Fxq/);
  assert.doesNotMatch(workflow, /tar -tzf "\$core_archive" \| grep -Fxq/);
  assert.match(workflow, /rust-publish:[\s\S]*if: needs\.prepare\.outputs\.mode == 'full'/);
  const release = workflow.match(/  release:\n([\s\S]*?)\n  npm-recovery:/)?.[1] ?? "";
  const recovery = workflow.match(/  npm-recovery:\n([\s\S]*)/)?.[1] ?? "";
  assert.doesNotMatch(release, /npm@11\.5\.1 publish|npm publish/);
  assert.doesNotMatch(recovery, /npm ci|npm run build|cargo build|go build|action-gh-release|docker\/build-push-action/);
});

test("release state inspection fails closed and permits only valid recovery modes", (t) => {
  const inspectRelease = extractWorkflowStepRun(
    ".github/workflows/release.yml",
    "prepare",
    "Inspect immutable GitHub Release state",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-state-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const ghLog = path.join(root, "gh.log");
  const version = "3.0.0";
  const archives = [
    `floegence-flowersec-core-${version}.tgz`,
    `floegence-flowersec-node-native-${version}.tgz`,
    ...["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]
      .map((platform) => `floegence-flowersec-node-native-${platform}-${version}.tgz`),
    `flowersec-runtime_${version}_linux_amd64.tar.gz`,
    `flowersec-runtime_${version}_linux_arm64.tar.gz`,
  ];
  const expectedAssets = ["checksums.txt", ...archives]
    .flatMap((asset) => [asset, `${asset}.sig`, `${asset}.pem`]);
  const assetRows = expectedAssets.map((asset) => `${asset}\t1\tuploaded`).join("\n");
  fs.mkdirSync(bin);
  writeExecutable(path.join(bin, "gh"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> ${JSON.stringify(ghLog)}
if [[ "$1" == api ]]; then
  case "$GH_BEHAVIOR" in
    exists|corrupt-checksum|signature-mismatch|readback-missing) cat <<'EOF'
${assetRows}
EOF
      ;;
    partial) printf '%s\n' '${expectedAssets[0]}\t1\tuploaded' ;;
    duplicate) cat <<'EOF'
${assetRows}
${expectedAssets[0]}\t1\tuploaded
EOF
      ;;
    extra) cat <<'EOF'
${assetRows}
unexpected.bin\t1\tuploaded
EOF
      ;;
    empty) awk 'BEGIN { OFS="\t" } NR == 1 { $2 = 0 } { print $1, $2, $3 }' <<'EOF'
${assetRows}
EOF
      ;;
    pending) awk 'BEGIN { OFS="\t" } NR == 1 { $3 = "pending" } { print $1, $2, $3 }' <<'EOF'
${assetRows}
EOF
      ;;
    missing) echo 'gh: Not Found (HTTP 404)' >&2; exit 1 ;;
    *) echo 'gh: upstream unavailable (HTTP 503)' >&2; exit 1 ;;
  esac
  exit 0
fi
destination=""
while (( $# > 0 )); do
  if [[ "$1" == --dir ]]; then destination="$2"; shift 2; else shift; fi
done
test -n "$destination"
mkdir -p "$destination"
assets=(
${expectedAssets.map((asset) => `  ${JSON.stringify(asset)}`).join("\n")}
)
if [[ "$GH_BEHAVIOR" == partial ]]; then assets=("${expectedAssets[0]}"); fi
for asset in "\${assets[@]}"; do printf x > "$destination/$asset"; done
if [[ "$GH_BEHAVIOR" == readback-missing ]]; then
  rm "$destination/flowersec-runtime_${version}_linux_arm64.tar.gz"
fi
if [[ "$GH_BEHAVIOR" != partial ]]; then
  : > "$destination/checksums.txt"
  for archive in ${archives.map((archive) => JSON.stringify(archive)).join(" ")}; do
    printf '%064d  %s\n' 0 "$archive" >> "$destination/checksums.txt"
  done
fi
`);
  writeExecutable(path.join(bin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do shift; done
shift
"$@"
`);
  writeExecutable(path.join(bin, "sha256sum"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$GH_BEHAVIOR" == corrupt-checksum ]]; then
  printf 'injected checksum mismatch\n' >&2
  exit 1
fi
`);
  writeExecutable(path.join(bin, "cosign"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$GH_BEHAVIOR" == signature-mismatch ]]; then exit 1; fi
`);
  writeExecutable(path.join(bin, "find"), `#!/usr/bin/env bash
set -euo pipefail
for file in "$1"/*; do basename "$file"; done
`);

  const inspect = (behavior, mode) => {
    const output = path.join(root, `output-${behavior}-${mode}`);
    const result = spawnSync("bash", ["-c", inspectRelease], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: isolatedEnvironment({
        GH_BEHAVIOR: behavior,
        GITHUB_OUTPUT: output,
        GITHUB_REPOSITORY: "floegence/flowersec",
        PATH: `${bin}:${process.env.PATH}`,
        RELEASE_MODE: mode,
        RELEASE_VERSION: version,
      }),
    });
    return { result, output: fs.existsSync(output) ? fs.readFileSync(output, "utf8") : "" };
  };

  const existing = inspect("exists", "full");
  assert.equal(existing.result.status, 0, existing.result.stderr);
  assert.equal(existing.output, "exists=true\ncomplete=true\n");

  for (const behavior of ["partial", "corrupt-checksum", "signature-mismatch"]) {
    const recoverable = inspect(behavior, "full");
    assert.equal(recoverable.result.status, 0, `${behavior}: ${recoverable.result.stderr}`);
    assert.equal(recoverable.output, "exists=true\ncomplete=false\n", behavior);
  }

  for (const behavior of ["duplicate", "extra", "empty", "pending", "readback-missing"]) {
    const invalid = inspect(behavior, "full");
    assert.equal(invalid.result.status, 1, `${behavior}: ${invalid.result.stderr}`);
    assert.match(invalid.result.stderr, /asset|release/i);
    assert.equal(invalid.output, "");
  }

  const firstRelease = inspect("missing", "full");
  assert.equal(firstRelease.result.status, 0, firstRelease.result.stderr);
  assert.equal(firstRelease.output, "exists=false\ncomplete=false\n");

  const invalidRecovery = inspect("missing", "npm-only");
  assert.equal(invalidRecovery.result.status, 1, invalidRecovery.result.stderr);
  assert.match(invalidRecovery.result.stderr, /requires an existing immutable GitHub Release/);
  assert.equal(invalidRecovery.output, "");

  const incompleteNpmRecovery = inspect("partial", "npm-only");
  assert.equal(incompleteNpmRecovery.result.status, 1, incompleteNpmRecovery.result.stderr);
  assert.match(incompleteNpmRecovery.result.stderr, /requires a complete immutable GitHub Release/);
  assert.equal(incompleteNpmRecovery.output, "");

  const apiFailure = inspect("error", "full");
  assert.equal(apiFailure.result.status, 1, apiFailure.result.stderr);
  assert.match(apiFailure.result.stderr, /HTTP 503/);
  assert.equal(apiFailure.output, "");
  assert.match(fs.readFileSync(ghLog, "utf8"), /repos\/floegence\/flowersec\/releases\/tags\/flowersec-go\/v3\.0\.0/);
});

test("GitHub Release readback verifies full runtime and npm asset closure", (t) => {
  const readback = extractWorkflowStepRun(
    ".github/workflows/release.yml",
    "release",
    "Verify GitHub Release asset readback",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-readback-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  fs.mkdirSync(bin);
  const version = "3.0.0";
  const archives = [
    `floegence-flowersec-core-${version}.tgz`,
    `floegence-flowersec-node-native-${version}.tgz`,
    ...["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]
      .map((platform) => `floegence-flowersec-node-native-${platform}-${version}.tgz`),
    `flowersec-runtime_${version}_linux_amd64.tar.gz`,
    `flowersec-runtime_${version}_linux_arm64.tar.gz`,
  ];
  const assets = ["checksums.txt", ...archives]
    .flatMap((asset) => [asset, `${asset}.sig`, `${asset}.pem`]);
  const cosignLog = path.join(root, "cosign.log");
  writeExecutable(path.join(bin, "timeout"), `#!/usr/bin/env bash
set -euo pipefail
while [[ "$1" == --* ]]; do shift; done
shift
"$@"
`);
  writeExecutable(path.join(bin, "gh"), `#!/usr/bin/env bash
set -euo pipefail
destination=""
while (( $# > 0 )); do
  if [[ "$1" == --dir ]]; then destination="$2"; shift 2; else shift; fi
done
test -n "$destination"
mkdir -p "$destination"
assets=(
${assets.map((asset) => `  ${JSON.stringify(asset)}`).join("\n")}
)
for asset in "\${assets[@]}"; do printf x > "$destination/$asset"; done
: > "$destination/checksums.txt"
for archive in ${archives.map((archive) => JSON.stringify(archive)).join(" ")}; do
  printf '%064d  %s\n' 0 "$archive" >> "$destination/checksums.txt"
done
case "$FAKE_READBACK_MODE" in
  missing-runtime) rm "$destination/flowersec-runtime_${version}_linux_arm64.tar.gz" ;;
  missing-signature) rm "$destination/flowersec-runtime_${version}_linux_amd64.tar.gz.sig" ;;
esac
`);
  writeExecutable(path.join(bin, "sha256sum"), `#!/usr/bin/env bash
set -euo pipefail
if [[ "$FAKE_READBACK_MODE" == corrupt-checksum ]]; then
  printf 'injected checksum mismatch\n' >&2
  exit 1
fi
`);
  writeExecutable(path.join(bin, "cosign"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_COSIGN_LOG"
if [[ "$FAKE_READBACK_MODE" == runtime-signature && "$*" == *flowersec-runtime_3.0.0_linux_arm64.tar.gz* ]]; then
  exit 1
fi
`);
  writeExecutable(path.join(bin, "find"), `#!/usr/bin/env bash
set -euo pipefail
for file in "$1"/*; do basename "$file"; done
`);

  const runReadback = (mode) => spawnSync("bash", ["-c", readback], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment({
      FAKE_COSIGN_LOG: cosignLog,
      FAKE_READBACK_MODE: mode,
      GITHUB_REPOSITORY: "floegence/flowersec",
      PATH: `${bin}:${process.env.PATH}`,
      RELEASE_VERSION: version,
    }),
  });

  const success = runReadback("success");
  assert.equal(success.status, 0, `${success.stdout}${success.stderr}`);
  const cosignCalls = fs.readFileSync(cosignLog, "utf8");
  assert.match(cosignCalls, /flowersec-runtime_3\.0\.0_linux_amd64\.tar\.gz/);
  assert.match(cosignCalls, /flowersec-runtime_3\.0\.0_linux_arm64\.tar\.gz/);

  for (const [mode, evidence] of [
    ["missing-runtime", /full asset readback closure mismatch/],
    ["missing-signature", /full asset readback closure mismatch/],
    ["corrupt-checksum", /injected checksum mismatch/],
    ["runtime-signature", /asset signature does not match a trusted workflow identity/],
  ]) {
    const rejected = runReadback(mode);
    assert.notEqual(rejected.status, 0, `${mode} was accepted`);
    assert.match(rejected.stderr, evidence);
  }
});

test("native npm platform packages carry repository metadata for provenance", () => {
  for (const platform of ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]) {
    const manifest = JSON.parse(fs.readFileSync(
      path.join(sourceRoot, `flowersec-node-native/npm/${platform}/package.json`),
      "utf8",
    ));
    assert.deepEqual(manifest.repository, {
      type: "git",
      url: "git+https://github.com/floegence/flowersec.git",
    }, `${platform} package must identify the source repository for npm provenance`);
  }
});

test("npm source install omits the unpublished native package closure", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package-lock.json"), "utf8"));
  const wrapperManifest = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-node-native/package.json"), "utf8"));
  const version = wrapperManifest.version;
  assert.match(version, /^\d+\.\d+\.\d+$/);
  assert.equal(manifest.optionalDependencies?.["@floegence/flowersec-node-native"], undefined);
  assert.equal(lock.packages?.[""].optionalDependencies?.["@floegence/flowersec-node-native"], undefined);
  assert.equal(lock.packages?.["node_modules/@floegence/flowersec-node-native"], undefined);
  for (const platform of ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]) {
    const packageName = `@floegence/flowersec-node-native-${platform}`;
    assert.equal(wrapperManifest.optionalDependencies?.[packageName], version);
    const platformManifest = JSON.parse(fs.readFileSync(
      path.join(sourceRoot, `flowersec-node-native/npm/${platform}/package.json`),
      "utf8",
    ));
    assert.equal(platformManifest.name, packageName);
    assert.equal(platformManifest.version, version);
  }
});

test("npm SBOM contains the complete native optional dependency closure", () => {
  const wrapperManifest = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-node-native/package.json"), "utf8"));
  const sbom = JSON.parse(fs.readFileSync(path.join(sourceRoot, "flowersec-ts/sbom/cyclonedx.json"), "utf8"));
  const version = wrapperManifest.version;
  const purl = (name) => `pkg:npm/${encodeURIComponent(name).replaceAll("%2F", "/")}@${version}`;
  const wrapperRef = purl("@floegence/flowersec-node-native");
  const platforms = ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]
    .map((platform) => purl(`@floegence/flowersec-node-native-${platform}`));
  const components = new Set(sbom.components.map((component) => component.purl));
  assert.ok(components.has(wrapperRef), "SBOM omits the native wrapper component");
  for (const platform of platforms) assert.ok(components.has(platform), `SBOM omits ${platform}`);
  const wrapperDependency = sbom.dependencies.find((dependency) => dependency.ref === wrapperRef);
  assert.deepEqual([...(wrapperDependency?.dependsOn ?? [])].sort(), [...platforms].sort());
});

test("npm release builds use the complete lockfile without omitting optional packages", () => {
  const workflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  assert.match(workflow, /npm ci --ignore-scripts --no-audit --no-fund/);
  assert.doesNotMatch(workflow, /npm install(?:\s|$)/);
  assert.doesNotMatch(workflow, /npm (?:ci|install) --omit=optional/);
});

test("npm release metadata staging binds every published manifest to one source commit", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-npm-metadata-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true });
  fs.copyFileSync(
    path.join(sourceRoot, "scripts/stage-npm-release-metadata.mjs"),
    path.join(root, "scripts/stage-npm-release-metadata.mjs"),
  );
  const manifests = [
    "flowersec-ts/package.json",
    "flowersec-node-native/package.json",
    "flowersec-node-native/npm/darwin-arm64/package.json",
    "flowersec-node-native/npm/darwin-x64/package.json",
    "flowersec-node-native/npm/linux-arm64-gnu/package.json",
    "flowersec-node-native/npm/linux-x64-gnu/package.json",
  ];
  fs.mkdirSync(path.join(root, "flowersec-ts"), { recursive: true });
  fs.mkdirSync(path.join(root, "flowersec-node-native"), { recursive: true });
  for (const platform of ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]) {
    fs.mkdirSync(path.join(root, `flowersec-node-native/npm/${platform}`), { recursive: true });
  }
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package.json"),
    '{"name":"@floegence/flowersec-core","version":"2.3.7"}\n',
  );
  fs.writeFileSync(
    path.join(root, "flowersec-node-native/package.json"),
    '{"name":"@floegence/flowersec-node-native","version":"2.3.7"}\n',
  );
  for (const platform of ["darwin-arm64", "darwin-x64", "linux-arm64-gnu", "linux-x64-gnu"]) {
    fs.writeFileSync(
      path.join(root, `flowersec-node-native/npm/${platform}/package.json`),
      JSON.stringify({ name: `@floegence/flowersec-node-native-${platform}`, version: "2.3.7" }) + "\n",
    );
  }
  const sourceCommit = "a".repeat(40);
  const result = spawnSync(process.execPath, [path.join(root, "scripts/stage-npm-release-metadata.mjs"), sourceCommit], { encoding: "utf8" });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  for (const relative of manifests) {
    assert.equal(JSON.parse(fs.readFileSync(path.join(root, relative), "utf8")).flowersecSourceCommit, sourceCommit);
  }
  const stagedCore = JSON.parse(fs.readFileSync(path.join(root, "flowersec-ts/package.json"), "utf8"));
  assert.deepEqual(stagedCore.optionalDependencies, {
    "@floegence/flowersec-node-native": "2.3.7",
  });
});

test("release policy mutations use bounded isolated concurrency", () => {
  const source = fs.readFileSync(import.meta.filename, "utf8");
  assert.match(source, /const releaseMutationConcurrency = 4;/);
  assert.match(
    source,
    /test\("release policy rejects disconnected or commented-out gates", \{ concurrency: releaseMutationConcurrency \}/,
  );
  assert.match(source, /await Promise\.all\(policyMutations\);/);
});

function runGit(args, options = {}) {
  const { env, ...spawnOptions } = options;
  const result = spawnSync("git", args, {
    encoding: "utf8",
    ...spawnOptions,
    env: isolatedEnvironment(env),
  });
  if (result.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`,
    );
  }
  return result.stdout.trim();
}

function executablePath(name) {
  const result = spawnSync("which", [name], {
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
  if (result.status !== 0) {
    throw new Error(`could not locate ${name}:\n${result.stdout}${result.stderr}`);
  }
  return result.stdout.trim();
}

function createReleaseScriptFixture(t, makeScript = "#!/bin/sh\nexit 0\n") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-script-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  const origin = path.join(root, "origin.git");
  const bin = path.join(root, "bin");
  const gitLog = path.join(root, "git.log");
  const goLog = path.join(root, "go.log");
  const realGit = executablePath("git");
  const realMake = executablePath("make");
  fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-ts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-go"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-rust/fuzz"), { recursive: true });
  fs.mkdirSync(path.join(repo, "examples/rust"), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });

  for (const file of mainGateGraphFiles) {
    const destination = path.join(repo, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, file), destination);
  }
  fs.copyFileSync(
    path.join(sourceRoot, "scripts/check-release-version-consistency.mjs"),
    path.join(repo, "scripts/check-release-version-consistency.mjs"),
  );
  fs.chmodSync(path.join(repo, "scripts/release.sh"), 0o755);
  fs.writeFileSync(
    path.join(repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.26.0" }),
  );
  fs.writeFileSync(
    path.join(repo, "flowersec-ts/package-lock.json"),
    JSON.stringify({ version: "0.26.0", packages: { "": { version: "0.26.0" } } }),
  );
  fs.writeFileSync(
    path.join(repo, "flowersec-go/go.mod"),
    "module github.com/floegence/flowersec/flowersec-go/v0\n",
  );
  fs.writeFileSync(path.join(repo, "Package.swift"), "// Flowersec release major: 0\n");
  fs.writeFileSync(
    path.join(repo, "flowersec-rust/Cargo.toml"),
    "[package]\nname = \"flowersec\"\nversion = \"0.26.0\"\n",
  );
  fs.writeFileSync(path.join(repo, "flowersec-rust/fuzz/Cargo.toml"), "[package]\nname = \"fuzz\"\n");
  fs.writeFileSync(path.join(repo, "examples/rust/Cargo.toml"), "[package]\nname = \"example\"\n");
  fs.writeFileSync(path.join(repo, "tracked.txt"), "clean\n");

  fs.writeFileSync(
    path.join(bin, "cargo"),
    "#!/bin/sh\nprintf '%s\\n' '{\"packages\":[{\"name\":\"flowersec\",\"version\":\"0.26.0\",\"source\":null}]}'\n",
  );
  fs.chmodSync(path.join(bin, "cargo"), 0o755);
  fs.writeFileSync(path.join(bin, "make"), makeScript);
  fs.chmodSync(path.join(bin, "make"), 0o755);
  fs.writeFileSync(
    path.join(bin, "go"),
    [
      "#!/bin/sh",
      "printf '%s\\n' \"$*\" >> \"$FLOWERSEC_TEST_GO_LOG\"",
      "if [ \"${FLOWERSEC_TEST_FAIL_NOTES:-0}\" = 1 ]; then exit 88; fi",
      "output=''",
      "previous=''",
      "for argument in \"$@\"; do",
      "  if [ \"$previous\" = --output ]; then output=\"$argument\"; fi",
      "  previous=\"$argument\"",
      "done",
      "[ -n \"$output\" ] && printf '%s\\n' '# release notes' > \"$output\"",
      "",
    ].join("\n"),
  );
  fs.chmodSync(path.join(bin, "go"), 0o755);
  fs.writeFileSync(
    path.join(bin, "git"),
    [
      "#!/bin/sh",
      "printf '%s\\n' \"$*\" >> \"$FLOWERSEC_TEST_GIT_LOG\"",
      "if [ \"$1\" = tag ] && [ \"${FLOWERSEC_TEST_FAIL_TAG:-}\" = \"${2:-}\" ]; then",
      "  exit 86",
      "fi",
      "if [ \"$1\" = push ] && [ \"${FLOWERSEC_TEST_FAIL_PUSH:-0}\" = 1 ]; then",
      "  exit 87",
      "fi",
      "exec \"$FLOWERSEC_TEST_REAL_GIT\" \"$@\"",
      "",
    ].join("\n"),
  );
  fs.chmodSync(path.join(bin, "git"), 0o755);

  runGit(["init", "--bare", origin]);
  runGit(["init", "-b", "main", repo]);
  runGit(["-C", repo, "config", "user.name", "Release Test"]);
  runGit(["-C", repo, "config", "user.email", "release-test@example.com"]);
  runGit(["-C", repo, "add", "."]);
  runGit(["-C", repo, "commit", "-m", "test: release fixture"]);
  runGit(["-C", repo, "remote", "add", "origin", origin]);
  runGit(["-C", repo, "push", "-u", "origin", "main"]);

  return { bin, gitLog, goLog, origin, realGit, realMake, repo };
}

function runReleaseScript(fixture, env = {}) {
  return spawnSync("bash", ["scripts/release.sh", "0.26.0"], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: isolatedEnvironment({
      FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
      FLOWERSEC_TEST_GO_LOG: fixture.goLog,
      FLOWERSEC_TEST_REAL_GIT: fixture.realGit,
      PATH: `${fixture.bin}:${process.env.PATH}`,
      ...env,
    }),
  });
}

function gitCommands(fixture) {
  const contents = fs.readFileSync(fixture.gitLog, "utf8").trim();
  return contents === "" ? [] : contents.split("\n");
}

function assertNoReleaseTags(fixture) {
  assert.equal(runGit(["-C", fixture.repo, "tag", "--list"]), "");
  assert.equal(runGit(["--git-dir", fixture.origin, "tag", "--list"]), "");
}

function assertReleaseDidNotStartPublication(fixture) {
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.equal(
    commands.some((command) => /^tag (?:flowersec-go\/v0\.26\.0|0\.26\.0|flowersec-rust\/v0\.26\.0) [0-9a-f]+$/.test(command)),
    false,
    commands.join("\n"),
  );
  assert.equal(commands.some((command) => command.startsWith("push ")), false, commands.join("\n"));
}

function createReleasePolicyFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-policy-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const file of releasePolicyFixtureFiles) {
    const destination = path.join(root, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, file), destination);
  }
  return root;
}

function workflowSnapshot(root) {
  const workflowRoot = path.join(root, ".github/workflows");
  return Object.fromEntries(
    fs.readdirSync(workflowRoot)
      .filter((file) => file.endsWith(".yml") || file.endsWith(".yaml"))
      .sort()
      .map((file) => [file, fs.readFileSync(path.join(workflowRoot, file), "utf8")]),
  );
}

function runReleasePolicy(root) {
  const sourceWorkflows = workflowSnapshot(sourceRoot);
  const fixtureWorkflows = workflowSnapshot(root);
  const sourceWorkflowNames = Object.keys(sourceWorkflows);
  const fixtureWorkflowNames = Object.keys(fixtureWorkflows);
  const workflowSetMatches = JSON.stringify(sourceWorkflowNames) === JSON.stringify(fixtureWorkflowNames);
  const workflowsChanged = JSON.stringify(sourceWorkflows) !== JSON.stringify(fixtureWorkflows);
  const changedNonWorkflowFiles = releasePolicyFixtureFiles.filter((file) => {
    if (file.startsWith(".github/workflows/")) return false;
    return fs.readFileSync(path.join(root, file), "utf8") !== fs.readFileSync(path.join(sourceRoot, file), "utf8");
  });
  if (workflowSetMatches && workflowsChanged && changedNonWorkflowFiles.length === 0) {
    return spawnSync("ruby", ["-W0", "scripts/check-release-workflows.rb"], {
      cwd: root,
      encoding: "utf8",
      env: isolatedEnvironment(),
    });
  }
  if (!workflowsChanged && changedNonWorkflowFiles.length === 1 && changedNonWorkflowFiles[0] === "Makefile") {
    return spawnSync("node", ["scripts/check-security-makefile.mjs", "Makefile"], {
      cwd: root,
      encoding: "utf8",
      env: isolatedEnvironment(),
    });
  }
  return spawnSync("bash", ["scripts/check-release-workflow-policy.sh"], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
}

test("release fixtures cannot modify an inherited hook repository", (t) => {
  const sentinel = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-sentinel-"));
  t.after(() => fs.rmSync(sentinel, { recursive: true, force: true }));
  runGit(["init", "-b", "main", sentinel]);
  const sentinelConfig = path.join(sentinel, ".git/config");
  const before = fs.readFileSync(sentinelConfig, "utf8");
  const canonical = spawnSync("git", ["rev-parse", "--local-env-vars"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(canonical.status, 0, canonical.stderr);
  for (const variable of canonical.stdout.trim().split("\n")) {
    assert.ok(repositoryLocalEnvironmentVariables.includes(variable), `missing Git local environment variable ${variable}`);
  }
  const original = Object.fromEntries(
    repositoryLocalEnvironmentVariables.map((variable) => [variable, process.env[variable]]),
  );

  try {
    for (const variable of repositoryLocalEnvironmentVariables) {
      process.env[variable] = "inherited";
    }
    process.env.GIT_DIR = path.join(sentinel, ".git");
    process.env.GIT_WORK_TREE = sentinel;
    process.env.GIT_INDEX_FILE = path.join(sentinel, ".git/index");
    const fixture = createReleaseScriptFixture(t);
    assert.equal(runGit(["-C", fixture.repo, "status", "--short"]), "");
  } finally {
    for (const variable of repositoryLocalEnvironmentVariables) {
      if (original[variable] === undefined) {
        delete process.env[variable];
      } else {
        process.env[variable] = original[variable];
      }
    }
  }

  assert.equal(fs.readFileSync(sentinelConfig, "utf8"), before);
});

test("release script rejects non-canonical versions before repository access", () => {
  for (const version of ["02.0.0", "2.00.0", "2.0.00"]) {
    const result = spawnSync("bash", ["scripts/release.sh", version], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: isolatedEnvironment(),
    });
    assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /major\.minor\.patch/);
  }
});

test("release gates stay wired into local checks and publication workflows", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const releaseWorkflow = fs.readFileSync(
    path.join(sourceRoot, ".github/workflows/release.yml"),
    "utf8",
  );
  const rustWorkflow = fs.readFileSync(
    path.join(sourceRoot, ".github/workflows/rust-release.yml"),
    "utf8",
  );
  const ciWorkflow = fs.readFileSync(
    path.join(sourceRoot, ".github/workflows/ci.yml"),
    "utf8",
  );
  const policyScript = fs.readFileSync(
    path.join(sourceRoot, "scripts/check-release-workflow-policy.sh"),
    "utf8",
  );

  assert.match(makefile, /^release-version-check:\n\tnode scripts\/check-release-version-consistency\.mjs$/m);
  assert.match(
    makefile,
    /^release-test:\n\tnode --test scripts\/check-release-version-consistency\.test\.mjs scripts\/release\.test\.mjs$/m,
  );
  assert.match(makefile, /^release-policy-check:\n(?:\t.*\n)*\t\$\(MAKE\) release-version-check$/m);
  assert.match(makefile, /^release-policy-check:\n(?:\t.*\n)*\t\$\(MAKE\) release-test$/m);
  assert.match(
    makefile,
    /^check: security-makefile-check\n\t\$\(MAKE\) release-policy-check$/m,
  );
  assert.match(makefile, /^check: security-makefile-check\n(?:\t.*\n)*\t\$\(MAKE\) final-integration-lanes$/m);
  assert.match(makefile, /^final-integration-lanes:\n\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 race \$\(MAKE\) final-race-check\n\tCARGO_NET_OFFLINE=true GOPROXY=off GOSUMDB=off npm_config_offline=true node scripts\/run-final-stage\.mjs 595 languages node scripts\/run-final-lanes\.mjs \$\(MAKE\) final-go-check final-ts-check final-swift-check final-rust-check\n\tnode scripts\/run-final-stage\.mjs 595 browser \$\(MAKE\) browser-smoke$/m);
  assert.match(makefile, /^release-check:\n\tnode scripts\/check-release-version-consistency\.mjs$/m);
  assert.doesNotMatch(makefile, /^release-check:\n(?:\t.*\n)*\t\$\(MAKE\) /m);
  assert.match(
    releaseWorkflow,
    /^\s+RELEASE_VERSION: \$\{\{ steps\.vars\.outputs\.version \}\}\n\s+run: node scripts\/check-release-version-consistency\.mjs "\$RELEASE_VERSION"$/m,
  );
  assert.match(
    rustWorkflow,
    /^\s+RELEASE_VERSION: \$\{\{ steps\.version\.outputs\.version \}\}\n\s+run: node scripts\/check-release-version-consistency\.mjs "\$RELEASE_VERSION"$/m,
  );
  for (const workflow of [releaseWorkflow, rustWorkflow]) {
    const rustSetup = workflow.indexOf("uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4");
    const versionCheck = workflow.indexOf("run: node scripts/check-release-version-consistency.mjs");
    assert.ok(rustSetup >= 0 && rustSetup < versionCheck, "Rust must be set up before Cargo metadata validation");
  }
  const releaseScript = fs.readFileSync(
    path.join(sourceRoot, "scripts/release.sh"),
    "utf8",
  );
  assert.match(
    releaseWorkflow,
    /go -C tools\/releasenotes run \. \\[\r\n]+\s*--repo \.\.\/\.\./,
    "release workflow must run release notes from its Go module",
  );
  assert.doesNotMatch(
    releaseWorkflow,
    /go run \.\/tools\/releasenotes/,
    "release workflow must not assume a root Go module",
  );
  for (const required of [releaseScript, releaseWorkflow, rustWorkflow]) {
    assert.match(required, /check-release-version-consistency\.mjs/);
  }
  assert.match(policyScript, /check-release-version-consistency\.mjs/);
  assert.match(ciWorkflow, /^\s+run: scripts\/check-release-workflow-policy\.sh$/m);
  assert.match(ciWorkflow, /^\s+run: make precommit$/m);
  assert.match(ciWorkflow, /actions\/dependency-review-action@[0-9a-f]{40} # v5\.0\.0/);
});

test("default and final Go gates use the maintained source and test runner", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const goTest = makefile.match(/^go-test:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  assert.match(goTest, /\.\.\/scripts\/list-default-go-test-packages\.sh/);
  assert.doesNotMatch(goTest, /transport-test-runner|transportcheck/);
  assert.doesNotMatch(makefile, /tools\/transportcheck|transportcheck-diagnostic-contract|transport-v2-unit/);
  assert.match(makefile, /^test:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test run --suite acceptance$/m);
  assert.match(makefile, /^test-resume:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test resume --suite acceptance$/m);
  assert.match(makefile, /^browser-smoke:\n\tgo -C flowersec-go run \.\/internal\/cmd\/flowersec-test run --suite browser-smoke$/m);
  assert.match(makefile, /^diagnostic:\n\t\$\(FLOWERSEC_TEST_HOST\) run --suite diagnostic$/m);
  assert.match(
    makefile,
    /^performance:\n\t@test -n "\$\(REPORT\)" \|\| \{ echo "REPORT=\/absolute\/path\/performance-report\.md is required" >&2; exit 2; \}\n\t\$\(FLOWERSEC_TEST_HOST\) run --suite performance --report "\$\(REPORT\)" --budget "\$\(PERFORMANCE_BUDGET\)"$/m,
  );
});

test("release stays publication-only while main push owns fast acceptance", () => {
  const makefile = fs.readFileSync(path.join(sourceRoot, "Makefile"), "utf8");
  const releaseRecipe = makefile.match(/^release-check:\n((?:\t.*\n)+)/m)?.[1] ?? "";
  const releaseScript = fs.readFileSync(path.join(sourceRoot, "scripts/release.sh"), "utf8");
  const pushScript = fs.readFileSync(path.join(sourceRoot, "scripts/push-main.sh"), "utf8");
  const prePush = fs.readFileSync(path.join(sourceRoot, ".githooks/pre-push"), "utf8");

  assert.doesNotMatch(releaseRecipe, /\$\(MAKE\) check/);
  assert.match(releaseRecipe, /check-release-version-consistency\.mjs/);
  assert.doesNotMatch(releaseRecipe, /transport-v2|receipt|evidence|\$\(MAKE\)/);
  assert.doesNotMatch(releaseScript, /\bmake\b/);
  assert.doesNotMatch(
    releaseScript,
    /\b(?:go run|go test|npm|cargo|swift (?:build|test)|transport-v2-(?:release|signed|result))\b/,
  );
  assert.match(releaseScript, /go -C tools\/releasenotes run \. \\[\r\n]+\s*--repo \.\.\/\.\./);
  assert.doesNotMatch(releaseScript, /go run \.\/tools\/releasenotes/);
  assert.doesNotMatch(prePush, /make(?: -C \"\$repo_root\")? check/);
  assert.match(prePush, /use \.\/scripts\/push-main\.sh/);

  const gate = pushScript.indexOf("make test");
  const push = pushScript.indexOf("git push origin");
  assert.ok(gate >= 0 && gate < push, "fast acceptance must precede push");
  assert.doesNotMatch(pushScript, /make (?:precommit|check)/);
  assert.doesNotMatch(pushScript + releaseScript, /make performance|--suite performance|performance-report/);
  assert.doesNotMatch(pushScript, /evidence|receipt/);
});

test("release workflows pin actions and pass expressions through fields, not shell source", () => {
  const workflows = [
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/release.yml",
    ".github/workflows/rust-release.yml",
    ".github/workflows/scorecard.yml",
  ].map((file) => ({ file, source: fs.readFileSync(path.join(sourceRoot, file), "utf8") }));
  for (const { file, source } of workflows) {
    for (const match of source.matchAll(/^\s*uses:\s+(\S+)(?:\s+#\s*(\S+))?$/gm)) {
      if (match[1].startsWith("./")) continue;
      assert.match(match[1], /@[0-9a-f]{40}$/, `${file} must pin ${match[1]} to a commit`);
      assert.ok(match[2], `${file} must retain a readable version comment for ${match[1]}`);
    }
  }
  const ruby = [
    'require "psych"',
    'ARGV.each do |file|',
    '  workflow = Psych.safe_load(File.read(file), aliases: false)',
    '  workflow.fetch("jobs").each_value do |job|',
    '    Array(job["steps"]).each do |step|',
    '      abort("#{file}: #{step["name"] || step["uses"]} interpolates an expression into run") if step["run"]&.include?("${{")',
    '    end',
    '  end',
    'end',
  ].join("\n");
  const result = spawnSync("ruby", ["-W0", "-rpsych", "-e", ruby, ...workflows.map(({ file }) => file)], {
    cwd: sourceRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const dependabot = fs.readFileSync(path.join(sourceRoot, ".github/dependabot.yml"), "utf8");
  for (const [ecosystem, directory] of [
    ["github-actions", "/"],
    ["npm", "/flowersec-ts"],
    ["gomod", "/flowersec-go"],
    ["gomod", "/tools/releasenotes"],
    ["gomod", "/tools/stabilitycheck"],
    ["cargo", "/flowersec-rust"],
    ["cargo", "/flowersec-rust/fuzz"],
    ["cargo", "/examples/rust"],
    ["swift", "/"],
    ["swift", "/examples/swift"],
  ]) {
    const escapedDirectory = directory.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.match(
      dependabot,
      new RegExp(`  - package-ecosystem: ${ecosystem}\\n    directory: ${escapedDirectory}\\n    schedule:\\n      interval: weekly`),
    );
  }
  assert.doesNotMatch(dependabot, /open-pull-requests-limit:/);
  assert.match(
    dependabot,
    /^    groups:\n      codeql-action:\n        patterns:\n          - github\/codeql-action$/m,
  );
  assert.match(
    dependabot,
    /  - package-ecosystem: gomod\n    directory: \/flowersec-go\n    schedule:\n      interval: weekly\n    groups:\n      quic-stack:\n        patterns:\n          - github\.com\/quic-go\/quic-go\n          - github\.com\/quic-go\/webtransport-go/m,
  );
  assert.match(
    dependabot,
    /  - package-ecosystem: cargo\n    directory: \/flowersec-rust\n    schedule:\n      interval: weekly\n    ignore:\n      # Flowersec v2 freezes IDNA behavior to Unicode 15\.1; 1\.1\.0 moves to Unicode 16\.0\.\n      - dependency-name: idna_mapping\n        versions:\n          - ">= 1\.1\.0"/m,
  );
  assert.match(
    dependabot,
    /  - package-ecosystem: npm\n    directory: \/flowersec-ts\n    schedule:\n      interval: weekly\n    ignore:\n      # Flowersec v2 freezes IDNA behavior to Unicode 15\.1; tr46 6 uses newer data\.\n      - dependency-name: tr46\n        versions:\n          - ">= 6\.0\.0"/m,
  );
  assert.match(
    dependabot,
    /      # idna_adapter 1\.2 uses newer ICU data that accepts post-15\.1 code points\.\n      - dependency-name: idna_adapter\n        versions:\n          - ">= 1\.2\.0"/m,
  );
});

test("CodeQL policy structurally separates scheduled Swift analysis", () => {
  const result = spawnSync("ruby", ["-W0", "scripts/check-release-workflows.rb"], {
    cwd: sourceRoot,
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
});

test("push and release gates never depend on Swift CodeQL", () => {
  const releaseWorkflow = fs.readFileSync(path.join(sourceRoot, ".github/workflows/release.yml"), "utf8");
  const pushMain = fs.readFileSync(path.join(sourceRoot, "scripts/push-main.sh"), "utf8");
  const agentGuide = fs.readFileSync(path.join(sourceRoot, "AGENTS.md"), "utf8");

  assert.doesNotMatch(releaseWorkflow, /swift[^\n]*(?:codeql|analysis)|(?:codeql|analysis)[^\n]*swift/i);
  assert.doesNotMatch(pushMain, /codeql|swift/i);
  assert.match(agentGuide, /^- Swift CodeQL runs on the daily\/manual path only and never gates push or release\.$/m);
});

test("release workflow parser passes filenames compatibly across Psych versions", () => {
  const checker = fs.readFileSync(path.join(sourceRoot, "scripts/check-release-workflows.rb"), "utf8");
  assert.match(checker, /Psych\.parse_stream\(source, filename: path\)/);
  assert.doesNotMatch(checker, /Psych\.parse_stream\(source, path\)/);
});

test("Rust recovery rejects non-canonical versions before invoking git", (t) => {
  const ruby = [
    'require "psych"',
    'workflow = Psych.safe_load(File.read(ARGV.fetch(0)), aliases: false)',
    'step = workflow.fetch("jobs").fetch("publish").fetch("steps").find { |entry| entry["name"] == "Checkout release commit" }',
    'print step.fetch("run")',
  ].join("\n");
  const extracted = spawnSync("ruby", ["-W0", "-rpsych", "-e", ruby, ".github/workflows/rust-release.yml"], {
    cwd: sourceRoot,
    encoding: "utf8",
  });
  assert.equal(extracted.status, 0, `${extracted.stdout}${extracted.stderr}`);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-rust-release-input-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const gitLog = path.join(root, "git.log");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\nprintf '%s\\n' "$*" >> ${JSON.stringify(gitLog)}\nexit 99\n`);
  fs.chmodSync(path.join(bin, "git"), 0o755);

  for (const version of [
    "02.0.0",
    '2.0.0"; echo unexpected; #',
    "2.0.0$(echo unexpected)",
    "2.0.0;printf${IFS}unexpected",
  ]) {
    const output = path.join(root, `output-${Math.random()}`);
    const result = spawnSync("bash", ["-c", extracted.stdout], {
      cwd: sourceRoot,
      encoding: "utf8",
      env: isolatedEnvironment({
        GITHUB_OUTPUT: output,
        PATH: `${bin}:${process.env.PATH}`,
        RELEASE_VERSION_INPUT: version,
      }),
    });
    assert.equal(result.status, 2, `${result.stdout}${result.stderr}`);
  }
  assert.equal(fs.existsSync(gitLog), false, "invalid versions must fail before git");
});

test("release policy rejects disconnected or commented-out gates", { concurrency: releaseMutationConcurrency }, async (t) => {
  const policyMutations = [];
  const schedulePolicyTest = (name, fn) => {
    policyMutations.push(t.test(name, { concurrency: true }, fn));
  };
  schedulePolicyTest("current policy passes", () => {
    const root = createReleasePolicyFixture(t);
    const result = runReleasePolicy(root);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  });

  for (const bypass of [
    { name: "npm publication before the release gate", run: "npm publish" },
    { name: "GitHub release publication before the release gate", run: "gh release create bypass" },
  ]) {
    schedulePolicyTest(`rejects ${bypass.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const marker = "    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n";
      assert.ok(workflow.includes(marker));
      fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed command\n        run: ${bypass.run}\n\n`));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /step sequence|publication|unreviewed/i);
    });
  }

  schedulePolicyTest("rejects cargo publication before the Rust gate", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "  publish:\n    runs-on: ubuntu-latest\n    timeout-minutes: 120\n    permissions:\n      contents: read\n      id-token: write\n    steps:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed cargo publication\n        run: cargo publish\n\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /step sequence|publication|unreviewed/i);
  });

  schedulePolicyTest("rejects an unreviewed publication action", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "    permissions:\n      contents: write\n      packages: write\n      id-token: write\n    steps:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed publisher\n        uses: example/publish-action@v1\n\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /step sequence|publication|unreviewed/i);
  });

  for (const mutation of [
    { name: "workflow", file: ".github/workflows/bypass.yaml", contents: "name: bypass\non: push\njobs: {}\n" },
    {
      name: "job",
      file: ".github/workflows/release.yml",
      marker: "jobs:\n",
      replacement: "jobs:\n  bypass:\n    runs-on: ubuntu-latest\n    steps: []\n",
    },
    {
      name: "harmless-looking step",
      file: ".github/workflows/ci.yml",
      marker: "    steps:\n",
      replacement: "    steps:\n      - name: Unreviewed step\n        run: echo bypass\n\n",
    },
  ]) {
    schedulePolicyTest(`rejects an unreviewed ${mutation.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const target = path.join(root, mutation.file);
      if (mutation.contents) {
        fs.writeFileSync(target, mutation.contents);
      } else {
        const source = fs.readFileSync(target, "utf8");
        assert.ok(source.includes(mutation.marker));
        fs.writeFileSync(target, source.replace(mutation.marker, mutation.replacement));
      }
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /workflow|job|step sequence|unreviewed/i);
    });
  }

  for (const mutation of [
    {
      name: "manual recovery defaults to rebuilding",
      from: "        default: npm-only\n",
      to: "        default: full\n",
    },
    {
      name: "immutable release output is removed",
      from: "      release_exists: ${{ steps.release-state.outputs.exists }}\n",
      to: "",
    },
    {
      name: "native artifacts rebuild after release publication",
      from: "    if: needs.prepare.outputs.mode == 'full' && needs.prepare.outputs.release_complete == 'false'\n",
      to: "    if: needs.prepare.outputs.mode == 'full'\n",
    },
    {
      name: "partial release assets are not recoverably replaced",
      from: "          overwrite_files: true\n",
      to: "          overwrite_files: false\n",
    },
    {
      name: "release build date is wall-clock dependent",
      from: "          DATE=\"$(git show -s --format='%cI' HEAD)\"\n",
      to: "          DATE=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"\n",
    },
    {
      name: "npm recovery no longer waits for full release publication",
      from: "    needs: [prepare, release]\n",
      to: "    needs: prepare\n",
    },
    {
      name: "cosign installer version is mutable",
      from: "          cosign-release: v3.0.6\n",
      to: "          cosign-release: latest\n",
    },
    {
      name: "release signing accepts an arbitrary workflow ref",
      from: '          certificate_identity="https://github.com/${GITHUB_WORKFLOW_REF}"\n',
      to: '          certificate_identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/heads/unreviewed"\n',
    },
  ]) {
    schedulePolicyTest(`rejects unsafe immutable release mutation: ${mutation.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      assert.ok(workflow.includes(mutation.from), `missing mutation source: ${mutation.from}`);
      fs.writeFileSync(workflowPath, workflow.replace(mutation.from, mutation.to));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /reviewed|release|dependency|step sequence|fields/i);
    });
  }

  schedulePolicyTest("release validation rejects injected environment controls", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}          NODE_OPTIONS: --require ./bypass.cjs\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /environment|reviewed value|version facts/i);
  });

  for (const mutation of [
    "        shell: bash --noprofile --norc -c 'true; exit 0; #' {0}\n",
    "        working-directory: flowersec-ts\n",
  ]) {
    schedulePolicyTest(`release validation rejects semantic override ${mutation.trim()}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const marker = "      - name: Validate release version facts\n";
      assert.ok(workflow.includes(marker));
      fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}${mutation}`));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /fields|validation|version facts/i);
    });
  }

  for (const mutation of [
    ["working-directory: flowersec-rust", "working-directory: ."],
    ["CARGO_REGISTRY_TOKEN: ${{ steps.native-auth.outputs.token }}", "CARGO_REGISTRY_TOKEN: attacker-token"],
    ["timeout --kill-after=5s 600s cargo publish --locked", "timeout --kill-after=5s 600s cargo publish --allow-dirty"],
    ["uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18", "uses: example/auth-action@v1"],
    ["group: ${{ inputs.release_lock_held && format('flowersec-release-child-{0}', github.run_id) || 'flowersec-release' }}", "group: flowersec-rust-release"],
  ]) {
    schedulePolicyTest(`Rust publication rejects changed contract ${mutation[0]}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      assert.ok(workflow.includes(mutation[0]));
      fs.writeFileSync(workflowPath, workflow.replace(mutation[0], mutation[1]));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /Rust|crate|publish|action|token|directory/i);
    });
  }

  schedulePolicyTest("release tests disconnected from release-policy-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(makefilePath, makefile.replace("\t$(MAKE) release-test\n", ""));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-test/);
  });

  schedulePolicyTest("Dependabot action updates cannot be replaced by block-scalar decoys", () => {
    const root = createReleasePolicyFixture(t);
    const configPath = path.join(root, ".github/dependabot.yml");
    const config = fs.readFileSync(configPath, "utf8");
    fs.writeFileSync(configPath, `${config
      .replace("package-ecosystem: github-actions", "package-ecosystem: npm")
      .replace("interval: weekly", "interval: daily")}decoy: |2\n  - package-ecosystem: github-actions\n      interval: weekly\n`);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Dependabot|reviewed value|fields/i);
  });

  schedulePolicyTest("release version check disconnected from release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    const versionCheck = "\tnode scripts/check-release-version-consistency.mjs\n";
    assert.ok(makefile.includes(versionCheck));
    fs.writeFileSync(
      makefilePath,
      makefile.replace(versionCheck, ""),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-check|version/i);
  });

  schedulePolicyTest("complete tests cannot enter release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    const versionCheck = "\tnode scripts/check-release-version-consistency.mjs\n";
    assert.ok(makefile.includes(versionCheck));
    fs.writeFileSync(
      makefilePath,
      makefile.replace(
        versionCheck,
        `\t$(MAKE) check\n${versionCheck}`,
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-check|exact recipe|check/i);
  });

  schedulePolicyTest("commented unified workflow version check", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
        '        # run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  for (const mutation of [
    "        if: ${{ false }}\n",
    "        continue-on-error: true\n",
  ]) {
    schedulePolicyTest(`disabled unified workflow version check: ${mutation.trim()}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      fs.writeFileSync(
        workflowPath,
        workflow.replace(
          "      - name: Validate release version facts\n",
          `      - name: Validate release version facts\n${mutation}`,
        ),
      );
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /unified release workflow/);
    });
  }

  const equivalentControlKeyMutations = [
    "        if : ${{ false }}\n",
    "        \"if\": ${{ false }}\n",
    "        'if' : ${{ false }}\n",
    "        \"\\u0069f\": ${{ false }}\n",
    "        continue-on-error : true\n",
    "        \"continue-on-error\": true\n",
    "        \"continue-on-\\u0065rror\": true\n",
  ];
  for (const step of [
    { file: ".github/workflows/release.yml", name: "Validate release version facts" },
    { file: ".github/workflows/release.yml", name: "Publish GitHub Release" },
    { file: ".github/workflows/rust-release.yml", name: "Publish native transport crate" },
    { file: ".github/workflows/rust-release.yml", name: "Publish Flowersec Rust SDK" },
  ]) {
    for (const mutation of equivalentControlKeyMutations) {
      schedulePolicyTest(`${step.name} rejects equivalent YAML key ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, step.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        const marker = `      - name: ${step.name}\n`;
        assert.ok(workflow.includes(marker), `${step.file} is missing ${step.name}`);
        fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}${mutation}`));
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      });
    }
  }

  const criticalSteps = [
    { file: ".github/workflows/release.yml", name: "Build release artifacts" },
    { file: ".github/workflows/release.yml", name: "Generate release notes" },
    { file: ".github/workflows/release.yml", name: "Publish GitHub Release" },
    { file: ".github/workflows/release.yml", name: "Build and push runtime image by digest" },
    { file: ".github/workflows/release.yml", name: "Publish or recover npm registry packages from immutable release assets" },
    { file: ".github/workflows/rust-release.yml", name: "Check whether native transport version is already published" },
    { file: ".github/workflows/rust-release.yml", name: "Authenticate native transport publication" },
    { file: ".github/workflows/rust-release.yml", name: "Publish native transport crate" },
    { file: ".github/workflows/rust-release.yml", name: "Wait for native transport registry readback" },
    { file: ".github/workflows/rust-release.yml", name: "Check whether Flowersec Rust SDK version is already published" },
    { file: ".github/workflows/rust-release.yml", name: "Authenticate Flowersec Rust SDK publication" },
    { file: ".github/workflows/rust-release.yml", name: "Publish Flowersec Rust SDK" },
    { file: ".github/workflows/rust-release.yml", name: "Verify Flowersec Rust SDK registry readback" },
  ];
  for (const step of criticalSteps) {
    for (const mutation of [
      "        if: ${{ always() }}\n",
      "        continue-on-error: true\n",
    ]) {
      schedulePolicyTest(`${step.name} rejects ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, step.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        const marker = `      - name: ${step.name}\n`;
        assert.ok(workflow.includes(marker), `${step.file} is missing ${step.name}`);
        fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}${mutation}`));
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
        assert.match(result.stderr, /publication step|Rust publication step|duplicate YAML key|fields/);
      });
    }
  }

  schedulePolicyTest("unified workflow version failure is swallowed", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        'run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
        'run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION" || true',
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  schedulePolicyTest("indented fake targets cannot hide no-op real gates", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const replaceTarget = (source, target, replacement) => {
      const lines = source.split("\n");
      const start = lines.findIndex((line) => line.startsWith(`${target}:`));
      assert.ok(start >= 0, `missing Make target ${target}`);
      let end = start + 1;
      while (end < lines.length && (lines[end].startsWith("\t") || lines[end].trim() === "")) end += 1;
      lines.splice(start, end - start, ...replacement.split("\n"));
      return lines.join("\n");
    };
    let makefile = fs.readFileSync(makefilePath, "utf8");
    makefile = replaceTarget(makefile, "check", [
      "check :",
      "\t@:",
      "",
      "policy-decoy-check:",
      "\tcheck:",
      "\t$(MAKE) release-policy-check",
      "\t$(MAKE) transport-tool-contract",
      "\t$(MAKE) weaknet-smoke",
      "\t$(MAKE) quic-native-smoke",
    ].join("\n"));
    makefile = replaceTarget(makefile, "release-check", [
      "release-check :",
      "\t@:",
      "",
      "policy-decoy-release-check:",
      "\trelease-check:",
      "\t$(MAKE) check",
      "\t$(MAKE) interop-stress-full",
      "\t$(MAKE) transport-v2-result-check",
    ].join("\n"));
    fs.writeFileSync(makefilePath, makefile);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Makefile target (?:check|release-check)/);
  });

  schedulePolicyTest("Make definitions cannot hide no-op effective release gates", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    const replaceTarget = (source, target, replacement) => {
      const lines = source.split("\n");
      const start = lines.findIndex((line) => line.startsWith(`${target}:`));
      assert.ok(start >= 0, `missing Make target ${target}`);
      let end = start + 1;
      while (end < lines.length && (lines[end].startsWith("\t") || lines[end].trim() === "")) end += 1;
      lines.splice(start, end - start, ...replacement.split("\n"));
      return lines.join("\n");
    };
    let mutated = replaceTarget(makefile, "check", [
      "define policy_decoy_check",
      "check:",
      "\t$(MAKE) release-policy-check",
      "\t$(MAKE) transport-tool-contract",
      "\t$(MAKE) weaknet-smoke",
      "\t$(MAKE) quic-native-smoke",
      "endef",
      "check::",
      "\t@:",
    ].join("\n"));
    mutated = replaceTarget(mutated, "release-check", [
      "define policy_decoy_release_check",
      "release-check:",
      "\t$(MAKE) check",
      "\t$(MAKE) interop-stress-full",
      "\t$(MAKE) transport-v2-result-check",
      "endef",
      "release-check::",
      "\t@:",
    ].join("\n"));
    fs.writeFileSync(makefilePath, mutated);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /effective|Makefile target|release gate/i);
  });

  schedulePolicyTest("validation run must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
    ].join("\n");
    const replacement = [
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '          run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      "        run: echo bypassed",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /version facts|direct step field|unified release workflow/i);
  });

  schedulePolicyTest("Rust setup uses must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Setup Rust",
      "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable",
    ].join("\n");
    const replacement = [
      "      - name: Setup Rust",
      "        env:",
      "          uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4",
      "        run: echo bypassed",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Setup Rust|direct step field|set up Rust/i);
  });

  schedulePolicyTest("Rust publish condition must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Publish Flowersec Rust SDK",
      "        if: steps.sdk-published.outputs.exists != 'true'",
      "        working-directory: flowersec-rust",
      "        env:",
      "          CARGO_REGISTRY_TOKEN: ${{ steps.sdk-auth.outputs.token }}",
    ].join("\n");
    const replacement = [
      "      - name: Publish Flowersec Rust SDK",
      "        working-directory: flowersec-rust",
      "        env:",
      "          if: steps.sdk-published.outputs.exists != 'true'",
      "          CARGO_REGISTRY_TOKEN: ${{ steps.sdk-auth.outputs.token }}",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /approved condition|direct step field|Rust publication step|fields/i);
  });

  schedulePolicyTest("workflow aliases and merge keys are rejected", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "jobs:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(
      workflowPath,
      workflow.replace(marker, "guard: &guard\n  if: ${{ false }}\n\njobs:\n")
        .replace("  release:\n", "  release:\n    <<: *guard\n"),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /alias|anchor|merge|unconditional/i);
  });

  for (const implicitKey of ["yes", "true", "ON"]) {
    schedulePolicyTest(`implicit YAML scalar key ${implicitKey} cannot shadow the Actions on key`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const reviewedTrigger = [
        "on:",
        "  push:",
        "    tags:",
        "      - \"flowersec-go/v*\"",
      ].join("\n");
      assert.ok(workflow.includes(reviewedTrigger));
      fs.writeFileSync(workflowPath, workflow.replace(reviewedTrigger, [
        "on: {}",
        `${implicitKey}:`,
        "  push:",
        "    tags:",
        "      - \"flowersec-go/v*\"",
      ].join("\n")));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /implicit|mapping key|ambiguous|on key/i);
    });
  }

  for (const mutation of [
    ["sbom: true", "sbom: yes"],
    ["fetch-depth: 0", "fetch-depth: 00"],
    ["fetch-depth: 0", "fetch-depth: +0"],
  ]) {
    schedulePolicyTest(`non-canonical YAML scalar ${mutation[1]} is rejected`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      assert.ok(workflow.includes(mutation[0]));
      fs.writeFileSync(workflowPath, workflow.replace(mutation[0], mutation[1]));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /canonical|implicit|scalar|reviewed value/i);
    });
  }

  schedulePolicyTest("hosted CI invokes the full local release gate", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/ci.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    fs.writeFileSync(
      workflowPath,
      workflow.replace(
        "run: scripts/check-release-workflow-policy.sh",
        "run: make release-policy-check",
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /hosted CI/);
  });

  schedulePolicyTest("release validation steps moved into the prepare job", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const guardedSteps = [
      "      - name: Setup Rust",
      "        uses: dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4 # stable",
      "",
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(guardedSteps));
    fs.writeFileSync(
      workflowPath,
      workflow.replace(guardedSteps, "").replace(
        "\n  rust-publish:",
        `\n${guardedSteps}\n  rust-publish:`,
      ),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /unified release workflow/);
  });

  schedulePolicyTest("release version validation moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const validationStep = [
      "      - name: Validate release version facts",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: node scripts/check-release-version-consistency.mjs "$RELEASE_VERSION"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(validationStep));
    fs.writeFileSync(
      workflowPath,
      `${workflow.replace(validationStep, "")}\n${validationStep}`,
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /in order|before every publication step|step sequence/);
  });

  schedulePolicyTest("release tag verification moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const verificationStep = [
      "      - name: Verify all language tags point to this commit",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      "          RELEASE_SHA: ${{ steps.vars.outputs.sha }}",
      '        run: scripts/verify-release-tags.sh "$RELEASE_VERSION" "$RELEASE_SHA"',
      "",
    ].join("\n");
    assert.ok(workflow.includes(verificationStep));
    fs.writeFileSync(
      workflowPath,
      `${workflow.replace(verificationStep, "")}\n${verificationStep}`,
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /before every publication step|step sequence/);
  });

  for (const tt of [
    { file: ".github/workflows/release.yml", job: "release", expected: /duplicate YAML key|fields/ },
    { file: ".github/workflows/release.yml", job: "rust-publish", expected: /duplicate YAML key|fields/ },
    { file: ".github/workflows/rust-release.yml", job: "publish", expected: /must remain unconditional|fields/ },
  ]) {
    for (const mutation of [
      "    if: ${{ false }}\n",
      "    if : ${{ false }}\n",
      "    \"if\": ${{ false }}\n",
      "    'if' : ${{ false }}\n",
      "    \"\\x69f\": ${{ false }}\n",
      "    \"\\u0069f\": ${{ false }}\n",
    ]) {
      schedulePolicyTest(`${tt.job} job rejects ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, tt.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        fs.writeFileSync(
          workflowPath,
          workflow.replace(`  ${tt.job}:\n`, `  ${tt.job}:\n${mutation}`),
        );
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
        assert.match(result.stderr, tt.expected);
      });
    }
  }

  for (const mutation of [
    {
      name: "Swift returns to the push and pull request matrix",
      from: "          - language: rust\n            build-mode: none\n            runner: ubuntu-latest\n",
      to: "          - language: rust\n            build-mode: none\n            runner: ubuntu-latest\n          - language: swift\n            build-mode: manual\n            runner: macos-26\n",
      expected: /CodeQL matrix/,
    },
    {
      name: "Swift permits push events",
      from: "    if: github.event_name == 'workflow_dispatch' || (github.event_name == 'schedule' && needs.plan.outputs.should_scan == 'true')\n",
      to: "    if: github.event_name != 'pull_request'\n",
      expected: /Swift analyze job.*approved condition/i,
    },
    {
      name: "Swift loses its manual recovery path",
      from: "    if: github.event_name == 'workflow_dispatch' || (github.event_name == 'schedule' && needs.plan.outputs.should_scan == 'true')\n",
      to: "    if: github.event_name == 'schedule' && needs.plan.outputs.should_scan == 'true'\n",
      expected: /Swift analyze job.*approved condition/i,
    },
    {
      name: "daily CodeQL scheduling is removed",
      from: "  schedule:\n    - cron: \"17 3 * * *\"\n",
      to: "",
      expected: /CodeQL triggers/,
    },
    {
      name: "same-SHA schedules no longer skip Swift",
      from: "            echo \"should_scan=false\" >> \"$GITHUB_OUTPUT\"\n",
      to: "            echo \"should_scan=true\" >> \"$GITHUB_OUTPUT\"\n",
      expected: /CodeQL plan job.*reviewed command/i,
    },
    {
      name: "scheduled API failure no longer scans fail-safe",
      from: "            echo \"::warning::Could not inspect previous CodeQL runs; scanning fail-safe.\"\n            echo \"should_scan=true\" >> \"$GITHUB_OUTPUT\"\n            exit 0\n          fi\n",
      to: "            echo \"::warning::Could not inspect previous CodeQL runs; scanning fail-safe.\"\n            echo \"should_scan=false\" >> \"$GITHUB_OUTPUT\"\n            exit 0\n          fi\n",
      expected: /CodeQL plan job.*reviewed command/i,
    },
    {
      name: "scheduled API requests lose their bounded timeout",
      from: "            --connect-timeout 5 --max-time 20 \\\n",
      to: "",
      expected: /CodeQL plan job.*reviewed command/i,
    },
    {
      name: "scheduled API response parsing no longer scans fail-safe",
      from: "            echo \"::warning::Could not parse previous CodeQL runs; scanning fail-safe.\"\n            echo \"should_scan=true\" >> \"$GITHUB_OUTPUT\"\n            exit 0\n          fi\n",
      to: "            echo \"::warning::Could not parse previous CodeQL runs; scanning fail-safe.\"\n            echo \"should_scan=false\" >> \"$GITHUB_OUTPUT\"\n            exit 0\n          fi\n",
      expected: /CodeQL plan job.*reviewed command/i,
    },
  ]) {
    schedulePolicyTest(`rejects CodeQL policy mutation: ${mutation.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/codeql.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      assert.ok(workflow.includes(mutation.from), `missing CodeQL policy marker for ${mutation.name}`);
      fs.writeFileSync(workflowPath, workflow.replace(mutation.from, mutation.to));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, mutation.expected);
    });
  }
  await Promise.all(policyMutations);
});

test("release validates maintained versions before publication", (t) => {
  const fixture = createReleaseScriptFixture(t);
  fs.writeFileSync(
    path.join(fixture.repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.25.0" }),
  );
  runGit(["-C", fixture.repo, "add", "flowersec-ts/package.json"]);
  runGit(["-C", fixture.repo, "commit", "-m", "test: stale release version"]);
  runGit(["-C", fixture.repo, "push", "origin", "main"]);

  const result = runReleaseScript(fixture);
  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release versions are inconsistent/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release removes all local tags when tag creation fails partway", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_TAG: "0.26.0" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.ok(commands.includes("tag flowersec-go/v0.26.0 " + runGit(["-C", fixture.repo, "rev-parse", "HEAD"])), commands.join("\n"));
  assert.equal(commands.some((command) => command.startsWith("push ")), false, commands.join("\n"));
});

test("release removes all local tags when atomic push fails", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_PUSH: "1" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.ok(commands.some((command) => command.startsWith("push --atomic origin ")), commands.join("\n"));
});

test("release notes preflight rejects generator failure and removes local tags", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_NOTES: "1" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release notes preflight failed/);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.equal(commands.some((command) => command.startsWith("push ")), false, commands.join("\n"));
  assert.match(fs.readFileSync(fixture.goLog, "utf8"), /-C tools\/releasenotes run \. --repo \.\.\/\./);
});

test("release can retry after an atomic push failure without moving tags", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const failed = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_PUSH: "1" });
  assert.notEqual(failed.status, 0, `${failed.stdout}${failed.stderr}`);
  assertNoReleaseTags(fixture);

  const retried = runReleaseScript(fixture);
  assert.equal(retried.status, 0, `${retried.stdout}${retried.stderr}`);
  assert.deepEqual(runGit(["--git-dir", fixture.origin, "tag", "--list"]).split("\n"), [
    "0.26.0",
    "flowersec-go/v0.26.0",
    "flowersec-rust/v0.26.0",
  ]);
});

test("release publishes main and all ecosystem tags atomically", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture);

  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const expectedTags = ["0.26.0", "flowersec-go/v0.26.0", "flowersec-rust/v0.26.0"];
  assert.deepEqual(runGit(["-C", fixture.repo, "tag", "--list"]).split("\n"), expectedTags);
  assert.deepEqual(runGit(["--git-dir", fixture.origin, "tag", "--list"]).split("\n"), expectedTags);
  assert.equal(
    runGit(["-C", fixture.repo, "rev-parse", "HEAD"]),
    runGit(["--git-dir", fixture.origin, "rev-parse", "refs/heads/main"]),
  );
  const commands = gitCommands(fixture);
  assert.ok(commands.some((command) => command.startsWith("push --atomic origin ")), commands.join("\n"));
});

test("pre-push accepts only the complete release tag set for the synchronized commit", async (t) => {
  const hook = path.join(sourceRoot, ".githooks/pre-push");
  const verified = "1".repeat(40);
  const other = "2".repeat(40);
  const deleted = "0".repeat(40);
  const tagLine = (ref, sha = verified) => `${ref} ${sha} ${ref} ${deleted}`;
  const allTags = [
    tagLine("refs/tags/flowersec-go/v0.26.0"),
    tagLine("refs/tags/0.26.0"),
    tagLine("refs/tags/flowersec-rust/v0.26.0"),
  ];
  const releaseEnv = {
    ...process.env,
    FLOWERSEC_RELEASE_PUSH_SHA: verified,
    FLOWERSEC_RELEASE_VERSION: "0.26.0",
  };
  const cases = [
    {
      name: "missing release entrypoint marker",
      lines: allTags,
      env: process.env,
      status: 1,
      error: /must be pushed with scripts\/release\.sh/,
    },
    {
      name: "missing one ecosystem tag",
      lines: allTags.slice(0, 2),
      env: releaseEnv,
      status: 1,
      error: /must be pushed together/,
    },
    {
      name: "tag points to another commit",
      lines: [...allTags.slice(0, 2), tagLine("refs/tags/flowersec-rust/v0.26.0", other)],
      env: releaseEnv,
      status: 1,
      error: /must point to the synchronized release commit/,
    },
    {
      name: "complete synchronized release",
      lines: allTags,
      env: releaseEnv,
      status: 0,
    },
  ];

  for (const tt of cases) {
    await t.test(tt.name, () => {
      const result = spawnSync("sh", [hook], {
        encoding: "utf8",
        env: isolatedEnvironment(tt.env),
        input: `${tt.lines.join("\n")}\n`,
      });
      assert.equal(result.status, tt.status, `${result.stdout}${result.stderr}`);
      if (tt.error) {
        assert.match(result.stderr, tt.error);
      }
    });
  }
});

test("pre-push permits push-main and rejects direct main pushes without running tests", (t) => {
  const marker = path.join(os.tmpdir(), `flowersec-pre-push-make-${process.pid}-${Date.now()}`);
  t.after(() => fs.rmSync(marker, { force: true }));
  const fixture = createReleaseScriptFixture(
    t,
    `#!/bin/sh\nprintf invoked > ${JSON.stringify(marker)}\nexit 99\n`,
  );
  const hook = path.join(fixture.repo, ".githooks/pre-push");
  const head = runGit(["-C", fixture.repo, "rev-parse", "HEAD"]);
  const input = `refs/heads/main ${head} refs/heads/main ${head}\n`;
  const env = isolatedEnvironment({
    FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
    FLOWERSEC_TEST_REAL_GIT: fixture.realGit,
    PATH: `${fixture.bin}${path.delimiter}${process.env.PATH}`,
    FLOWERSEC_PUSH_MAIN_SHA: head,
  });

  const verified = spawnSync("sh", [hook], {
    cwd: fixture.repo,
    encoding: "utf8",
    env,
    input,
  });
  assert.equal(verified.status, 0, `${verified.stdout}${verified.stderr}`);
  assert.equal(fs.existsSync(marker), false, "pre-push must not invoke make");

  const direct = spawnSync("sh", [hook], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: isolatedEnvironment({
      FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
      FLOWERSEC_TEST_REAL_GIT: fixture.realGit,
      PATH: `${fixture.bin}${path.delimiter}${process.env.PATH}`,
    }),
    input,
  });
  assert.notEqual(direct.status, 0, `${direct.stdout}${direct.stderr}`);
  assert.match(direct.stderr, /use \.\/scripts\/push-main\.sh/);
  assert.equal(fs.existsSync(marker), false, "direct push rejection must not invoke make");
});

test("main push gates the exact SHA with fast acceptance before opening the remote transport", () => {
  const script = path.join(sourceRoot, "scripts/push-main.sh");
  assert.equal(fs.existsSync(script), true, "scripts/push-main.sh is missing");
  const source = fs.readFileSync(script, "utf8");
  const gate = source.indexOf("make test");
  const push = source.indexOf("git push origin");
  assert.notEqual(gate, -1, "main push must run fast acceptance");
  assert.notEqual(push, -1, "main push must use normal git push");
  assert.ok(gate < push, "the gate must finish before git opens the push transport");
  assert.match(source, /FLOWERSEC_PUSH_MAIN_SHA="\$head" git push/);
  assert.doesNotMatch(source, /make (?:precommit|check)/);
  assert.doesNotMatch(source, /receipt|TRANSPORT_V2_EVIDENCE/);
  assert.doesNotMatch(source, /--no-verify/);
});

test("main push passes only the checked HEAD after the gate completes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-main-push-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, "bin");
  const log = path.join(root, "commands.log");
  const head = "a".repeat(40);
  const origin = "b".repeat(40);
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, "git"),
    [
      "#!/bin/sh",
      "printf 'git %s\\n' \"$*\" >> \"$FLOWERSEC_TEST_COMMAND_LOG\"",
      "case \"$*\" in",
      "  'status --short') exit 0 ;;",
      "  'symbolic-ref --short -q HEAD') printf 'main\\n' ; exit 0 ;;",
      `  'rev-parse HEAD') printf '${head}\\n' ; exit 0 ;;`,
      `  'rev-parse origin/main') printf '${origin}\\n' ; exit 0 ;;`,
      "  'fetch origin main') exit 0 ;;",
      "  'merge-base --is-ancestor '*) exit 0 ;;",
      `  'push origin refs/heads/main:refs/heads/main') [ "${"$"}{FLOWERSEC_PUSH_MAIN_SHA:-}" = '${head}' ] ; exit ;;`,
      "esac",
      "exit 90",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(bin, "make"),
    "#!/bin/sh\nprintf 'make %s\\n' \"$*\" >> \"$FLOWERSEC_TEST_COMMAND_LOG\"\n",
    { mode: 0o755 },
  );
  const result = spawnSync("bash", [path.join(sourceRoot, "scripts/push-main.sh")], {
    cwd: sourceRoot,
    encoding: "utf8",
    env: isolatedEnvironment({
      ...process.env,
      FLOWERSEC_TEST_COMMAND_LOG: log,
      PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    }),
  });
  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const commands = fs.readFileSync(log, "utf8").trim().split("\n");
  const gate = commands.indexOf("make test");
  const push = commands.findIndex((command) => command.startsWith("git push origin "));
  assert.ok(gate >= 0 && push > gate, commands.join("\n"));
  assert.equal(commands.filter((command) => command === "make test").length, 1, commands.join("\n"));
});

test("browser compatibility remains explicit and separate from Chromium smoke", () => {
  const registry = fs.readFileSync(path.join(sourceRoot, "flowersec-go/internal/cmd/flowersec-test/registry.go"), "utf8");
  assert.match(registry, /browserCompatibilityEntry\("compat\/v2\/browser\/firefox\/webtransport-capability"/);
  assert.match(registry, /browserCompatibilityEntry\("compat\/v2\/browser\/webkit\/webtransport-capability"/);
  assert.doesNotMatch(registry, /"diagnostic\/browser"/);
  const packageManifest = fs.readFileSync(path.join(sourceRoot, "flowersec-ts/package.json"), "utf8");
  assert.match(packageManifest, /"test:browser": "npm run test:browser:chromium"/);
  assert.match(packageManifest, /"test:browser:chromium": "npm run ensure:browser && npm run build && playwright test --project=chromium"/);
  assert.match(packageManifest, /"test:browser:firefox": "npm run ensure:browser:firefox && npm run build && playwright test --project=firefox-compat"/);
  assert.match(packageManifest, /"test:browser:webkit": "npm run ensure:browser:webkit && npm run build && playwright test --project=webkit-smoke"/);
});
