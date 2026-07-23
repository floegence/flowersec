import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const sourceRoot = path.resolve(import.meta.dirname, "..");
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

function run(command, args, options = {}) {
  const { env, ...spawnOptions } = options;
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...spawnOptions,
    env: isolatedEnvironment(env),
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`,
    );
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
  const realGit = run("sh", ["-c", "command -v git"]);
  const realMake = run("sh", ["-c", "command -v make"]);
  fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-ts"), { recursive: true });
  fs.mkdirSync(path.join(repo, "flowersec-rust/fuzz"), { recursive: true });
  fs.mkdirSync(path.join(repo, "examples/rust"), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });

  for (const script of ["release.sh", "check-release-version-consistency.mjs"]) {
    fs.copyFileSync(path.join(sourceRoot, "scripts", script), path.join(repo, "scripts", script));
  }
  fs.chmodSync(path.join(repo, "scripts/release.sh"), 0o755);
  fs.cpSync(
    path.join(sourceRoot, "tools/releasenotes"),
    path.join(repo, "tools/releasenotes"),
    {
      recursive: true,
      filter(source) {
        return !source.endsWith("_test.go");
      },
    },
  );
  fs.writeFileSync(
    path.join(repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.26.0" }),
  );
  fs.writeFileSync(
    path.join(repo, "flowersec-ts/package-lock.json"),
    JSON.stringify({ version: "0.26.0", packages: { "": { version: "0.26.0" } } }),
  );
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

  run("git", ["init", "--bare", origin]);
  run("git", ["init", "-b", "main", repo]);
  run("git", ["-C", repo, "config", "user.name", "Release Test"]);
  run("git", ["-C", repo, "config", "user.email", "release-test@example.com"]);
  run("git", ["-C", repo, "add", "."]);
  run("git", ["-C", repo, "commit", "-m", "test: release fixture"]);
  run("git", ["-C", repo, "remote", "add", "origin", origin]);
  run("git", ["-C", repo, "push", "-u", "origin", "main"]);

  return { bin, gitLog, origin, realGit, realMake, repo };
}

function runReleaseScript(fixture, env = {}) {
  return spawnSync("bash", ["scripts/release.sh", "0.26.0"], {
    cwd: fixture.repo,
    encoding: "utf8",
    env: isolatedEnvironment({
      FLOWERSEC_TEST_GIT_LOG: fixture.gitLog,
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
  assert.equal(run("git", ["-C", fixture.repo, "tag", "--list"]), "");
  assert.equal(run("git", ["--git-dir", fixture.origin, "tag", "--list"]), "");
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
  const files = [
    "Makefile",
    ".github/dependabot.yml",
    ".githooks/pre-push",
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/rust-release.yml",
    "docker/flowersec-runtime/Dockerfile",
    "scripts/check-release-version-consistency.mjs",
    "scripts/check-release-version-consistency.test.mjs",
    "scripts/check-container-release-policy.mjs",
    "scripts/check-release-workflows.rb",
    "scripts/check-release-workflow-policy.sh",
    "scripts/check-security-makefile.mjs",
    "scripts/check-transport-v2-evidence.sh",
    "scripts/release.sh",
    "scripts/release.test.mjs",
  ];
  for (const file of files) {
    const destination = path.join(root, file);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(sourceRoot, file), destination);
  }
  return root;
}

function runReleasePolicy(root) {
  return spawnSync("bash", ["scripts/check-release-workflow-policy.sh"], {
    cwd: root,
    encoding: "utf8",
    env: isolatedEnvironment(),
  });
}

test("release fixtures cannot modify an inherited hook repository", (t) => {
  const sentinel = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-sentinel-"));
  t.after(() => fs.rmSync(sentinel, { recursive: true, force: true }));
  run("git", ["init", "-b", "main", sentinel]);
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
    assert.equal(run("git", ["-C", fixture.repo, "status", "--short"]), "");
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
    /^check: security-makefile-check security-dependency-check\n\t\$\(MAKE\) release-policy-check$/m,
  );
  for (const target of ["transport-v2-unit", "weaknet-smoke", "quic-native-smoke"]) {
    assert.match(
      makefile,
      new RegExp(
        `^check: security-makefile-check security-dependency-check\\n(?:\\t.*\\n)*\\t\\$\\(MAKE\\) ${target}$`,
        "m",
      ),
    );
  }
  for (const target of ["transport-v2-release-evidence", "transport-v2-signed-evidence-check"]) {
    assert.match(makefile, new RegExp(`^release-check:\\n(?:\\t.*\\n)*\\t\\$\\(MAKE\\) ${target}$`, "m"));
  }
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
  for (const required of [releaseScript, releaseWorkflow, rustWorkflow]) {
    assert.match(required, /check-release-version-consistency\.mjs/);
  }
  assert.match(policyScript, /check-release-version-consistency\.mjs/);
  assert.match(ciWorkflow, /^\s+run: scripts\/check-release-workflow-policy\.sh$/m);
});

test("release workflows pin actions and pass expressions through fields, not shell source", () => {
  const workflows = [
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/rust-release.yml",
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
  assert.match(dependabot, /^\s+- package-ecosystem: github-actions$/m);
  assert.match(dependabot, /^\s+interval: weekly$/m);
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

test("release policy rejects disconnected or commented-out gates", async (t) => {
  await t.test("current policy passes", () => {
    const root = createReleasePolicyFixture(t);
    const result = runReleasePolicy(root);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  });

  for (const bypass of [
    { name: "npm publication before the release gate", run: "npm publish" },
    { name: "GitHub release publication before the release gate", run: "gh release create bypass" },
  ]) {
    await t.test(`rejects ${bypass.name}`, () => {
      const root = createReleasePolicyFixture(t);
      const workflowPath = path.join(root, ".github/workflows/release.yml");
      const workflow = fs.readFileSync(workflowPath, "utf8");
      const marker = "  release:\n    needs: prepare\n    runs-on: ubuntu-latest\n    steps:\n";
      assert.ok(workflow.includes(marker));
      fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed command\n        run: ${bypass.run}\n\n`));
      const result = runReleasePolicy(root);
      assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
      assert.match(result.stderr, /step sequence|publication|unreviewed/i);
    });
  }

  await t.test("rejects cargo publication before the Rust gate", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "  publish:\n    runs-on: ubuntu-latest\n    steps:\n";
    assert.ok(workflow.includes(marker));
    fs.writeFileSync(workflowPath, workflow.replace(marker, `${marker}      - name: Unreviewed cargo publication\n        run: cargo publish\n\n`));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /step sequence|publication|unreviewed/i);
  });

  await t.test("rejects an unreviewed publication action", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const marker = "  release:\n    needs: prepare\n    runs-on: ubuntu-latest\n    steps:\n";
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
    await t.test(`rejects an unreviewed ${mutation.name}`, () => {
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

  await t.test("release validation rejects injected environment controls", () => {
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
    await t.test(`release validation rejects semantic override ${mutation.trim()}`, () => {
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
    ["CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}", "CARGO_REGISTRY_TOKEN: attacker-token"],
    ["run: cargo publish --no-verify", "run: cargo publish --allow-dirty"],
    ["uses: rust-lang/crates-io-auth-action@c6f97d42243bad5fab37ca0427f495c86d5b1a18", "uses: example/auth-action@v1"],
  ]) {
    await t.test(`Rust publication rejects changed contract ${mutation[0]}`, () => {
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

  await t.test("release tests disconnected from release-policy-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(makefilePath, makefile.replace("\t$(MAKE) release-test\n", ""));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /release-test/);
  });

  await t.test("Dependabot action updates cannot be replaced by block-scalar decoys", () => {
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

  await t.test("signed Transport v2 evidence disconnected from release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(
      makefilePath,
      makefile.replace("\t$(MAKE) transport-v2-signed-evidence-check\n", ""),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /transport-v2-signed-evidence-check/);
  });

  await t.test("Transport v2 evidence generation disconnected from release-check", () => {
    const root = createReleasePolicyFixture(t);
    const makefilePath = path.join(root, "Makefile");
    const makefile = fs.readFileSync(makefilePath, "utf8");
    fs.writeFileSync(
      makefilePath,
      makefile.replace("\t$(MAKE) transport-v2-release-evidence\n", ""),
    );
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /transport-v2-release-evidence/);
  });

  await t.test("commented unified workflow version check", () => {
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
    await t.test(`disabled unified workflow version check: ${mutation.trim()}`, () => {
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
    { file: ".github/workflows/rust-release.yml", name: "Publish crate" },
  ]) {
    for (const mutation of equivalentControlKeyMutations) {
      await t.test(`${step.name} rejects equivalent YAML key ${mutation.trim()}`, () => {
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
    { file: ".github/workflows/release.yml", name: "Build and push runtime image" },
    { file: ".github/workflows/release.yml", name: "Publish npm package" },
    { file: ".github/workflows/rust-release.yml", name: "Check whether version is already published" },
    { file: ".github/workflows/rust-release.yml", name: "Authenticate to crates.io" },
    { file: ".github/workflows/rust-release.yml", name: "Publish crate" },
  ];
  for (const step of criticalSteps) {
    for (const mutation of [
      "        if: ${{ always() }}\n",
      "        continue-on-error: true\n",
    ]) {
      await t.test(`${step.name} rejects ${mutation.trim()}`, () => {
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

  await t.test("unified workflow version failure is swallowed", () => {
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

  await t.test("indented fake targets cannot hide no-op real gates", () => {
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
      "\t$(MAKE) transport-v2-unit",
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
      "\t$(MAKE) transport-v2-release-evidence",
      "\t$(MAKE) transport-v2-signed-evidence-check",
    ].join("\n"));
    fs.writeFileSync(makefilePath, makefile);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /Makefile target (?:check|release-check)/);
  });

  await t.test("Make definitions cannot hide no-op effective release gates", () => {
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
      "\t$(MAKE) transport-v2-unit",
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
      "\t$(MAKE) transport-v2-release-evidence",
      "\t$(MAKE) transport-v2-signed-evidence-check",
      "endef",
      "release-check::",
      "\t@:",
    ].join("\n"));
    fs.writeFileSync(makefilePath, mutated);
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /effective|Makefile target|release gate/i);
  });

  await t.test("validation run must be a direct step field", () => {
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

  await t.test("Rust setup uses must be a direct step field", () => {
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

  await t.test("Rust publish condition must be a direct step field", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/rust-release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const expected = [
      "      - name: Publish crate",
      "        if: steps.published.outputs.exists != 'true'",
      "        working-directory: flowersec-rust",
      "        env:",
      "          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}",
    ].join("\n");
    const replacement = [
      "      - name: Publish crate",
      "        working-directory: flowersec-rust",
      "        env:",
      "          if: steps.published.outputs.exists != 'true'",
      "          CARGO_REGISTRY_TOKEN: ${{ steps.auth.outputs.token }}",
    ].join("\n");
    assert.ok(workflow.includes(expected));
    fs.writeFileSync(workflowPath, workflow.replace(expected, replacement));
    const result = runReleasePolicy(root);
    assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(result.stderr, /approved condition|direct step field|Rust publication step|fields/i);
  });

  await t.test("workflow aliases and merge keys are rejected", () => {
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
    await t.test(`implicit YAML scalar key ${implicitKey} cannot shadow the Actions on key`, () => {
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
    ["push: true", "push: yes"],
    ["fetch-depth: 0", "fetch-depth: 00"],
    ["fetch-depth: 0", "fetch-depth: +0"],
  ]) {
    await t.test(`non-canonical YAML scalar ${mutation[1]} is rejected`, () => {
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

  await t.test("hosted CI invokes the full local release gate", () => {
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

  await t.test("release validation steps moved into the prepare job", () => {
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

  await t.test("release version validation moved after publication", () => {
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

  await t.test("release tag verification moved after publication", () => {
    const root = createReleasePolicyFixture(t);
    const workflowPath = path.join(root, ".github/workflows/release.yml");
    const workflow = fs.readFileSync(workflowPath, "utf8");
    const verificationStep = [
      "      - name: Verify all language tags point to this commit",
      "        env:",
      "          RELEASE_VERSION: ${{ steps.vars.outputs.version }}",
      '        run: scripts/verify-release-tags.sh "$RELEASE_VERSION" "$GITHUB_SHA"',
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
    { file: ".github/workflows/release.yml", job: "release" },
    { file: ".github/workflows/release.yml", job: "rust-publish" },
    { file: ".github/workflows/rust-release.yml", job: "publish" },
  ]) {
    for (const mutation of [
      "    if: ${{ false }}\n",
      "    if : ${{ false }}\n",
      "    \"if\": ${{ false }}\n",
      "    'if' : ${{ false }}\n",
      "    \"\\x69f\": ${{ false }}\n",
      "    \"\\u0069f\": ${{ false }}\n",
    ]) {
      await t.test(`${tt.job} job rejects ${mutation.trim()}`, () => {
        const root = createReleasePolicyFixture(t);
        const workflowPath = path.join(root, tt.file);
        const workflow = fs.readFileSync(workflowPath, "utf8");
        fs.writeFileSync(
          workflowPath,
          workflow.replace(`  ${tt.job}:\n`, `  ${tt.job}:\n${mutation}`),
        );
        const result = runReleasePolicy(root);
        assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
        assert.match(result.stderr, /must remain unconditional|fields/);
      });
    }
  }
});

test("release validates maintained versions before publication", (t) => {
  const fixture = createReleaseScriptFixture(t);
  fs.writeFileSync(
    path.join(fixture.repo, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.25.0" }),
  );
  run("git", ["-C", fixture.repo, "add", "flowersec-ts/package.json"]);
  run("git", ["-C", fixture.repo, "commit", "-m", "test: stale release version"]);
  run("git", ["-C", fixture.repo, "push", "origin", "main"]);

  const result = runReleaseScript(fixture);
  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release versions are inconsistent/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release stops before git tag or push when release-check dirties the worktree", (t) => {
  const fixture = createReleaseScriptFixture(
    t,
    "#!/bin/sh\nprintf '%s\\n' dirty >> tracked.txt\n",
  );
  const result = runReleaseScript(fixture);

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release-check modified the worktree/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release stops before git tag or push when release-check changes HEAD", (t) => {
  const fixture = createReleaseScriptFixture(
    t,
    "#!/bin/sh\nprintf '%s\\n' generated > release-generated.txt\ngit add release-generated.txt\ngit commit -m 'test: release-check commit' >/dev/null\n",
  );
  const result = runReleaseScript(fixture);

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /release-check changed HEAD/);
  assertReleaseDidNotStartPublication(fixture);
});

test("release make gate ignores hostile inherited make control variables", (t) => {
  const fixture = createReleaseScriptFixture(t);
  fs.writeFileSync(
    path.join(fixture.repo, "Makefile"),
    ".PHONY: release-check fail\nrelease-check:\n\t$(MAKE) fail\nfail:\n\t@false\n",
  );
  fs.writeFileSync(path.join(fixture.repo, "attacker.mk"), "SHELL := /usr/bin/true\n");
  fs.writeFileSync(
    path.join(fixture.bin, "make"),
    `#!/bin/sh\nexec ${JSON.stringify(fixture.realMake)} \"$@\"\n`,
  );
  fs.chmodSync(path.join(fixture.bin, "make"), 0o755);
  run("git", ["-C", fixture.repo, "add", "Makefile", "attacker.mk"]);
  run("git", ["-C", fixture.repo, "commit", "-m", "test: add failing release gate"]);
  run("git", ["-C", fixture.repo, "push", "origin", "main"]);

  const result = runReleaseScript(fixture, {
    MAKE: "true",
    MAKE_COMMAND: "true",
    MAKEFILES: "attacker.mk",
    MAKEFLAGS: "-i",
    GNUMAKEFLAGS: "-i",
  });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertReleaseDidNotStartPublication(fixture);
});

test("release removes all local tags when tag creation fails partway", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture, { FLOWERSEC_TEST_FAIL_TAG: "0.26.0" });

  assert.notEqual(result.status, 0, `${result.stdout}${result.stderr}`);
  assertNoReleaseTags(fixture);
  const commands = gitCommands(fixture);
  assert.ok(commands.includes("tag flowersec-go/v0.26.0 " + run("git", ["-C", fixture.repo, "rev-parse", "HEAD"])), commands.join("\n"));
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

test("release publishes main and all ecosystem tags atomically", (t) => {
  const fixture = createReleaseScriptFixture(t);
  const result = runReleaseScript(fixture);

  assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
  const expectedTags = ["0.26.0", "flowersec-go/v0.26.0", "flowersec-rust/v0.26.0"];
  assert.deepEqual(run("git", ["-C", fixture.repo, "tag", "--list"]).split("\n"), expectedTags);
  assert.deepEqual(run("git", ["--git-dir", fixture.origin, "tag", "--list"]).split("\n"), expectedTags);
  assert.equal(
    run("git", ["-C", fixture.repo, "rev-parse", "HEAD"]),
    run("git", ["--git-dir", fixture.origin, "rev-parse", "refs/heads/main"]),
  );
  const commands = gitCommands(fixture);
  assert.ok(commands.some((command) => command.startsWith("push --atomic origin ")), commands.join("\n"));
});

test("pre-push accepts only the complete release tag set for the gated commit", async (t) => {
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
  const gatedEnv = {
    ...process.env,
    FLOWERSEC_RELEASE_GATE_COMMIT: verified,
    FLOWERSEC_RELEASE_VERSION: "0.26.0",
  };
  const cases = [
    {
      name: "missing release gate",
      lines: allTags,
      env: process.env,
      status: 1,
      error: /must be pushed with scripts\/release\.sh/,
    },
    {
      name: "missing one ecosystem tag",
      lines: allTags.slice(0, 2),
      env: gatedEnv,
      status: 1,
      error: /must be pushed together/,
    },
    {
      name: "tag points to another commit",
      lines: [...allTags.slice(0, 2), tagLine("refs/tags/flowersec-rust/v0.26.0", other)],
      env: gatedEnv,
      status: 1,
      error: /must point to the locally verified commit/,
    },
    {
      name: "complete verified release",
      lines: allTags,
      env: gatedEnv,
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
