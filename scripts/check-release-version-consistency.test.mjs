import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  collectReleaseVersions,
  validateReleaseVersions,
} from "./check-release-version-consistency.mjs";

const sourceLabels = [
  "flowersec-ts/package.json",
  "flowersec-ts/package-lock.json",
  "flowersec-rust/Cargo.toml",
  "flowersec-rust/Cargo.lock",
  "flowersec-rust/fuzz/Cargo.lock",
  "examples/rust/Cargo.lock",
];

function matchingVersions(version = "0.26.0") {
  return sourceLabels.map((label) => ({ label, version }));
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed:\n${result.stdout}${result.stderr}`,
    );
  }
}

function createReleaseFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-version-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  fs.mkdirSync(path.join(root, "flowersec-ts"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.26.0" }),
  );
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package-lock.json"),
    JSON.stringify({ version: "0.26.0", packages: { "": { version: "0.26.0" } } }),
  );

  const manifests = [
    {
      path: "flowersec-rust/Cargo.toml",
      contents:
        "[package]\nname = \"flowersec\"\nversion = \"0.26.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    },
    {
      path: "flowersec-rust/fuzz/Cargo.toml",
      contents:
        "[package]\nname = \"flowersec-fuzz-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nflowersec = { path = \"..\" }\n",
    },
    {
      path: "examples/rust/Cargo.toml",
      contents:
        "[package]\nname = \"flowersec-example-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\npublish = false\n\n[dependencies]\nflowersec = { path = \"../../flowersec-rust\" }\n",
    },
  ];
  for (const manifest of manifests) {
    const manifestPath = path.join(root, manifest.path);
    fs.mkdirSync(path.join(path.dirname(manifestPath), "src"), { recursive: true });
    fs.writeFileSync(manifestPath, manifest.contents);
    fs.writeFileSync(path.join(path.dirname(manifestPath), "src/lib.rs"), "");
    run("cargo", ["generate-lockfile", "--manifest-path", manifestPath]);
  }

  return root;
}

function replaceFlowersecLockVersion(lockPath) {
  const contents = fs.readFileSync(lockPath, "utf8");
  const updated = contents.replace(
    /(name = "flowersec"\nversion = ")0\.26\.0(")/,
    (_match, prefix, suffix) => `${prefix}0.25.0${suffix}`,
  );
  assert.notEqual(updated, contents, `missing flowersec package in ${lockPath}`);
  fs.writeFileSync(lockPath, updated);
}

test("accepts one version across every release source", () => {
  assert.equal(validateReleaseVersions(matchingVersions(), "0.26.0"), "0.26.0");
});

test("rejects non-canonical numeric semantic versions", () => {
  for (const version of ["00.26.0", "0.026.0", "0.26.00", "+0.26.0"]) {
    assert.throws(() => validateReleaseVersions(matchingVersions(version)), /semantic version/);
  }
});

test("rejects drift in each release source", () => {
  for (const label of sourceLabels) {
    const versions = matchingVersions();
    versions.find((entry) => entry.label === label).version = "0.25.0";
    assert.throws(
      () => validateReleaseVersions(versions),
      new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  }
});

test("rejects a requested release version that does not match the files", () => {
  assert.throws(
    () => validateReleaseVersions(matchingVersions("0.25.0"), "0.26.0"),
    /requested release version 0\.26\.0/,
  );
});

test("collects npm JSON and all Cargo lock contexts", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-version-"));
  fs.mkdirSync(path.join(root, "flowersec-ts"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.26.0" }),
  );
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package-lock.json"),
    JSON.stringify({ version: "0.26.0", packages: { "": { version: "0.26.0" } } }),
  );

  const manifests = [
    "flowersec-rust/Cargo.toml",
    "flowersec-rust/fuzz/Cargo.toml",
    "examples/rust/Cargo.toml",
  ];
  for (const manifest of manifests) {
    fs.mkdirSync(path.dirname(path.join(root, manifest)), { recursive: true });
    fs.writeFileSync(path.join(root, manifest), "[package]\nname = \"fixture\"\n");
  }

  const seen = [];
  const versions = collectReleaseVersions(root, {
    cargoMetadata(manifestPath) {
      seen.push(path.relative(root, manifestPath));
      return "0.26.0";
    },
  });

  assert.deepEqual(versions, matchingVersions());
  assert.deepEqual(seen, manifests);
});

test("rejects inconsistent top-level and root package-lock versions", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "flowersec-release-lock-"));
  fs.mkdirSync(path.join(root, "flowersec-ts"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package.json"),
    JSON.stringify({ version: "0.26.0" }),
  );
  fs.writeFileSync(
    path.join(root, "flowersec-ts/package-lock.json"),
    JSON.stringify({ version: "0.26.0", packages: { "": { version: "0.25.0" } } }),
  );

  assert.throws(
    () => collectReleaseVersions(root, { cargoMetadata: () => "0.26.0" }),
    /package-lock\.json contains inconsistent versions/,
  );
});

test("collects the maintained version from real npm and Cargo lock contexts", (t) => {
  const root = createReleaseFixture(t);
  assert.deepEqual(collectReleaseVersions(root), matchingVersions());
});

test("rejects drift in every maintained npm version fact", async (t) => {
  const mutations = [
    ["package.json", (document) => { document.version = "0.25.0"; }],
    ["package-lock.json top-level", (document) => { document.version = "0.25.0"; }],
    ["package-lock.json root package", (document) => {
      document.packages[""].version = "0.25.0";
    }],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, (t) => {
      const root = createReleaseFixture(t);
      const fileName = name.startsWith("package.json") ? "package.json" : "package-lock.json";
      const filePath = path.join(root, "flowersec-ts", fileName);
      const document = JSON.parse(fs.readFileSync(filePath, "utf8"));
      mutate(document);
      fs.writeFileSync(filePath, JSON.stringify(document));
      assert.throws(() => validateReleaseVersions(collectReleaseVersions(root)), /0\.25\.0/);
    });
  }
});

test("rejects stale Rust manifest and lockfile facts", async (t) => {
  const mutations = [
    ["flowersec-rust/Cargo.toml", (root) => {
      const manifestPath = path.join(root, "flowersec-rust/Cargo.toml");
      const contents = fs.readFileSync(manifestPath, "utf8");
      fs.writeFileSync(manifestPath, contents.replace('version = "0.26.0"', 'version = "0.25.0"'));
    }],
    ["flowersec-rust/Cargo.lock", (root) => {
      replaceFlowersecLockVersion(path.join(root, "flowersec-rust/Cargo.lock"));
    }],
    ["flowersec-rust/fuzz/Cargo.lock", (root) => {
      replaceFlowersecLockVersion(path.join(root, "flowersec-rust/fuzz/Cargo.lock"));
    }],
    ["examples/rust/Cargo.lock", (root) => {
      replaceFlowersecLockVersion(path.join(root, "examples/rust/Cargo.lock"));
    }],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, (t) => {
      const root = createReleaseFixture(t);
      mutate(root);
      assert.throws(
        () => collectReleaseVersions(root),
        /cargo metadata failed/,
      );
    });
  }
});
