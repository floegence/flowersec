import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  checkNoticesContent,
  collectNpmPackages,
  collectPublishedRustPackages,
  generateNotices,
  renderNotices,
} from "./generate-third-party-notices.mjs";

const sourceRoot = path.resolve(import.meta.dirname, "..");

test("npm inventory is unique, nested-package aware, and sorted", () => {
  const packages = collectNpmPackages({
    packages: {
      "": { name: "root", version: "1.0.0" },
      "node_modules/z": { version: "2.0.0", license: "MIT" },
      "node_modules/a/node_modules/z": { version: "1.0.0", license: "ISC" },
      "node_modules/alias/node_modules/@scope/pkg": { version: "3.0.0", license: "Apache-2.0" },
      "node_modules/duplicate": { version: "1.0.0", license: "MIT" },
      "node_modules/other/node_modules/duplicate": { version: "1.0.0", license: "MIT" },
    },
  });
  assert.deepEqual(packages, [
    { name: "@scope/pkg", version: "3.0.0", license: "Apache-2.0" },
    { name: "duplicate", version: "1.0.0", license: "MIT" },
    { name: "z", version: "1.0.0", license: "ISC" },
    { name: "z", version: "2.0.0", license: "MIT" },
  ]);
});

test("Rust inventory follows published normal and build dependencies but excludes dev-only crates", () => {
  const metadata = {
    packages: [
      { id: "root", name: "flowersec", version: "1.0.0", source: null, license: "MIT" },
      { id: "normal", name: "normal", version: "1.0.0", source: "registry", license: "MIT" },
      { id: "build", name: "build", version: "2.0.0", source: "registry", license: "Apache-2.0" },
      { id: "dev", name: "dev", version: "3.0.0", source: "registry", license: "ISC" },
    ],
    resolve: {
      root: "root",
      nodes: [
        { id: "root", deps: [
          { pkg: "normal", dep_kinds: [{ kind: null }] },
          { pkg: "dev", dep_kinds: [{ kind: "dev" }] },
        ] },
        { id: "normal", deps: [{ pkg: "build", dep_kinds: [{ kind: "build" }] }] },
        { id: "build", deps: [] },
        { id: "dev", deps: [] },
      ],
    },
  };
  assert.deepEqual(collectPublishedRustPackages(metadata), [
    { name: "build", version: "2.0.0", license: "Apache-2.0" },
    { name: "normal", version: "1.0.0", license: "MIT" },
  ]);
});

test("notices rendering is deterministic and stale content is rejected", () => {
  const inventory = {
    go: [{ name: "example.com/module", version: "v1.2.3", license: "BSD-3-Clause", file: "LICENSE" }],
    npm: [{ name: "package", version: "2.0.0", license: "MIT" }],
    rust: [{ name: "crate", version: "3.0.0", license: "Apache-2.0 OR MIT" }],
  };
  const expected = renderNotices(inventory);
  assert.equal(renderNotices(inventory), expected);
  assert.doesNotThrow(() => checkNoticesContent(expected, expected));
  assert.throws(() => checkNoticesContent(expected, expected.replace("v1.2.3", "v1.2.2")), /out of date/);
});

test("checked-in third-party notices match all dependency sources", () => {
  const expected = generateNotices(sourceRoot);
  const actual = fs.readFileSync(path.join(sourceRoot, "THIRD_PARTY_NOTICES.md"), "utf8");
  checkNoticesContent(expected, actual);
  assert.match(actual, /^## Rust Crates$/m);
  assert.match(actual, /^- quinn@0\.11\.11 /m);
  assert.match(actual, /^- rustls@0\.23\./m);
});
