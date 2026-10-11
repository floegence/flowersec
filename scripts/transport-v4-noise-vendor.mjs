import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const hash = bytes => createHash("sha256").update(bytes).digest("hex");
const relativeDirectory = "flowersec-go/internal/noisehandshake";

function readRegularFile(file) {
  let descriptor;
  try {
    descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (error) {
    if (error.code === "ELOOP") assert.fail(`vendored Noise source must be a regular file: ${file}`);
    throw error;
  }
  try {
    assert.ok(fs.fstatSync(descriptor).isFile(), `vendored Noise source must be a regular file: ${file}`);
    return fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

// Validate the exact included upstream source and explicit narrow modification.
// Provenance bytes are inputs to the source SBOM, not a cryptographic review vote.
export function verifyNoiseVendor(root) {
  const directory = path.join(root, relativeDirectory);
  if (!fs.existsSync(directory)) return null;
  assert.ok(fs.lstatSync(directory).isDirectory(), "vendored Noise directory must not be a symlink");
  const manifest = JSON.parse(readRegularFile(path.join(directory, "UPSTREAM.json")).toString("utf8"));
  assert.equal(manifest.schema, "flowersec.vendored-noise-source.v1");
  assert.equal(manifest.module, "flowersec-go");
  assert.equal(manifest.package, "internal/noisehandshake");
  assert.equal(manifest.name, "Flowersec Noise public-length adapter");
  assert.equal(manifest.version, "1.1.0-flowersec.1");
  assert.equal(manifest.upstream.module, "github.com/flynn/noise");
  assert.equal(manifest.upstream.version, "v1.1.0");
  assert.equal(manifest.upstream.revision, "4d9f71cd4ba1fe81415efac312664ccc4bc79b46");
  assert.equal(manifest.upstream.source, `https://github.com/flynn/noise/tree/${manifest.upstream.revision}`);
  assert.equal(manifest.upstream.module_sum, "h1:KjPQoQCEFdZDiP03phOvGi11+SVVhBG2wOWAorLsstg=");
  assert.equal(manifest.upstream.go_mod_sum, "h1:xbMo+0i6+IGbYdJhF31t2eR1BIU0CYc12+BNAKwUTag=");
  assert.equal(manifest.license, "BSD-3-Clause");
  assert.equal(manifest.patch.path, "upstream.patch");
  assert.deepEqual(Object.keys(manifest.files).sort(), ["LICENSE", "cipher_suite.go", "hkdf.go", "patterns.go", "state.go"]);
  assert.deepEqual(fs.readdirSync(directory).sort(), [...Object.keys(manifest.files), "UPSTREAM.json", "upstream.patch"].sort());
  const read = name => readRegularFile(path.join(directory, name));
  for (const [name, info] of Object.entries(manifest.files)) {
    assert.match(info.upstream_sha256, /^[a-f0-9]{64}$/u);
    assert.match(info.sha256, /^[a-f0-9]{64}$/u);
    assert.equal(hash(read(name)), info.sha256, `vendored Noise source drift: ${name}`);
    if (!["state.go", "cipher_suite.go"].includes(name)) assert.equal(info.sha256, info.upstream_sha256);
  }
  assert.equal(hash(read("upstream.patch")), manifest.patch.sha256, "vendored Noise patch drift");
  const licenseText = read("LICENSE").toString("utf8");
  assert.ok(licenseText.includes(manifest.copyright));
  // Go reports physical source directories even when the checkout's parent is
  // reached through a host path alias (for example macOS /var -> /private/var).
  return { manifest, directory: fs.realpathSync(directory), licenseText };
}
