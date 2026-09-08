# Engineering toolchains

[`toolchains.json`](../toolchains.json) is the authority for exact engineering
toolchain versions. Development, primary CI, acceptance, security analysis, and
publication use these versions. The published SDK minimum versions are separate
compatibility promises.

| Role | Configuration | Execution |
| --- | --- | --- |
| Go | `go.version` | All modules, CI, security tools, probes, and the container builder |
| Rust | `rust.version` | Root `rust-toolchain.toml`, primary CI, native addons, probes, and publication |
| Rust minimum | `rust.msrv` | Dedicated MSRV checks for all three published Rust crates |
| Rust fuzzing | `rust.nightly` | Explicit fuzz target using a dated nightly |
| Node | `node.version` | `.nvmrc`, primary CI, local gates, and publication |
| Node compatibility | `node.compatibility` | Dedicated compatibility CI only |
| Swift | `swift.version`, `swift.xcode` | Explicit Xcode selection on macOS, including CodeQL; signed Swift release on Linux |
| Swift package minimum | `swift.toolsVersion` | Swift package manifests |
| TypeScript compiler | `typescript.version` | Explicit `@typescript/native/bin/tsc` entry point |
| TypeScript lint API | `typescript.apiVersion` | The `typescript` dependency alias consumed by lint tooling |
| TypeScript compatibility compiler | `typescript.compatibilityVersion` | Locked compiler behind the API wrapper and explicit `tsc6` consumer checks |

## Local setup

Install the exact Go version from the configuration and put its `bin` directory
first in `PATH`. Use `nvm install` followed by `nvm use` from the repository root
to select Node. Rustup reads the root `rust-toolchain.toml` automatically;
install the separately declared minimum or nightly toolchain when running those
explicit checks. On macOS select the configured Xcode using `DEVELOPER_DIR`.
On Linux install the configured Swift release with signature verification.

Check the environment before development:

```sh
node scripts/toolchains.mjs --check-runtime go node rust swift
make ts-ci
node scripts/toolchains.mjs --check-runtime typescript
make install-hooks
```

Runtime checks report the expected version, actual version, and setup guidance.
They do not modify a developer's global toolchain selection. Make disables Go
automatic toolchain switching. Arbitrary direct compiler commands outside the
engineering gates remain subject to the caller's environment.

## Consistency enforcement

`make precommit`, `make test`, and `make check` validate the actual toolchain
versions before executing work. The primary language precommit lanes also
validate their own toolchains. TypeScript builds validate the explicit compiler
entry point after dependencies are installed.

`scripts/check-toolchain-policy.mjs` checks native manifests, runtime gate
wiring, host initialization, minimum-version coverage, and the absence of
floating Rust selectors. The Go and workflow policy checks compare declarations
against the same configuration. Regression tests mutate declarations and remove
guards to ensure drift fails the gate. A passing schema check alone does not
authorize changing a supported minimum.

Some tools require native files or bootstrap literals, including `go.mod`,
`.nvmrc`, `rust-toolchain.toml`, workflow setup inputs, Docker image references,
and the Linux host installer. These are checked projections of the central
configuration, not independent version policies.

## Updating toolchains

Change the authoritative configuration and its checked projections together in
one feature worktree. Verify upstream downloads, update archive checksums and
container digests with the version, refresh affected dependency inventories,
and run the focused policy tests plus the normal precommit and acceptance gates.
Compiler changes also require the affected language and compatibility checks.
Release continues to perform publication and ref validation without running tests.

Keep existing SDK minimums unless a separate product decision changes support.
Dependabot proposals require the same consistency checks; floating selectors
such as `stable`, `nightly`, or `latest` are not upgrade mechanisms for the
primary toolchain.
