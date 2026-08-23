# Ubuntu Test Host

Privileged diagnostics and performance tests run natively as root on one
dedicated Ubuntu 22.04 or later amd64 or arm64 host. The host must support
direct root access or non-interactive `sudo -n`; the required host profile is fixed.

Use one entrypoint from a clean checkout whose exact commit is available from
`origin`:

```text
./scripts/test-host.sh init
./scripts/test-host.sh status --suite diagnostic
./scripts/test-host.sh resume --suite diagnostic
```

The entrypoint switches to root once, sets a fixed environment, and checks out
the exact source SHA under `/var/lib/flowersec-test/workspace`. Home, state,
temporary files, and caches remain root-owned under `/var/lib/flowersec-test`.
Root tests never use the invoking user's checkout or cache.

`test-host-init.sh` idempotently installs and verifies host-wide prerequisites.
Downloaded Go, Node, Rustup, and Swiftly artifacts are checked against pinned
per-architecture SHA-256 digests before root use; Swiftly also verifies the
PGP signature of the exact Swift toolchain release before installation.
`flowersec-test` is the only test runner; it records only the source SHA, suite,
plan, and completed canonical test IDs under `/var/lib/flowersec-test/state`.
Each test owns its resources and cleanup. GREEN retains no artifacts, while RED
retains only a bounded first-failure log.

The runner is built and invoked by the canonical host entrypoint; there is no
separate `bin/flowersec-test` installation contract.

Local `make test`, `make browser-smoke`, and fast `make precommit` run as the
ordinary development user without an external host. Release does not run tests
or consume test output.
