# Ubuntu Test Host

External Linux tests run natively as root on one dedicated Ubuntu 22.04 or
later amd64 or arm64 host. The host must support direct root access or
non-interactive `sudo -n`; there is no non-root fallback.

Use one entrypoint from a clean checkout whose exact commit is available from
`origin`:

```text
./scripts/test-host.sh init
./scripts/test-host.sh status --suite acceptance
./scripts/test-host.sh resume --suite acceptance
```

The entrypoint switches to root once, sets a fixed environment, and checks out
the exact source SHA under `/var/lib/flowersec-test/workspace`. Home, state,
temporary files, and caches remain root-owned under `/var/lib/flowersec-test`.
Root tests never use the invoking user's checkout or cache.

`test-host-init.sh` idempotently installs and verifies host-wide prerequisites.
`flowersec-test` is the only test runner; it records only the plan and completed
canonical test IDs under `/var/lib/flowersec-test/state`. Each test owns its
resources and cleanup. GREEN retains no artifacts, while RED retains only a
bounded first-failure log.

The runner is built and invoked by the canonical host entrypoint; there is no
separate `bin/flowersec-test` installation contract.

Fast `make precommit` remains a normal-user check on the development host.
Release does not run tests or consume test output.
