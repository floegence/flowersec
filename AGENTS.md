# Flowersec Agent Guide

> Scope: this repository (`flowersec/`).
>
> Goal: keep development, CI, release, and repository hygiene consistent and auditable.

---

## 1. Git workflow (Worktree, required)

- Never develop directly on `main`.
- Every change must be done in a dedicated worktree + feature branch.
- `main` is only for `pull --ff-only` and integration.
- `main` must not be managed as a partial-push branch relative to `origin/main`.
  - If local `main` is going to be pushed, push the full current local `main` tip together with all of its latest commits.
  - Do not push only a subset of local `main` commits, and do not update remote `main` through another branch while leaving newer local `main` commits unpublished.
- One feature = one dedicated worktree + one local private branch.
- Worktree and branch ownership is strict. Manage only worktrees and branches
  created for the current task. Worktrees and branches owned by another user,
  agent, or task may coexist and do not count toward the current task's limit.
  Do not stash, stage, commit, switch, rebase, move, prune, remove, or delete
  another owner's worktree or branch. Read-only inspection is allowed only to
  identify ownership or avoid a path or branch-name collision; leave the
  resource unchanged and choose a different task-local path or name.
- Keep at most one active non-main Flowersec worktree owned by the current task.
  Before creating or switching to another feature or diagnostic worktree for
  that task, finish or preserve the task's current work, remove that task-owned
  worktree, and verify with `git worktree list` that no superseded worktree
  owned by the current task remains. Other owners' worktrees may coexist. The
  main worktree remains the clean integration worktree described in this guide;
  do not perform feature edits there.
- Do not leave disposable Flowersec worktrees or clones under `/tmp`,
  `/private/tmp`, or the platform temporary directory. When a failed
  diagnostic contains evidence worth retaining, move a checksummed archive,
  patch, or log into the repository-external task artifact directory, verify
  it, and then remove the temporary worktree or clone. Never delete unknown
  dirty work blindly; preserve its tracked diff, untracked files, and
  unreachable commit first.
- Default assumption: keep feature branches private until they are merged into `main`. This is what makes repeated history cleanup safe and predictable.
- Default sync strategy for clean graphs: rebase the feature branch onto `origin/main`. Do not merge `origin/main` into the feature branch in the default flow.
- Default integration strategy for clean graphs: use `git merge --squash "$BR"` on `main`.
  - Use `git merge --ff-only "$BR"` only when the feature branch already contains a small set of clean, intentional commits that are worth preserving on `main`.
- Do not combine `merge origin/main` inside the feature branch with `--no-ff` merges back into `main`; that combination is the main reason local multi-worktree graphs become noisy.
- Resolve conflicts only inside the feature worktree, never on `main`.
- Do not merge feature branches into each other.
- Do not create routine `backup/*` branches. If recovery is needed, abort the
  rebase, inspect the feature worktree, and create an explicit recovery branch
  only with user approval and a real collaboration purpose.
- Every new worktree must run `make install-hooks` before development starts.
- Before rebasing, require a clean feature worktree; after rebasing onto the
  latest `origin/main`, inspect the complete feature diff and rerun the affected
  focused checks.
- Before integration, fast-forward local `main` from `origin/main`. Preserve a
  small intentional feature history with `--ff-only`; otherwise squash it into
  one intentional Conventional Commit. Push the complete local `main` tip with
  `./scripts/push-main.sh`, then remove the task-owned worktree and branch.
- Integration and conflict resolution must preserve the semantic intent of all involved branches, not just produce text that compiles.
- Before resolving merge or rebase conflicts, review the substantive commits on each side for new features, bug fixes, behavior changes, tests, and user-facing workflows.
- Do not drop, overwrite, or silently weaken current or historical functionality unless the user explicitly approves that product decision.
- If two branches introduce incompatible behavior, surface the product or architecture tradeoff instead of choosing one side silently.
- After resolving conflicts, run focused checks for the affected behavior in addition to the repository quality gate.
- If a feature branch has already been pushed and someone else depends on it, stop treating it as a private rebase branch. Coordinate a separate conservative flow instead of forcing the beauty-first default.
- Resolve conflicts only in the feature worktree. Start from the latest main
  structure, restore the feature intent manually, regenerate derived artifacts
  instead of stitching them, and abort the rebase when the resolution is not
  defensible. Never select `--ours` or `--theirs` blindly.

## 1.1 Repository language policy (required)

- Maintained repository content should be English by default, including:
  - code comments
  - Markdown and other documentation files
  - scripts and examples
  - release notes and operational instructions
- Multilingual test fixtures and samples are allowed only when they are necessary to validate language-sensitive behavior, and they must stay minimal and well-explained in English context.

## 2. Temporary working docs (must stay out of the repo)

- Temporary planning notes, analysis docs, implementation checklists, or scratch writeups are allowed during development.
- They must not be committed into the repository.
  - Prefer storing them outside the repository.
  - If they must live inside the repository during development, keep them under paths covered by `.gitignore`, and make sure `git status` is clean before merging.
- Delete temporary working docs after the feature is merged so they do not accumulate as misleading historical drafts.
- Test and diagnostic temporary directories owned by the current task follow
  the same lifecycle. Remove
  successful scratch directories immediately after their result is recorded.
  For a failed run, retain only the checksummed logs or artifacts required for
  diagnosis in the repository-external task artifact directory, then remove
  the scratch directory. At every commit, integration, push, stage transition,
  and task recovery, audit `git worktree list` plus Flowersec-named entries in
  the system temporary roots for resources owned by the current task; do not
  proceed while a superseded task-owned worktree or unused task-owned test
  directory remains. Do not clean or mutate another owner's resources.

## 3. Local quality gate (required)

- Local gates are authoritative. A normal feature commit runs only the fast
  pre-commit gate. Required formal evidence is collected and signed for the
  final frozen main candidate before `./scripts/push-main.sh` runs the one
  complete `make check`, writes the exact-SHA gate receipt, and pushes main.
  The pre-push hook validates that receipt and never reruns the gate.
- Ordinary GitHub push and pull-request CI is source-only and fast. Expensive
  builds, package validation, coverage, browsers, integration, race,
  weak-network, performance, soak, and evidence belong to exact-main local
  validation. Release workflows retain only ref-dependent publication,
  signing, attestation, and registry readback work.
- Keep GitHub CodeQL Default Setup disabled. The checked-in workflow is the
  sole authority, runs only on its reviewed daily schedule or manual dispatch,
  skips an unchanged `main` after a successful scheduled analysis, and scans
  fail-closed when the prior-run lookup cannot be established.
- Every development worktree must run `make install-hooks` once after it is created.
- The pre-commit hook must block on the fast, source-oriented `make precommit`
  gate and must not reach final-only builds, package/publish validation,
  coverage, race, browsers, Docker, remote runners, weak-network, performance,
  soak, or integration work.
- `make check` owns the final candidate's only complete test run, including all
  checks excluded from pre-commit. Release verification owns no tests and only
  consumes the immutable signed evidence and exact gate receipt. The Makefile
  and its graph-contract tests are authoritative for the target inventory.

### 3.1 Mandatory validation layers

- Daily work starts with the smallest failing test and expands only to the affected boundary.
- Before the expensive exact-main gate starts, complete a bounded preflight for
  required remote access and dependency metadata. A preflight failure must stop
  before race, coverage, browser, integration, or package-validation work begins.
- When a parallel final lane fails, record and report the first failure, stop
  scheduling new work, and perform only bounded cleanup or drainage of work
  already running.
- A normal feature commit runs only the fast pre-commit gate.
- The final frozen main candidate runs exactly one complete `make check`
  through `./scripts/push-main.sh`.
- Required formal evidence must be collected and signed for that exact
  candidate before the final main push.
- If pre-push fails at stage S, keep main frozen and recover in the task feature
  worktree: fix the smallest failure, pass affected checks, then run the
  remaining stages after S. Repeat from any later tail failure until the tail
  is GREEN.
- After the tail is GREEN, synchronize and integrate the feature once, then run
  one complete `./scripts/push-main.sh`. Tail runs are diagnostic and never
  replace the final complete gate. When the candidate changes, regenerate only
  the formal evidence bound to the new candidate.
- Release verification consumes the immutable signed evidence and the exact
  main gate receipt. It must not rerun tests, builds, coverage, race, browser,
  package validation, or the collector.
- Keep external progress records as compact current-state snapshots. Store
  chronological evidence in checksummed logs rather than append-only journals.
- Default package tests must remain fast. Real browsers, network namespaces, Docker, remote runners, child-process systems, large fixtures, stress, performance, weak-network, soak, resource-cleanup evidence, full-package race, and repository-wide integration checks belong to explicit final-integration targets, independent packages, or named selectors, not the daily default path.
- Full-package race, complete `transportcheck`, browser, integration, stress, performance, weak-network, and resource-cleanup gates may run only after implementation is complete, the feature is synchronized, and the candidate SHA is frozen.
- `go test -parallel N` changes concurrency only for tests that explicitly call `t.Parallel()`; it is never a substitute for test ownership and layering.
- Independent focused test groups may run in parallel only when they do not share ports, directories, process-global environment, browser state, containers, or a remote runner. Environment-mutating or shared-runner tests must remain serial.
- The exact-main final gate runs dependency-free source contracts first, then a
  bounded dependency and network preflight, bounded offline package validation,
  complete race as an exclusive phase through `final-race-check`, four bounded
  offline language lanes, and bounded serial offline post-validation for
  examples and interoperability. Do not move work between these phases without
  updating the Make-graph contract tests.
- A single test case should normally finish within five minutes. Terminate it at ten minutes and retain its output and artifacts.
- Keep the final acceptance strength unchanged. Do not gain speed by deleting coverage, reducing workloads, weakening thresholds, skipping the final gate, or relabeling evidence; move tests to the correct layer instead.
- Before starting an expensive command, classify it as focused, affected, or final pre-push. If it cannot be classified, do not default to the complete suite.

### 3.2 Portable release runners

- Release and evidence code must be portable across supported Linux hosts and
  architectures; tracked policy must not bind a concrete hostname, kernel, or
  runner instance identity.
- Keep each runner's exact identity and secrets in a private Git-ignored local
  configuration. Never commit, hand-copy between hosts, or weaken validation of
  that identity.
- Collection, offline signing, and release verification must fail closed on
  identity, source, executable, argument, evidence, or lifecycle drift while
  preserving all workload, network, certificate, resource, threshold, and
  zero-residual requirements.
- Follow `docs/TRANSPORT_V2_RELEASE_EVIDENCE.md` for runner setup, collection,
  signing, and verification details.
- Every remote focused or formal workload must pass the checked-in preflight in the exact workload context. Any later environment-class failure that preflight could have detected requires a regression contract and preflight update before retry.

## 4. Release / tag policy

- A version release uses matching Go `flowersec-go/v<version>`, SwiftPM
  `<version>`, and Rust `flowersec-rust/v<version>` tags.
- `scripts/release.sh <version>` is the verification-and-publication-only
  release entrypoint. Run it from a clean synchronized `main`; it consumes the
  signed evidence and exact main gate receipt, validates static release
  contracts without running tests or builds, then pushes `main` and the
  complete matching tag set atomically.
- Reusable downstream capabilities follow an upstream-first flow: implement,
  validate, release, and verify Flowersec before upgrading consumers to the
  published version. Never use local path or source-checkout wiring as the
  completed integration.
- GitHub Release notes must include a human-readable summary of what the release contains. Do not publish a release with only a tag, assets, and an empty default body.
- Follow `docs/TRANSPORT_V2_RELEASE_EVIDENCE.md` for evidence inputs and the
  release scripts and workflow contracts for publication details.
