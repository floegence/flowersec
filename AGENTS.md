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

Recommended template:

```bash
git fetch origin
git switch main
git pull --ff-only

BR=feat-<topic>
WT=../flowersec-feat-<topic>
git worktree add -b "$BR" "$WT" origin/main
cd "$WT"
make install-hooks
```

Sync the feature branch with `origin/main`:

```bash
# in "$WT"
git status
# working tree must be clean before rebasing

git fetch origin
git rebase origin/main

# if conflicts happen:
# git add <resolved-files>
# git rebase --continue
#
# if you are unsure, stop immediately:
# git rebase --abort
```

After every rebase, do all of the following before you continue:

```bash
git diff origin/main...HEAD
# Run focused checks for the affected behavior. The exact main candidate owns
# the one complete pre-push gate described below.
```

Merge and cleanup:

```bash
git switch main
git fetch origin
git pull --ff-only

# If local main is already ahead of origin/main, push the full current local main tip first.
# Do not keep an older batch of local main commits unpublished while pushing only the new merge result.
# git push origin main

# default: keep main linear and clean
git merge --squash "$BR"
git commit -m "<type>(<scope>): <summary>"

# exception: preserve the original feature commits only when they are already clean
# git merge --ff-only "$BR"

./scripts/push-main.sh

git worktree remove "$WT"

# squash merges are not considered "merged" by git branch -d
git branch -D "$BR"

# if you used --ff-only instead, use:
# git branch -d "$BR"

# if the feature branch was ever pushed:
git push origin --delete "$BR"
```

Additional rules:

- Remote `main` should move directly to the latest local `main` tip whenever `main` is pushed.
- If local `main` has unpublished commits before you merge the current feature, publish those local `main` commits first, then merge, then push the updated `main` tip.
- Integration and conflict resolution must preserve the semantic intent of all involved branches, not just produce text that compiles.
- Before resolving merge or rebase conflicts, review the substantive commits on each side for new features, bug fixes, behavior changes, tests, and user-facing workflows.
- Do not drop, overwrite, or silently weaken current or historical functionality unless the user explicitly approves that product decision.
- If two branches introduce incompatible behavior, surface the product or architecture tradeoff instead of choosing one side silently.
- After resolving conflicts, run focused checks for the affected behavior in addition to the repository quality gate.
- If a feature branch has already been pushed and someone else depends on it, stop treating it as a private rebase branch. Coordinate a separate conservative flow instead of forcing the beauty-first default.

Conflict resolution principles:

- Resolve conflicts only in the feature worktree. If a conflict happens on `main`, abort and go back to the feature branch.
- During `git rebase origin/main`, do not use `--ours` / `--theirs` on autopilot:
  - in a rebase conflict, `--ours` usually refers to the rebasing target (`origin/main`);
  - `--theirs` usually refers to the replayed feature commit.
- Prefer the latest `main` structure first, then re-apply the real feature intent on top of it.
- For renames, file moves, formatting changes, or import reshuffles: keep the latest `main` layout, then restore the feature logic in the new location.
- For generated files, snapshots, and lockfiles: prefer regenerating rather than manually stitching conflict markers.
- For shared contracts, IDL-generated artifacts, stability manifests, and cross-package schema fields: never blindly take one side; align the semantics manually.
- For behavior conflicts that are not obvious from conflict markers, inspect the relevant commit history and tests so that fixes and existing product behavior are not regressed.
- If you are unsure whether the resolution is correct, abort the rebase and start over from the backup branch.

Recommended Git config:

```bash
git config --global rerere.enabled true
git config --global merge.conflictstyle zdiff3
```

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

- Local gates are the source of truth. The exact synchronized `main` candidate runs `make check` once through the pre-push hook; do not run it on intermediate feature tips.
- Push local `main` with `./scripts/push-main.sh`. It completes `make check`
  before opening the remote push transport, revalidates the clean exact SHA and
  unchanged `origin/main`, then invokes normal `git push`; the pre-push hook
  verifies the same SHA. Direct `git push` remains protected and runs the
  complete gate inside the hook, but should not be used for the normal main
  workflow because a long gate can outlive the already-open remote connection.
- GitHub push and pull-request CI is intentionally limited to formatting, syntax, short unit tests, static contracts, generated-file consistency, and repository-boundary checks. It must not install browsers, build product packages, or run Docker, integration, renderer, terminal, stress, performance, weak-network, soak, or full-race jobs.
- GitHub CodeQL Default Setup must remain disabled because it implicitly runs the full multi-language analysis on every push. The checked-in CodeQL workflow is the sole CodeQL authority and may run only by explicit manual dispatch or its reviewed daily schedule; it must not declare push or pull-request triggers. A scheduled run must compare the current `main` SHA with the latest successful scheduled CodeQL run and skip the expensive language matrix when they match; lookup failure must fail safe by scanning. Manual dispatch always scans. Ordinary push/PR security coverage stays in the fast source-only repository workflow, while compiled-language and full multi-language CodeQL analysis remains outside the ordinary push path.
- Do not move expensive validation into hosted push/PR CI merely to make it visible in Actions. Complete language builds, coverage, package/publish checks, browsers, integration, race, weak-network, performance, soak, and evidence collection belong to the frozen exact-main local pre-push gate. Release-tag workflows may retain only ref-dependent publication, signing, attestation, and registry readback work.
- Every development worktree must run `make install-hooks` once after it is created.
- The `pre-commit` hook automatically runs `make precommit` and blocks the commit on failure.
- `make precommit` covers the fast high-value local gate:
  - IDL/codegen consistency: `gen-check`
  - stability manifest, API docs, and Go/TypeScript source API guards: `stability-source-check`; compiled Swift/Rust stability verification remains in final-only `stability-check`
  - Go: `fmt-check`, `go vet`, `go test -short`, and `go-cover-check`; real carrier, endpoint, process, and network integration tests stay final-only
  - TypeScript: auto `npm ci --audit=false` when dependencies are missing or incomplete, then lint and the short Vitest group; integration, Go interop, browser-bundle, coverage, build, and package validation stay final-only
  - Swift: package description, dependency-security validation, and the source guard; build, test, and coverage stay final-only
  - Rust: formatting, clippy, and library unit tests; docs, MSRV, package, publish dry-run, coverage, semver, and fuzz-target builds stay final-only
  - repository security: lock/source policy, generated inventory freshness, and other static boundary contracts; distribution archive assembly and package-closure tests stay final-only
- `make precommit` must not reach Swift build/test/coverage, TypeScript coverage or package validation, Cargo package or publish dry-run, complete race suites, browsers, Docker, remote runners, weak-network, performance, soak, or integration workloads. Keep those checks reachable from `make check` instead.
- `pre-commit` does not replace final integration validation. Feature work runs focused and affected checks; after integration, the exact `main` push owns the single complete `make check` run through `pre-push`.
- `make check` covers:
  - Go: fmt, lint, test, race, and vulncheck
  - TypeScript: `npm ci`, lint, test, build, and audit
  - IDL codegen consistency: `gen-check`
  - Swift and Rust release checks, coverage, package and publish validation, distribution archive closure, examples, and interoperability smoke

### 3.1 Mandatory validation layers

- Daily RED/GREEN work runs only the exact test and the genuinely affected package, test file, or named test group.
- After a failure, rerun the smallest failing case first. Expand only to the affected boundary after it passes; never restart a complete suite as the first diagnostic step.
- Before the expensive exact-main gate starts, complete a bounded preflight for
  required remote access and dependency metadata. A preflight failure must stop
  before race, coverage, browser, integration, or package-validation work begins.
- After a complete-gate failure, rerun the smallest failing check first. A
  confirmed transient external failure permits at most one same-SHA complete
  retry only after the focused check and every remaining tail stage are GREEN;
  a repeated failure requires an infrastructure or gate fix.
- When a parallel final lane fails, record and report the first failure, stop
  scheduling new work, and perform only bounded cleanup or drainage of work
  already running.
- After an exact-main pre-push failure at stage S, rerun the smallest failing
  case first, then the affected boundary. On the repaired frozen candidate,
  continue with the explicit stages after S that were not reached or were
  cancelled. Do not immediately restart the complete pre-push gate.
- A pre-push recovery cycle may contain multiple diagnostic tail
  continuations. When a later tail stage fails, fix its smallest failing case,
  pass the affected boundary, and continue with the stages after that failure.
  Do not restart the complete pre-push gate until every remaining tail stage
  has been reached and is GREEN.
- After all tail stages are GREEN, run `./scripts/push-main.sh` once from the
  beginning. If that complete run finds another failure, begin a new recovery
  cycle instead of immediately repeating the complete gate. Diagnostic tail
  validation never replaces the final complete pre-push gate.
- This continuation exception applies only to the exact-main pre-push gate.
  Other test, formal collector, evidence, and release workflows may rerun
  completely after the smallest failure and affected checks are GREEN when
  their own fresh full-run contract requires it.
- Keep external progress records as compact current-state snapshots. Store
  chronological evidence in checksummed logs rather than append-only journals.
- Default package tests must remain fast. Real browsers, network namespaces, Docker, remote runners, child-process systems, large fixtures, stress, performance, weak-network, soak, resource-cleanup evidence, full-package race, and repository-wide integration checks belong to explicit final-integration targets, independent packages, or named selectors, not the daily default path.
- Full-package race, complete `transportcheck`, browser, integration, stress, performance, weak-network, and resource-cleanup gates may run only after implementation is complete, the feature is synchronized, and the candidate SHA is frozen. In the normal no-failure flow, run them once for the exact `main` SHA through the pre-push gate. The recovery exception above permits only the required diagnostic tail continuations before one final complete pre-push run.
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
- Do not repeat the same expensive complete gate when neither code nor an acceptance contract changed, except for the single confirmed-transient retry allowed above after the tail is GREEN.
- Before starting an expensive command, classify it as focused, affected, or final pre-push. If it cannot be classified, do not default to the complete suite.

### 3.2 Portable release runners

- Release and evidence code must be portable across supported Linux hosts. Switching between Orange, udesk, another runner, or a supported CPU architecture must not require a source change, trust-policy commit, or regenerated repository fixture.
- The repository may freeze supported operating systems and architectures, isolation, namespace, traffic-control, packet-counter, workload, threshold, effective-config, evidence-schema, and signer contracts. It must not freeze a machine instance's hostname, kernel release, executable digest, source digest, argv digest, or other host-specific identity in tracked policy.
- Store each runner instance's exact identity in a private Git-ignored local file. The default is `.flowersec/transport-runner.json`; `FLOWERSEC_TRANSPORT_RUNNER_CONFIG` may select an absolute repository-external file. Never commit a real runner identity or secret.
- Generate or refresh the default file on the concrete Linux runner with `make transport-runner-config`; use `TRANSPORT_RUNNER_CONFIG=/absolute/path make transport-runner-config` for a repository-external file. Generation is a workload-free preflight that requires a clean checkout and recomputes the deterministic executable, source graph, canonical argv, actual architecture, and kernel. Do not hand-edit or copy an identity between hosts.
- The collector must fail closed unless the local file is a canonical regular non-symlink file, is not group/world accessible, is untracked and ignored when inside the checkout, matches the actual OS/architecture/kernel, and matches deterministic executable/source/argv digests. It must bind the file digest and complete actual identity into raw evidence and detect changes during collection.
- Portability must not weaken evidence. Offline signing and release verification must still validate the signed host identity, recompute repository-derived source and argv identities, preserve executable and raw-job digest bindings, and enforce the same workload, network, certificate, resource, threshold, and zero-residual contracts.

## 4. Release / tag policy

- Go SDK (`flowersec-go`) releases use the tag format `flowersec-go/v<version>` such as `flowersec-go/v0.9.0`.
- SwiftPM releases use root semantic-version tags with no prefix, such as `0.19.15`.
  - The root `Package.swift` must describe a buildable Swift package at that tag.
  - Downstream Swift packages should prefer version ranges such as `.package(url: "https://github.com/floegence/flowersec.git", from: "0.19.15")`.
  - Use `.exact(...)`, `.revision(...)`, or local path dependencies only for temporary integration work, not for a completed downstream upgrade.
- Rust SDK releases use `flowersec-rust/v<version>`.
- Run releases only through `scripts/release.sh <version>` from a clean, synchronized `main` worktree. Transport v2 collection requires `TRANSPORT_V2_RELEASE_RUNNER`, `TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT`, `TRANSPORT_V2_BASE_SHA`, and a private local runner identity matching the actual host and deterministic build. Release itself requires only the immutable offline-signed `TRANSPORT_V2_EVIDENCE_REPORT` and the full ancestor `TRANSPORT_V2_BASE_SHA` described in `docs/TRANSPORT_V2_RELEASE_EVIDENCE.md`; it must never rerun the privileged collector. Missing or mismatched local identity authorizes no collection or release. The script runs `make release-check` once, creates the Go, SwiftPM, and Rust tags on the verified commit, and pushes `main` plus all three tags atomically.
- The pre-push hook rejects release-tag pushes that bypass the release script or do not carry all three matching tags for the same verified commit.
- Only `flowersec-go/v*` triggers the unified publication workflow. The SwiftPM and Rust tags are ecosystem source tags and must not trigger duplicate test or publication workflows. The Rust workflow is a reusable publication job called by the unified workflow and also provides a manual recovery entrypoint.
- Hosted release jobs may build and publish artifacts, images, npm packages, crates, and release notes. They must not repeat `make check`, coverage, race, fuzz, interoperability, or Swift test gates that already passed locally.
- When a downstream repository needs a new capability, use an upstream-first flow:
  - implement and validate the change in this repository first
  - merge it into `main`
  - run `scripts/release.sh <version>` to create and atomically push all release tags
  - confirm the release is published successfully
  - only then upgrade the downstream dependency
- GitHub Release notes must include a human-readable summary of what the release contains. Do not publish a release with only a tag, assets, and an empty default body.
- Release notes are generated from non-merge commit titles between the previous `flowersec-go/v*` tag and the current tag, so commit titles must stay concise, readable, and release-note friendly. Pure release housekeeping such as `chore(release): prepare/bump ...` should not end up in the published notes.
