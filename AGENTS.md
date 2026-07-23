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
make check
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

git push origin main

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

## 3. Local quality gate (required)

- Local gates are the source of truth. Run `make check` from the repository root before merge.
- GitHub Actions deliberately does not repeat the full language, coverage, race, vulnerability, interoperability, or Swift matrix. The push/PR workflow is limited to changed-line and shell-syntax checks so hosted runner time is reserved for actual publication work.
- Every development worktree must run `make install-hooks` once after it is created.
- The `pre-commit` hook automatically runs `make precommit` and blocks the commit on failure.
- `make precommit` covers the fast high-value local gate:
  - IDL/codegen consistency: `gen-check`
  - stability manifest, API docs, and Go API guard: `stability-check`
  - Go: `fmt-check`, `go vet`, `go test`, and `go-cover-check`
  - TypeScript: auto `npm ci --audit=false` when dependencies are missing or incomplete, then `lint`, `build`, `test`, `ts-cover-check`, and `verify:package`
  - Swift: package description, source guard, build, and tests
  - Rust: formatting, clippy, tests, docs, MSRV, package, and fuzz-target build checks
- `pre-commit` does not replace the pre-merge gate: run `make check` explicitly before integration.
- `make check` covers:
  - Go: fmt, lint, test, race, and vulncheck
  - TypeScript: `npm ci`, lint, test, build, and audit
  - IDL codegen consistency: `gen-check`
  - Swift and Rust release checks, coverage, package validation, examples, and interoperability smoke

## 4. Release / tag policy

- Go SDK (`flowersec-go`) releases use the tag format `flowersec-go/v<version>` such as `flowersec-go/v0.9.0`.
- SwiftPM releases use root semantic-version tags with no prefix, such as `0.19.15`.
  - The root `Package.swift` must describe a buildable Swift package at that tag.
  - Downstream Swift packages should prefer version ranges such as `.package(url: "https://github.com/floegence/flowersec.git", from: "0.19.15")`.
  - Use `.exact(...)`, `.revision(...)`, or local path dependencies only for temporary integration work, not for a completed downstream upgrade.
- Rust SDK releases use `flowersec-rust/v<version>`.
- Run releases only through `scripts/release.sh <version>` from a clean, synchronized `main` worktree. Transport v2 releases also require `TRANSPORT_V2_RELEASE_RUNNER`, `TRANSPORT_V2_EVIDENCE_REPORT`, and `TRANSPORT_V2_BASE_SHA` to identify the audited Linux runner, clean-final-SHA signed report, and full ancestor SHA described in `docs/TRANSPORT_V2_RELEASE_EVIDENCE.md`. Bootstrap-disabled trust data or placeholder runner hashes authorize no release. The script runs `make release-check` once, creates the Go, SwiftPM, and Rust tags on the verified commit, and pushes `main` plus all three tags atomically.
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
