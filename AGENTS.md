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
STAMP=$(date +%Y%m%d-%H%M%S)
git branch "backup/$BR-$STAMP"
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
git range-diff "backup/$BR-$STAMP"...HEAD
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

## 3. Local quality gate (required, CI-aligned)

- CI is the source of truth. Locally, at minimum, run `make check` from the repository root before merge.
- Every development worktree must run `make install-hooks` once after it is created.
- The `pre-commit` hook automatically runs `make precommit` and blocks the commit on failure.
- `make precommit` covers the fast high-value local gate:
  - IDL/codegen consistency: `gen-check`
  - stability manifest, API docs, and Go API guard: `stability-check`
  - Go: `fmt-check`, `go vet`, `go test`
  - TypeScript: auto `npm ci --audit=false` when dependencies are missing, then `lint`, `build`, `test`, and `verify:package`
- `pre-commit` does not replace the pre-merge gate: run `make check` explicitly before integration.
- `make check` covers:
  - Go: fmt, lint, test, race, and vulncheck
  - TypeScript: `npm ci`, lint, test, build, and audit
  - IDL codegen consistency: `gen-check`

## 4. Release / tag policy

- Go SDK (`flowersec-go`) releases use the tag format `flowersec-go/v<version>` such as `flowersec-go/v0.9.0`.
- When a downstream repository needs a new capability, use an upstream-first flow:
  - implement and validate the change in this repository first
  - merge it into `main`
  - create and push the release tag
  - confirm the release is published successfully
  - only then upgrade the downstream dependency
- GitHub Release notes must include a human-readable summary of what the release contains. Do not publish a release with only a tag, assets, and an empty default body.
- Release notes are generated from non-merge commit titles between the previous `flowersec-go/v*` tag and the current tag, so commit titles must stay concise, readable, and release-note friendly. Pure release housekeeping such as `chore(release): prepare/bump ...` should not end up in the published notes.
