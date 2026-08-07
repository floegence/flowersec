# Flowersec Agent Guide

> Scope: this repository (`flowersec/`).
>
> Goal: keep development, CI, release, and repository hygiene consistent and auditable.

---

## 1. Git workflow (Worktree, required)

- Never develop directly on `main`.
- Every change must be done in a dedicated worktree + feature branch.
- `main` is only for synchronization, integration, and the final push.
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
  diagnostic contains logs worth retaining, move a checksummed log or patch
  into the repository-external task artifact directory, verify
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
  For a failed run, retain only the checksummed logs required for
  diagnosis in the repository-external task artifact directory, then remove
  the scratch directory. At every commit, integration, push, stage transition,
  and task recovery, audit `git worktree list` plus Flowersec-named entries in
  the system temporary roots for resources owned by the current task; do not
  proceed while a superseded task-owned worktree or unused task-owned test
  directory remains. Do not clean or mutate another owner's resources.

## 3. External Linux test hosts

- External acceptance tests run only on dedicated Ubuntu 22.04+ amd64/x86_64/aarch64 hosts with non-interactive root access. Hosts without direct root or `sudo -n` capability are unsupported.
- Host initialization and all external tests run as root in one fixed environment rooted at `/var/lib/flowersec-test`. Never run root tests in a user's checkout or cache.
- Do not implement root/non-root fallback, per-suite privilege switching, cache ownership repair, or host-specific execution paths.
- `test-host-init.sh` idempotently prepares and validates only host-wide prerequisites. `flowersec-test` records only the plan and completed test IDs.
- Chromium does not support a WebTransport pooling option; each browser carrier is an independent native connection.
- The mobile cold phase requires every independent carrier to meet the existing deadline. A `dial_failed` result is RED and must not be hidden by pooling, retry, or timeout relaxation.
- Each test owns its setup, privileged resources, cancellation, and cleanup, and returns only GREEN or RED with minimal first-failure output.
- macOS fast precommit remains a local ordinary-user check and does not require an external host or root.

## 4. Release / tag policy

- A version release uses matching Go `flowersec-go/v<version>`, SwiftPM
  `<version>`, and Rust `flowersec-rust/v<version>` tags.
- Run `scripts/release.sh <version>` only from a clean `main` synchronized with `origin/main`.
- Release runs no tests and consumes no test artifacts, evidence, signatures, closures, attestations, or receipts.
- Release performs only version and ref validation, packaging, release-artifact signing, publication, and registry readback.
- GitHub Release notes must contain a human-readable summary.
- Publish Flowersec before upgrading downstream consumers.
