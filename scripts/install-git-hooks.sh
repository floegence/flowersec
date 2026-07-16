#!/bin/sh

set -eu

repo_root=$(git rev-parse --show-toplevel)

git config core.hooksPath .githooks
chmod +x "$repo_root/.githooks/pre-commit"
chmod +x "$repo_root/.githooks/pre-push"

printf '%s\n' "Installed Flowersec git hooks from $repo_root/.githooks"
