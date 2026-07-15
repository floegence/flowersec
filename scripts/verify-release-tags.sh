#!/usr/bin/env bash

set -euo pipefail

version="${1:-}"
expected_commit="${2:-}"
remote="${3:-origin}"

if [[ -z "$version" || -z "$expected_commit" ]]; then
  echo "usage: $0 <version> <expected-commit> [remote]" >&2
  exit 2
fi

expected_commit="$(git rev-parse "${expected_commit}^{commit}")"
refs=(
  "refs/tags/flowersec-go/v${version}"
  "refs/tags/${version}"
  "refs/tags/flowersec-rust/v${version}"
)

for ref in "${refs[@]}"; do
  if ! git fetch --quiet --no-tags "$remote" "$ref"; then
    echo "required release tag is missing: $ref" >&2
    exit 1
  fi
  commit="$(git rev-parse 'FETCH_HEAD^{commit}')"
  if [[ "$commit" != "$expected_commit" ]]; then
    echo "$ref points to $commit, expected $expected_commit" >&2
    exit 1
  fi
done

echo "release tags agree on $expected_commit"
