#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <package-directory> [shard-count] [timeout]" >&2
}

if [[ $# -lt 1 || $# -gt 3 ]]; then
  usage
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package_dir="$1"
shard_count="${2:-4}"
timeout="${3:-10m}"

if [[ "$package_dir" != /* ]]; then
  package_dir="$repo_root/$package_dir"
fi
if [[ ! -d "$package_dir" ]]; then
  echo "race shard package directory does not exist: $package_dir" >&2
  exit 2
fi
if [[ ! "$shard_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "race shard count must be a positive integer: $shard_count" >&2
  exit 2
fi
if [[ -z "$timeout" ]]; then
  echo "race shard timeout must not be empty" >&2
  exit 2
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/flowersec-race-shards.XXXXXX")"
trap 'rm -rf "$temp_dir"' EXIT
tests_file="$temp_dir/tests"

(
  cd "$package_dir"
  go test -list '^Test' .
) | awk '/^Test[A-Za-z0-9_]+$/ { print }' > "$tests_file"

if [[ ! -s "$tests_file" ]]; then
  echo "race shard runner discovered no top-level tests in $package_dir" >&2
  exit 1
fi

duplicate_tests="$(sort "$tests_file" | uniq -d)"
if [[ -n "$duplicate_tests" ]]; then
  echo "race shard runner discovered duplicate top-level tests:" >&2
  echo "$duplicate_tests" >&2
  exit 1
fi

awk -v directory="$temp_dir" -v count="$shard_count" '
  {
    shard = (NR - 1) % count
    print > (directory "/shard-" shard)
  }
' "$tests_file"

test_count="$(wc -l < "$tests_file" | tr -d ' ')"
echo "race shard runner discovered $test_count tests across $shard_count shards"

for ((shard = 0; shard < shard_count; shard++)); do
  shard_file="$temp_dir/shard-$shard"
  if [[ ! -s "$shard_file" ]]; then
    continue
  fi
  pattern="$(paste -sd'|' "$shard_file")"
  shard_tests="$(wc -l < "$shard_file" | tr -d ' ')"
  echo "running race shard $((shard + 1))/$shard_count with $shard_tests tests"
  (
    cd "$package_dir"
    go test -race -count=1 -timeout="$timeout" -run "^(${pattern})$" .
  )
done
