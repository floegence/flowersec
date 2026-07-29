#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <package-directory> [shard-count] [timeout] [parallelism] [race|normal]" >&2
}

if [[ $# -lt 1 || $# -gt 5 ]]; then
  usage
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package_dir="$1"
shard_count="${2:-4}"
timeout="${3:-5m}"
parallelism="${4:-4}"
mode="${5:-race}"

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
if [[ ! "$parallelism" =~ ^[1-9][0-9]*$ ]]; then
  echo "race shard parallelism must be a positive integer: $parallelism" >&2
  exit 2
fi
case "$mode" in
  race | normal) ;;
  *)
    echo "shard mode must be race or normal: $mode" >&2
    exit 2
    ;;
esac
case "$timeout" in
	1m | 2m | 3m | 4m | 5m) ;;
	*)
		echo "race shard timeout must be between 1m and 5m: $timeout" >&2
		exit 2
		;;
esac

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/flowersec-race-shards.XXXXXX")"
cleanup() {
  local status="$?"
  if (( status == 0 )); then
    rm -rf "$temp_dir"
  else
    echo "race shard logs retained at $temp_dir" >&2
  fi
}
trap cleanup EXIT
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
echo "$mode shard runner discovered $test_count tests across $shard_count shards with parallelism $parallelism"

run_batch() {
  local failed=0
  local index
  for index in "${!batch_pids[@]}"; do
    if ! wait "${batch_pids[$index]}"; then
      failed=1
    fi
    cat "${batch_logs[$index]}"
  done
  batch_pids=()
  batch_logs=()
  return "$failed"
}

batch_pids=()
batch_logs=()
batch_failed=0
for ((shard = 0; shard < shard_count; shard++)); do
  shard_file="$temp_dir/shard-$shard"
  if [[ ! -s "$shard_file" ]]; then
    continue
  fi
  pattern="$(paste -sd'|' "$shard_file")"
  shard_tests="$(wc -l < "$shard_file" | tr -d ' ')"
  log_file="$temp_dir/shard-$shard.log"
  (
    echo "running $mode shard $((shard + 1))/$shard_count with $shard_tests tests"
    cd "$package_dir"
    if [[ "$mode" == "race" ]]; then
      go test -race -count=1 -timeout="$timeout" -run "^(${pattern})$" .
    else
      go test -count=1 -timeout="$timeout" -run "^(${pattern})$" .
    fi
  ) >"$log_file" 2>&1 &
  batch_pids+=("$!")
  batch_logs+=("$log_file")
  if (( ${#batch_pids[@]} >= parallelism )); then
    if ! run_batch; then
      batch_failed=1
    fi
  fi
done
if (( ${#batch_pids[@]} > 0 )); then
  if ! run_batch; then
    batch_failed=1
  fi
fi
exit "$batch_failed"
