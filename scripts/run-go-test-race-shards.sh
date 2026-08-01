#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <package-directory> [shard-count] [timeout] [parallelism] [race|normal] [worker-gomaxprocs]" >&2
}

if [[ $# -lt 1 || $# -gt 6 ]]; then
  usage
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
package_dir="$1"
shard_count="${2:-4}"
timeout="${3:-5m}"
parallelism="${4:-4}"
mode="${5:-race}"
worker_gomaxprocs="${6:-}"

if [[ "$package_dir" != /* ]]; then
  package_dir="$repo_root/$package_dir"
fi
if [[ ! -d "$package_dir" ]]; then
  echo "race shard package directory does not exist: $package_dir" >&2
  exit 2
fi
auto_shard_count=0
if [[ "$shard_count" == "auto" ]]; then
  auto_shard_count=1
elif [[ ! "$shard_count" =~ ^[1-9][0-9]*$ ]]; then
  echo "race shard count must be a positive integer: $shard_count" >&2
  exit 2
fi
if [[ "$parallelism" == "auto" ]]; then
  online_cpus="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
  if [[ ! "$online_cpus" =~ ^[1-9][0-9]*$ ]]; then
    echo "race shard runner cannot determine the online CPU count" >&2
    exit 2
  fi
  parallelism="$online_cpus"
  if (( parallelism > 12 )); then
    parallelism=12
  fi
elif [[ ! "$parallelism" =~ ^[1-9][0-9]*$ ]]; then
  echo "race shard parallelism must be a positive integer: $parallelism" >&2
  exit 2
fi
if [[ -n "$worker_gomaxprocs" && ! "$worker_gomaxprocs" =~ ^[1-9][0-9]*$ ]]; then
  echo "race shard worker GOMAXPROCS must be a positive integer: $worker_gomaxprocs" >&2
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
interrupted=0
active_pids=()
active_logs=()
active_done=()
active_count=0
cleanup() {
  local status="$?"
  if (( status == 0 && interrupted == 0 )); then
    rm -rf "$temp_dir"
  else
    echo "race shard logs retained at $temp_dir" >&2
  fi
}
handle_signal() {
  local signal="$1"
  local status=143
  local pid
  interrupted=1
  trap - INT TERM HUP
  case "$signal" in
    INT) status=130 ;;
    HUP) status=129 ;;
  esac
  for pid in "${active_pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "${active_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  exit "$status"
}
trap cleanup EXIT
trap 'handle_signal INT' INT
trap 'handle_signal TERM' TERM
trap 'handle_signal HUP' HUP
tests_file="$temp_dir/tests"
test_binary="$temp_dir/package.test"

(
  cd "$package_dir"
  if [[ "$mode" == "race" ]]; then
    go test -race -c -o "$test_binary" .
  else
    go test -c -o "$test_binary" .
  fi
  "$test_binary" -test.list '^Test'
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

test_count="$(wc -l < "$tests_file" | tr -d ' ')"
if (( auto_shard_count == 1 )); then
  shard_count="$test_count"
fi

# Keep expensive source-level contracts distributed across the bounded worker
# pool without relying on host-specific timing profiles. Function body span is
# a stable, repository-local cost proxy; tests without a source match retain
# their discovery order after the weighted entries.
test_weights="$temp_dir/test-weights"
: > "$test_weights"
for source_file in "$package_dir"/*_test.go; do
  [[ -f "$source_file" ]] || continue
  awk '
    /^[[:space:]]*func[[:space:]]+/ {
      if (name != "") print name, NR - start
      name = ""
      if ($0 ~ /^[[:space:]]*func[[:space:]]+Test[A-Za-z0-9_]*[[:space:]]*\(/) {
        name = $2
        sub(/\(.*/, "", name)
        start = NR
      }
    }
    END {
      if (name != "") print name, NR - start + 1
    }
  ' "$source_file" >> "$test_weights"
done
ordered_tests="$temp_dir/ordered-tests"
awk -v weights_file="$test_weights" '
  FILENAME == weights_file { weight[$1] = $2; next }
  {
    value = weight[$1]
    if (value == "") value = 1
    print value "\t" NR "\t" $0
  }
' "$test_weights" "$tests_file" | sort -k1,1nr -k2,2n | cut -f3- > "$ordered_tests"

awk -v directory="$temp_dir" -v count="$shard_count" '
  {
    shard = (NR - 1) % count
    print > (directory "/shard-" shard)
  }
' "$ordered_tests"

echo "$mode shard runner discovered $test_count tests across $shard_count shards with parallelism $parallelism and worker GOMAXPROCS ${worker_gomaxprocs:-inherited}"

reap_finished_shards() {
  local index
  local shift_index
  while true; do
    for ((index = 0; index < active_count; index++)); do
      if [[ -e "${active_done[$index]}" ]] || ! kill -0 "${active_pids[$index]}" 2>/dev/null; then
        if ! wait "${active_pids[$index]}"; then
          shard_failed=1
        fi
        cat "${active_logs[$index]}"
        for ((shift_index = index; shift_index + 1 < active_count; shift_index++)); do
          active_pids[$shift_index]="${active_pids[$((shift_index + 1))]}"
          active_logs[$shift_index]="${active_logs[$((shift_index + 1))]}"
          active_done[$shift_index]="${active_done[$((shift_index + 1))]}"
        done
        unset 'active_pids[active_count - 1]' 'active_logs[active_count - 1]' 'active_done[active_count - 1]'
        active_count=$((active_count - 1))
        return
      fi
    done
    sleep 0.05
  done
}

shard_failed=0
shard_order=()
while read -r _shard_tests shard; do
  shard_order+=("$shard")
done < <(
  for ((shard = 0; shard < shard_count; shard++)); do
    shard_file="$temp_dir/shard-$shard"
    if [[ -s "$shard_file" ]]; then
      printf '%s %s\n' "$(wc -l < "$shard_file" | tr -d ' ')" "$shard"
    fi
  done | sort -k1,1nr -k2,2n
)
for shard in "${shard_order[@]}"; do
  shard_file="$temp_dir/shard-$shard"
  pattern="$(paste -sd'|' "$shard_file")"
  shard_tests="$(wc -l < "$shard_file" | tr -d ' ')"
  log_file="$temp_dir/shard-$shard.log"
  done_file="$temp_dir/shard-$shard.done"
  (
    trap 'printf "done\n" > "$done_file"' EXIT
    echo "running $mode shard $((shard + 1))/$shard_count with $shard_tests tests"
    cd "$package_dir"
    if [[ -n "$worker_gomaxprocs" ]]; then
      export GOMAXPROCS="$worker_gomaxprocs"
    fi
    "$test_binary" -test.count=1 -test.timeout="$timeout" -test.run "^(${pattern})$"
  ) >"$log_file" 2>&1 &
  active_pids[$active_count]="$!"
  active_logs[$active_count]="$log_file"
  active_done[$active_count]="$done_file"
  active_count=$((active_count + 1))
  if (( active_count >= parallelism )); then
    reap_finished_shards
    if (( shard_failed != 0 )); then
      echo "stopping shard scheduling after the first failure" >&2
      break
    fi
  fi
done
while (( active_count > 0 )); do
  reap_finished_shards
done
exit "$shard_failed"
