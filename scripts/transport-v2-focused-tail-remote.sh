#!/usr/bin/env bash

set -euo pipefail
umask 077
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

action=${1:-}
case "$action" in
  hold-lock|prepare|recover-receipt|preflight|run-shard) ;;
  *) printf 'focused-tail remote agent: unsupported action\n' >&2; exit 10 ;;
esac

IFS= read -r request
[[ -n $request ]] || { printf 'focused-tail remote agent: missing JSON request\n' >&2; exit 10; }
jq -e '
  type == "object" and
  (keys | sort) == (["artifact_root","cache_root","cell","prepared","schema_version","shard","source_root","source_sha"] | sort) and
  .schema_version == 1 and
  (.source_sha | test("^[0-9a-f]{40}$")) and
  (.cell | type == "object") and
  (.cell | keys | sort) == (["id","profile","runner_target","topology"] | sort) and
  (.cell.id | test("^[a-z0-9][a-z0-9._-]{0,95}$")) and
  .cell.runner_target == "browser-webtransport-cell" and
  (.cell.profile | test("^[a-z0-9][a-z0-9._-]{0,95}$")) and
  (.cell.topology | test("^[a-z0-9][a-z0-9._-]{0,95}$")) and
  (.source_root | test("^/[A-Za-z0-9._/-]{1,511}$")) and
  (.artifact_root | test("^/[A-Za-z0-9._/-]{1,511}$")) and
  (.cache_root | test("^/[A-Za-z0-9._/-]{1,511}$")) and
  (.shard | type == "number" and floor == . and . >= 0 and . <= 5)
' >/dev/null <<<"$request" || { printf 'focused-tail remote agent: invalid JSON request\n' >&2; exit 10; }

source_sha=$(jq -r '.source_sha' <<<"$request")
source_root=$(jq -r '.source_root' <<<"$request")
artifact_root=$(jq -r '.artifact_root' <<<"$request")
cache_root=$(jq -r '.cache_root' <<<"$request")
cell=$(jq -r '.cell.id' <<<"$request")
profile=$(jq -r '.cell.profile' <<<"$request")
topology=$(jq -r '.cell.topology' <<<"$request")
shard=$(jq -r '.shard' <<<"$request")
receipt_root=$artifact_root/.focused-tail-receipts/$source_sha/$cell
lock_file=$artifact_root/.focused-tail.lock
lock_owner=focused-$source_sha-$cell

fail() {
  printf 'focused-tail remote agent: %s\n' "$*" >&2
  exit 20
}

require_exact_source() {
  [[ -d $source_root && ! -L $source_root ]] || fail "source root is not a real directory"
  [[ $(git -C "$source_root" rev-parse HEAD) == "$source_sha" ]] || fail "source SHA mismatch"
  [[ -z $(git -C "$source_root" status --porcelain=v1 --untracked-files=all) ]] || fail "source checkout is dirty"
}

require_real_directory() {
  local path
  for path in "$@"; do
    [[ -d $path && ! -L $path ]] || fail "required directory is missing or a symlink: $path"
  done
}

toolchain_digest() {
  local material
  material=$(cd "$source_root" && printf '%s\n' \
    "$(go version)" \
    "$(go env GOOS GOARCH CGO_ENABLED)" \
    "$(node --version)" \
    "$(sha256sum flowersec-go/go.mod flowersec-go/go.sum flowersec-ts/package-lock.json)")
  printf '%s' "$material" | sha256sum | awk '{print $1}'
}

typescript_dist_digest() {
  (cd "$source_root/flowersec-ts" && find dist -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
}

validate_prepared() {
  local prepared_sha prepared_runner prepared_runner_sha prepared_preflight prepared_preflight_sha prepared_toolchain prepared_dist
  prepared_sha=$(jq -r '.prepared.source_sha // ""' <<<"$request")
  prepared_runner=$(jq -r '.prepared.runner_path // ""' <<<"$request")
  prepared_runner_sha=$(jq -r '.prepared.runner_sha256 // ""' <<<"$request")
  prepared_preflight=$(jq -r '.prepared.preflight_path // ""' <<<"$request")
  prepared_preflight_sha=$(jq -r '.prepared.preflight_sha256 // ""' <<<"$request")
  prepared_toolchain=$(jq -r '.prepared.toolchain_sha256 // ""' <<<"$request")
  prepared_dist=$(jq -r '.prepared.typescript_dist_sha256 // ""' <<<"$request")
  [[ $prepared_sha == "$source_sha" ]] || fail "prepared source SHA mismatch"
  [[ $prepared_runner =~ ^/[A-Za-z0-9._/-]{1,511}$ && -x $prepared_runner && ! -L $prepared_runner ]] || fail "prepared runner is unavailable"
  [[ $prepared_runner_sha =~ ^[0-9a-f]{64}$ && $(sha256sum "$prepared_runner" | awk '{print $1}') == "$prepared_runner_sha" ]] || fail "prepared runner digest mismatch"
  [[ $prepared_preflight =~ ^/[A-Za-z0-9._/-]{1,511}$ && -x $prepared_preflight && ! -L $prepared_preflight ]] || fail "prepared preflight is unavailable"
  [[ $prepared_preflight_sha =~ ^[0-9a-f]{64}$ && $(sha256sum "$prepared_preflight" | awk '{print $1}') == "$prepared_preflight_sha" ]] || fail "prepared preflight digest mismatch"
  [[ $prepared_toolchain =~ ^[0-9a-f]{64}$ && $(toolchain_digest) == "$prepared_toolchain" ]] || fail "prepared toolchain digest mismatch"
  [[ $prepared_dist =~ ^[0-9a-f]{64}$ && $(typescript_dist_digest) == "$prepared_dist" ]] || fail "prepared TypeScript dist digest mismatch"
}

if [[ $action == hold-lock ]]; then
  install -d -m 0700 "$artifact_root"
  exec 9>"$lock_file"
  flock -n 9 || fail "another focused-tail job owns the remote runner"
  printf '%s\n' "$lock_owner" >"$lock_file"
  chmod 0600 "$lock_file"
  printf '{"status":"LOCKED"}\n'
  exec sleep 86400
fi

if [[ $action == prepare ]]; then
  require_exact_source
  install -d -m 0700 "$cache_root"
  require_real_directory "$cache_root" "$source_root"
  current_toolchain=$(toolchain_digest)
  runner=$cache_root/$source_sha-$current_toolchain-transport-release-runner
  preflight_runner=$cache_root/$source_sha-$current_toolchain-transportcheck
  runner_digest_file=$runner.sha256
  if [[ -e $runner || -e $runner_digest_file ]]; then
    [[ -x $runner && ! -L $runner && -f $runner_digest_file && ! -L $runner_digest_file ]] || fail "cached runner shape is invalid"
    expected_runner=$(<"$runner_digest_file")
    [[ $expected_runner =~ ^[0-9a-f]{64}$ && $(sha256sum "$runner" | awk '{print $1}') == "$expected_runner" ]] || fail "cached runner digest drifted"
  else
    temporary_runner=$(mktemp "$cache_root/.focused-runner.XXXXXX")
    trap 'rm -f -- "$temporary_runner" "$temporary_runner.sha256"' EXIT INT TERM
    (cd "$source_root/flowersec-go" && CGO_ENABLED=1 go build -trimpath -buildvcs=false -o "$temporary_runner" ./internal/cmd/transport-release-runner)
    chmod 0700 "$temporary_runner"
    expected_runner=$(sha256sum "$temporary_runner" | awk '{print $1}')
    printf '%s\n' "$expected_runner" >"$temporary_runner.sha256"
    chmod 0600 "$temporary_runner.sha256"
    sync -f "$temporary_runner"
    sync -f "$temporary_runner.sha256"
    mv "$temporary_runner" "$runner"
    mv "$temporary_runner.sha256" "$runner_digest_file"
    trap - EXIT INT TERM
  fi
  preflight_digest_file=$preflight_runner.sha256
  if [[ -e $preflight_runner || -e $preflight_digest_file ]]; then
    [[ -x $preflight_runner && ! -L $preflight_runner && -f $preflight_digest_file && ! -L $preflight_digest_file ]] || fail "cached preflight shape is invalid"
    expected_preflight=$(<"$preflight_digest_file")
    [[ $expected_preflight =~ ^[0-9a-f]{64}$ && $(sha256sum "$preflight_runner" | awk '{print $1}') == "$expected_preflight" ]] || fail "cached preflight digest drifted"
  else
    temporary_preflight=$(mktemp "$cache_root/.focused-preflight.XXXXXX")
    trap 'rm -f -- "$temporary_preflight" "$temporary_preflight.sha256"' EXIT INT TERM
    (cd "$source_root/tools/transportcheck" && go build -trimpath -buildvcs=true -o "$temporary_preflight" .)
    chmod 0700 "$temporary_preflight"
    expected_preflight=$(sha256sum "$temporary_preflight" | awk '{print $1}')
    printf '%s\n' "$expected_preflight" >"$temporary_preflight.sha256"
    chmod 0600 "$temporary_preflight.sha256"
    sync -f "$temporary_preflight"
    sync -f "$temporary_preflight.sha256"
    mv "$temporary_preflight" "$preflight_runner"
    mv "$temporary_preflight.sha256" "$preflight_digest_file"
    trap - EXIT INT TERM
  fi
  (cd "$source_root/flowersec-ts" && npm run build >/dev/null)
  dist_digest=$(typescript_dist_digest)
  require_exact_source
  jq -n \
    --arg source_sha "$source_sha" \
    --arg runner_path "$runner" \
    --arg runner_sha256 "$expected_runner" \
    --arg preflight_path "$preflight_runner" \
    --arg preflight_sha256 "$expected_preflight" \
    --arg toolchain_sha256 "$current_toolchain" \
    --arg typescript_dist_sha256 "$dist_digest" \
    '{source_sha:$source_sha,runner_path:$runner_path,runner_sha256:$runner_sha256,preflight_path:$preflight_path,preflight_sha256:$preflight_sha256,toolchain_sha256:$toolchain_sha256,typescript_dist_sha256:$typescript_dist_sha256}'
  exit 0
fi

printf -v shard_label '%02d' "$shard"
receipt_path=$receipt_root/shard-$shard_label.receipt.json
output_root=$artifact_root/focused-$source_sha-$cell-shard-$shard_label
[[ $shard =~ ^[1-5]$ ]] || fail "shard must be 1-5"

cleanup_success_scratch() {
  local expected_closure expected_stream actual_closure actual_stream
  [[ -d $output_root && ! -L $output_root ]] || { [[ ! -e $output_root ]] || fail "successful scratch shape is invalid"; return; }
  [[ -f $receipt_path && ! -L $receipt_path ]] || fail "successful scratch cannot be deleted without its receipt"
  expected_closure=$(jq -er '.closure_manifest_sha256 | select(test("^[0-9a-f]{64}$"))' "$receipt_path") || fail "receipt closure digest is invalid"
  expected_stream=$(jq -er '.deleted_content_stream_sha256 | select(test("^[0-9a-f]{64}$"))' "$receipt_path") || fail "receipt content-stream digest is invalid"
  [[ -f $output_root/SHA256SUMS && ! -L $output_root/SHA256SUMS ]] || fail "successful scratch closure manifest is unavailable"
  actual_closure=$(sha256sum "$output_root/SHA256SUMS" | awk '{print $1}')
  [[ $actual_closure == "$expected_closure" ]] || fail "successful scratch closure digest mismatch; refusing deletion"
  (cd "$output_root" && sha256sum -c SHA256SUMS >/dev/null) || fail "successful scratch file digest mismatch; refusing deletion"
  actual_stream=$(tar -C "$artifact_root" -cf - "$(basename "$output_root")" | sha256sum | awk '{print $1}')
  [[ $actual_stream == "$expected_stream" ]] || fail "successful scratch content-stream digest mismatch; refusing deletion"
  find "$output_root" -depth -delete
  [[ ! -e $output_root ]] || fail "successful scratch cleanup failed"
}

emit_failure_artifact() {
  local message=$1
  local failure_archive=$receipt_root/shard-$shard_label-product-failure.tar.gz
  local failure_checksum=$failure_archive.sha256
  local scratch_stream archive_stream failure_digest temporary_archive temporary_checksum
  install -d -m 0700 "$receipt_root"
  require_real_directory "$artifact_root" "$receipt_root"
  if [[ -d $output_root && ! -L $output_root ]]; then
    scratch_stream=$(tar -C "$artifact_root" -cf - "$(basename "$output_root")" | sha256sum | awk '{print $1}')
    if [[ ! -e $failure_archive && ! -L $failure_archive && ! -e $failure_checksum && ! -L $failure_checksum ]]; then
      temporary_archive=$(mktemp "$receipt_root/.shard-$shard_label-failure.XXXXXX.tar.gz")
      temporary_checksum=$(mktemp "$receipt_root/.shard-$shard_label-failure.XXXXXX.sha256")
      trap 'rm -f -- "$temporary_archive" "$temporary_checksum"' EXIT INT TERM
      tar -C "$artifact_root" -czf "$temporary_archive" "$(basename "$output_root")"
      gzip -t "$temporary_archive"
      failure_digest=$(sha256sum "$temporary_archive" | awk '{print $1}')
      printf '%s  %s\n' "$failure_digest" "$(basename "$failure_archive")" >"$temporary_checksum"
      chmod 0600 "$temporary_archive" "$temporary_checksum"
      sync -f "$temporary_archive"
      sync -f "$temporary_checksum"
      mv "$temporary_archive" "$failure_archive"
      mv "$temporary_checksum" "$failure_checksum"
      sync -f "$receipt_root"
      trap - EXIT INT TERM
    elif [[ -f $failure_archive && ! -L $failure_archive && ! -e $failure_checksum && ! -L $failure_checksum ]]; then
      gzip -t "$failure_archive"
      archive_stream=$(gzip -dc "$failure_archive" | sha256sum | awk '{print $1}')
      [[ $archive_stream == "$scratch_stream" ]] || fail "partial failure artifact content mismatch; refusing recovery"
      failure_digest=$(sha256sum "$failure_archive" | awk '{print $1}')
      temporary_checksum=$(mktemp "$receipt_root/.shard-$shard_label-failure.XXXXXX.sha256")
      trap 'rm -f -- "$temporary_checksum"' EXIT INT TERM
      printf '%s  %s\n' "$failure_digest" "$(basename "$failure_archive")" >"$temporary_checksum"
      chmod 0600 "$temporary_checksum"
      sync -f "$temporary_checksum"
      mv "$temporary_checksum" "$failure_checksum"
      sync -f "$receipt_root"
      trap - EXIT INT TERM
    fi
    [[ -f $failure_archive && ! -L $failure_archive && -f $failure_checksum && ! -L $failure_checksum ]] || fail "failure artifact shape is invalid; refusing scratch deletion"
    (cd "$receipt_root" && sha256sum -c "$(basename "$failure_checksum")" >/dev/null) || fail "failure artifact checksum mismatch; refusing scratch deletion"
    archive_stream=$(gzip -dc "$failure_archive" | sha256sum | awk '{print $1}')
    [[ $archive_stream == "$scratch_stream" ]] || fail "failure artifact content mismatch; refusing scratch deletion"
    find "$output_root" -depth -delete
    [[ ! -e $output_root ]] || fail "failure scratch cleanup failed"
    find "$receipt_root" -maxdepth 1 -type f -name ".shard-$shard_label-failure.*" -delete
  fi
  [[ -f $failure_archive && ! -L $failure_archive && -f $failure_checksum && ! -L $failure_checksum ]] || fail "failure artifact is unavailable"
  (cd "$receipt_root" && sha256sum -c "$(basename "$failure_checksum")" >/dev/null) || fail "failure artifact checksum mismatch"
  failure_digest=$(sha256sum "$failure_archive" | awk '{print $1}')
  jq -n --arg message "$message" --arg path "$failure_archive" --arg digest "$failure_digest" \
    '{receipt:null,failure:{classification:"product",workload_started:true,message:$message,diagnostic_path:$path,diagnostic_sha256:$digest}}'
}

if [[ $action == recover-receipt ]]; then
  if [[ -f $receipt_path && ! -L $receipt_path ]]; then
    require_exact_source
    validate_prepared
    require_real_directory "$artifact_root"
    prepared_runner_sha=$(jq -r '.prepared.runner_sha256' <<<"$request")
    prepared_toolchain=$(jq -r '.prepared.toolchain_sha256' <<<"$request")
    prepared_dist=$(jq -r '.prepared.typescript_dist_sha256' <<<"$request")
    jq -e \
      --arg schema "flowersec-focused-success-receipt-v1" --arg sha "$source_sha" --arg cell "$cell" \
      --arg runner "$prepared_runner_sha" --arg toolchain "$prepared_toolchain" --arg dist "$prepared_dist" --argjson shard "$shard" \
      '.schema == $schema and .source_sha == $sha and .cell_id == $cell and .shard == $shard and .shard_count == 5 and .result == "GREEN" and
       .runner_sha256 == $runner and .toolchain_sha256 == $toolchain and .typescript_dist_sha256 == $dist and
       (.report_sha256 | test("^[0-9a-f]{64}$")) and (.closure_manifest_sha256 | test("^[0-9a-f]{64}$")) and
       (.deleted_content_stream_sha256 | test("^[0-9a-f]{64}$")) and
       .residual_processes == 0 and .residual_cgroups == 0 and .residual_namespaces == 0' \
      "$receipt_path" >/dev/null || fail "receipt does not bind the exact prepared shard; refusing recovery cleanup"
    cleanup_success_scratch
    jq -n --slurpfile receipt "$receipt_path" '{receipt:$receipt[0],failure:null}'
  elif [[ -e $output_root || -e $receipt_root/shard-$shard_label-product-failure.tar.gz ]]; then
    emit_failure_artifact "recovered an interrupted shard without an exact-SHA GREEN receipt"
  else
    printf '{"receipt":null,"failure":null}\n'
  fi
  exit 0
fi

require_exact_source
validate_prepared
install -d -m 0700 "$artifact_root" "$cache_root"
require_real_directory "$artifact_root" "$cache_root"

runner=$(jq -r '.prepared.runner_path' <<<"$request")
runner_sha=$(jq -r '.prepared.runner_sha256' <<<"$request")
prepared_toolchain=$(jq -r '.prepared.toolchain_sha256' <<<"$request")
prepared_dist=$(jq -r '.prepared.typescript_dist_sha256' <<<"$request")
cgroup_root=/sys/fs/cgroup/flowersec-focused-$source_sha-$cell-shard-$shard_label
lane=$cgroup_root/lane-0
workload=$lane/workload
supervisor=/sys/fs/cgroup/flowersec-release-supervisor

cleanup() {
  if [[ -d $lane ]] && grep -q 'populated 1' "$lane/cgroup.events" 2>/dev/null; then
    printf '1' >"$lane/cgroup.kill" 2>/dev/null || true
  fi
  for _ in $(seq 1 100); do
    if find "$cgroup_root" -depth -type d -exec rmdir {} \; 2>/dev/null; then return; fi
    sleep 0.05
  done
}
trap cleanup EXIT INT TERM

setup_lane() {
  local delegated pid
  mkdir -p "$supervisor"
  delegated=0
  for _ in $(seq 1 100); do
    while read -r pid; do
      [[ -n $pid ]] || continue
      if ! printf '%s' "$pid" >"$supervisor/cgroup.procs"; then [[ ! -d /proc/$pid ]] || fail "cannot move live root process"; fi
    done </sys/fs/cgroup/cgroup.procs
    if [[ ! -s /sys/fs/cgroup/cgroup.procs ]] && printf '+cpuset +cpu +memory +pids' >/sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then delegated=1; break; fi
    sleep 0.05
  done
  [[ $delegated == 1 ]] || fail "could not delegate cgroup controllers"

  mkdir "$cgroup_root"
  printf '0,1,2,3' >"$cgroup_root/cpuset.cpus"
  printf '0' >"$cgroup_root/cpuset.mems"
  printf '+cpuset +cpu +memory +pids' >"$cgroup_root/cgroup.subtree_control"
  mkdir "$lane"
  printf '0,1,2,3' >"$lane/cpuset.cpus"
  printf '0' >"$lane/cpuset.mems"
  printf '400000 100000' >"$lane/cpu.max"
  printf '3221225472' >"$lane/memory.high"
  printf '3221225472' >"$lane/memory.max"
  printf '0' >"$lane/memory.swap.max"
  printf '1' >"$lane/memory.oom.group"
  printf '8192' >"$lane/pids.max"
  [[ $(cat "$lane/memory.swap.current") == 0 ]] || fail "isolated lane is using swap"
  printf '+cpuset +cpu +memory +pids' >"$lane/cgroup.subtree_control"
  mkdir "$workload"
}

preflight_report=$receipt_root/shard-$shard_label.preflight.json
run_unified_preflight() {
  local preflight_runner runner_config
  preflight_runner=$(jq -r '.prepared.preflight_path' <<<"$request")
  runner_config=$source_root/.flowersec/transport-runner.json
  install -d -m 0700 "$receipt_root"
  env \
    FLOWERSEC_RUNNER_CONTEXT=focused \
    FLOWERSEC_RUNNER_CONTEXT_SHA="$source_sha" \
    FLOWERSEC_RUNNER_LOCK_OWNER="$lock_owner" \
    FLOWERSEC_RUNNER_LAUNCHER_VERIFIED=1 \
    FLOWERSEC_RUNNER_LAUNCHER_RUNTIME=lxc \
    FLOWERSEC_RUNNER_REACHABILITY_VERIFIED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright \
    FLOWERSEC_WORKLOAD_CGROUP="$workload" \
    /bin/sh -c 'printf "%s\n" "$$" >"$FLOWERSEC_WORKLOAD_CGROUP/cgroup.procs" && exec "$@"' \
    flowersec-preflight timeout --signal=TERM --kill-after=1s 30s "$preflight_runner" runner-preflight \
      -mode focused \
      -repo "$source_root" \
      -sha "$source_sha" \
      -runner-config "$runner_config" \
      -output "$preflight_report" \
      -artifact-path "$output_root" \
      -runner-executable "$(jq -r '.prepared.runner_path' <<<"$request")" \
      -runner-sha256 "$(jq -r '.prepared.runner_sha256' <<<"$request")" \
      -toolchain-sha256 "$(jq -r '.prepared.toolchain_sha256' <<<"$request")" \
      -dist-sha256 "$(jq -r '.prepared.typescript_dist_sha256' <<<"$request")" \
      -lock-path "$lock_file" \
      -lock-owner "$lock_owner" \
      -cgroup-root "$lane"
}

set +e
setup_output=$(setup_lane 2>&1)
setup_result=$?
set -e
if [[ $setup_result != 0 ]]; then
  cleanup
  trap - EXIT INT TERM
  jq -n --arg message "$setup_output" \
    '{receipt:null,failure:{classification:"environment",workload_started:false,message:$message}}'
  exit 0
fi

if [[ $action == preflight ]]; then
  set +e
  run_unified_preflight >/dev/null 2>&1
  preflight_result=$?
  set -e
  cleanup
  trap - EXIT INT TERM
  if [[ -f $preflight_report && ! -L $preflight_report ]]; then
    cat "$preflight_report"
    exit 0
  fi
  jq -n --arg message "unified preflight did not produce a report (exit=$preflight_result)" \
    --arg mode "focused" --arg sha "$source_sha" \
    '{schema:"flowersec-runner-preflight-v1",status:"RED",classification:"environment",mode:$mode,source_sha:$sha,base_sha:"",workload_started:false,duration_ms:0,check_id:"preflight_collection",message:$message,checks:[{check_id:"preflight_collection",status:"RED",classification:"environment",message:$message,actual:"missing report",expected:"atomic report"}]}'
  exit 0
fi

jq -e --arg schema "flowersec-runner-preflight-v1" --arg sha "$source_sha" \
  '.schema == $schema and .status == "GREEN" and .classification == "none" and .mode == "focused" and
   .source_sha == $sha and .base_sha == "" and .workload_started == false and .check_id == "" and .message == "" and
   (.checks | length > 0 and all(.status == "GREEN"))' "$preflight_report" >/dev/null || fail "exact-SHA unified preflight receipt is unavailable"

install -d -m 0700 "$output_root/artifacts"
date -Is >"$output_root/started-at.txt"

first_run=$(( (shard - 1) * 3 + 1 ))
set +e
timeout --signal=INT --kill-after=20s 295s \
  env FLOWERSEC_LANE_CGROUP="$lane" GOMAXPROCS=4 PLAYWRIGHT_BROWSERS_PATH=/root/.cache/ms-playwright \
  /bin/sh -c 'printf "%s\n" "$$" >"$FLOWERSEC_LANE_CGROUP/workload/cgroup.procs" && exec tini -s -- "$@"' \
  flowersec-lane "$runner" \
  --target browser-webtransport-cell \
  --manifest "$source_root/testdata/transport_v2/performance_manifest.json" \
  --report "$output_root/cell.json" \
  --artifact-dir "$output_root/artifacts" \
  --source-sha "$source_sha" \
  --source-root "$source_root" \
  --profile "$profile" \
  --topology "$topology" \
  --run-shard "$shard" \
  >"$output_root/stdout.log" 2>"$output_root/stderr.log"
result=$?
set -e
date -Is >"$output_root/finished-at.txt"
printf '%s\n' "$result" >"$output_root/exit-code.txt"
cleanup
trap - EXIT INT TERM

post_active=$(ps -eo state=,comm= | awk '$1 !~ /^Z/ && ($2 ~ /transport-release/ || $2 ~ /chrome|chromium/) {n++} END{print n+0}')
post_zombies=$(ps -eo state= | awk '$1 ~ /^Z/ {n++} END{print n+0}')
post_netns=$(ip netns list | awk '$1 ~ /^fc-/ || $1 ~ /^fs-/ {n++} END{print n+0}')
post_cgroup=0
[[ ! -e $cgroup_root ]] || post_cgroup=1
report_valid=0
if [[ $result == 0 && $post_active == 0 && $post_zombies == 0 && $post_netns == 0 && $post_cgroup == 0 ]] && jq -e \
  --arg sha "$source_sha" --argjson shard "$shard" --argjson first "$first_run" \
  '.source_sha == $sha and .shard_index == $shard and
   ([.results[].run] == [$first, ($first + 1), ($first + 2)]) and
   ([.results[].workload.status] | all(. == "passed")) and
   ([.results[].workload.browser.version] | all(. == "151.0.7922.34")) and
   ([.results[].workload.browser.diagnostics] | all(length == 0)) and
   ([.results[].workload.spend_count] | all(. == 101)) and
   ([.results[].workload.cold | length] | all(. == 100)) and
   ([.results[].workload.rpc | length] | all(. == 100)) and
   ([.results[].workload.bulk.bytes_per_direction] | all(. == 8388608))' \
  "$output_root/cell.json" >/dev/null; then
  report_valid=1
fi

if [[ $result != 0 || $post_active != 0 || $post_zombies != 0 || $post_netns != 0 || $post_cgroup != 0 || $report_valid != 1 ]]; then
  emit_failure_artifact "workload, report identity, or zero-residual assertion failed with exit $result"
  exit 0
fi

(cd "$output_root" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
report_sha=$(sha256sum "$output_root/cell.json" | awk '{print $1}')
closure_sha=$(sha256sum "$output_root/SHA256SUMS" | awk '{print $1}')
deleted_stream_sha=$(tar -C "$artifact_root" -cf - "$(basename "$output_root")" | sha256sum | awk '{print $1}')
started_at=$(<"$output_root/started-at.txt")
finished_at=$(<"$output_root/finished-at.txt")
install -d -m 0700 "$receipt_root"
temporary_receipt=$(mktemp "$receipt_root/.receipt.XXXXXX")
trap 'rm -f -- "$temporary_receipt"' EXIT INT TERM
jq -n \
  --arg schema "flowersec-focused-success-receipt-v1" \
  --arg source_sha "$source_sha" --arg cell_id "$cell" --arg result GREEN \
  --arg runner_sha256 "$runner_sha" --arg toolchain_sha256 "$prepared_toolchain" --arg typescript_dist_sha256 "$prepared_dist" \
  --arg report_sha256 "$report_sha" --arg closure_manifest_sha256 "$closure_sha" --arg deleted_content_stream_sha256 "$deleted_stream_sha" \
  --arg started_at "$started_at" --arg finished_at "$finished_at" \
  --arg summary "three frozen runs completed 100 cold, 100 RPC, 8 MiB bulk, 101 spends, empty diagnostics, and zero residual" \
  --argjson shard "$shard" --argjson shard_count 5 \
  '{schema:$schema,source_sha:$source_sha,cell_id:$cell_id,shard:$shard,shard_count:$shard_count,result:$result,
    runner_sha256:$runner_sha256,toolchain_sha256:$toolchain_sha256,typescript_dist_sha256:$typescript_dist_sha256,
    report_sha256:$report_sha256,closure_manifest_sha256:$closure_manifest_sha256,deleted_content_stream_sha256:$deleted_content_stream_sha256,
    started_at:$started_at,finished_at:$finished_at,summary:$summary,residual_processes:0,residual_cgroups:0,residual_namespaces:0}' >"$temporary_receipt"
chmod 0600 "$temporary_receipt"
sync -f "$temporary_receipt"
[[ ! -e $receipt_path ]] || fail "receipt path already exists"
mv "$temporary_receipt" "$receipt_path"
sync -f "$receipt_root"
trap - EXIT INT TERM
cleanup_success_scratch
jq -n --slurpfile receipt "$receipt_path" '{receipt:$receipt[0],failure:null}'
