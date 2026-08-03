#!/usr/bin/env bash

set -euo pipefail

export LC_ALL=C.UTF-8
export TZ=UTC
export PATH=/usr/local/go/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export GOFLAGS=-mod=readonly
export GOWORK=off
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

usage() {
  echo "usage: transport-v2-release-runner.sh --target <owner|all> --report <absolute-fresh-path>" >&2
  exit 2
}

fail() {
  echo "transport-v2 release runner: $*" >&2
  exit 1
}

target=
report=
while (($# > 0)); do
  case "$1" in
    --target)
      [[ $# -ge 2 && -z $target ]] || usage
      target=$2
      shift 2
      ;;
    --report)
      [[ $# -ge 2 && -z $report ]] || usage
      report=$2
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done
[[ -n $target && -n $report ]] || usage

case "$target" in
  all | transport-conformance-smoke | transport-conformance-full | weaknet-full | weaknet-system | quic-native-smoke | quic-native-proof | quic-native-race | bench-transport-capacity | bench-transport-soak | bench-transport-ab) ;;
  *) fail "unsupported target: $target" ;;
esac

[[ $report == /* ]] || fail "report path must be absolute"
[[ ! -e $report && ! -L $report ]] || fail "report path must be fresh"
report_directory=$(dirname -- "$report")
[[ $(dirname -- "$report_directory") == /evidence && $report_directory != /evidence ]] || fail "report must use one fresh direct child directory under /evidence"
[[ ! -e $report_directory && ! -L $report_directory ]] || fail "report directory must be fresh"
release_owner_uid=${FLOWERSEC_RELEASE_OWNER_UID:-}
release_owner_gid=${FLOWERSEC_RELEASE_OWNER_GID:-}
[[ $release_owner_uid =~ ^[0-9]+$ && $release_owner_gid =~ ^[0-9]+$ ]] || fail "release output owner identity is unavailable"

build_directory=
probe_namespace=
probe_created=0
formal_workload_started=0
readonly bpf_pin_parent=/sys/fs/bpf

network_lab_namespaces() {
  local namespace
  while read -r namespace _; do
    [[ $namespace =~ ^f[csr]-[0-9a-f]{8}$ ]] && printf '%s\n' "$namespace"
  done < <(ip netns list)
}

network_lab_bpf_pins() {
  local path name
  while IFS= read -r path; do
    name=${path##*/}
    [[ $name =~ ^flowersec-fc-[0-9a-f]{8}-fs-[0-9a-f]{8}$ ]] && printf '%s\n' "$path"
  done < <(find "$bpf_pin_parent" -xdev -mindepth 1 -maxdepth 1 -type d -name 'flowersec-fc-????????-fs-????????' -print)
}

cleanup_network_labs() {
  local namespace path
  while IFS= read -r namespace; do
    [[ -n $namespace ]] && ip netns del "$namespace" >/dev/null 2>&1 || true
  done < <(network_lab_namespaces)
  while IFS= read -r path; do
    [[ -d $path && ! -L $path ]] || continue
    find "$path" -xdev -type f -delete >/dev/null 2>&1 || true
    find "$path" -xdev -depth -type d -exec rmdir {} \; >/dev/null 2>&1 || true
  done < <(network_lab_bpf_pins)
}

cleanup() {
  if ((probe_created)); then
    ip netns del "$probe_namespace" >/dev/null 2>&1 || true
  fi
  if ((formal_workload_started)); then
    cleanup_network_labs
  fi
  if [[ $build_directory == /tmp/flowersec-transport-release-build.* && -d $build_directory ]]; then
    rm -rf -- "$build_directory"
  fi
  if [[ -d $report_directory && ! -L $report_directory ]]; then
    chown -R "$release_owner_uid:$release_owner_gid" "$report_directory"
    chmod 0750 "$report_directory"
  fi
  if [[ -n ${formal_lock_file:-} && -f $formal_lock_file && ! -L $formal_lock_file ]] &&
    [[ $(<"$formal_lock_file") == "${formal_lock_owner:-}" ]]; then
    rm -f -- "$formal_lock_file"
  fi
}
trap cleanup EXIT

readonly source_root=/workspace/flowersec
readonly manifest_path=$source_root/testdata/transport_v2/performance_manifest.json
readonly registry_path=$source_root/testdata/transport_v2/case_registry.json
readonly trust_policy_path=$source_root/testdata/transport_v2/evidence_trust_policy.json
readonly effective_config_path=$source_root/testdata/transport_v2/runner_effective_config.json
runner_config_path=${FLOWERSEC_TRANSPORT_RUNNER_CONFIG:-$source_root/.flowersec/transport-runner.json}
readonly bpf_source_path=$source_root/flowersec-go/internal/transportrelease/linuxnetlab/bpf/packet_fault.c
readonly rust_runner_source_path=$source_root/flowersec-rust/examples/transport_release_runner.rs
readonly rust_lock_path=$source_root/flowersec-rust/Cargo.lock
readonly wrapper_source_path=$source_root/scripts/transport-v2-release-runner.sh
readonly host_bpftool=/opt/host-linux-tools/bpftool

[[ $(uname -s) == Linux ]] || fail "runner requires native Linux"
case $(uname -m) in
  x86_64)
    readonly actual_architecture=amd64
    readonly bpf_target_arch=x86
    readonly bpf_system_include=/usr/include/x86_64-linux-gnu
    ;;
  aarch64)
    readonly actual_architecture=arm64
    readonly bpf_target_arch=arm64
    readonly bpf_system_include=/usr/include/aarch64-linux-gnu
    ;;
  *)
    fail "unsupported Linux runner architecture: $(uname -m)"
    ;;
esac
export GOOS=linux GOARCH="$actual_architecture" CGO_ENABLED=0
[[ $(id -u) == 0 ]] || fail "runner requires root inside the dedicated privileged container"
[[ -r /etc/os-release ]] || fail "Ubuntu userspace identity is unavailable"
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail "runner requires the pinned Ubuntu 24.04 userspace"

for path in "$manifest_path" "$registry_path" "$trust_policy_path" "$effective_config_path" "$bpf_source_path" "$rust_runner_source_path" "$rust_lock_path" "$wrapper_source_path"; do
  [[ -f $path && ! -L $path ]] || fail "required source file is missing or is a symlink: $path"
done
actual_wrapper=$(realpath -- "$0")
cmp -s -- "$actual_wrapper" "$wrapper_source_path" || fail "installed wrapper does not match the clean source checkout"

base_sha=${TRANSPORT_V2_BASE_SHA:-}
[[ $base_sha =~ ^[0-9a-f]{40}$ ]] || fail "TRANSPORT_V2_BASE_SHA must be a full lowercase Git SHA"
final_sha=$(git -C "$source_root" rev-parse HEAD)

formal_lock_file=/evidence/.transport-v2-formal.lock
formal_lock_owner=formal-$final_sha
exec 9>"$formal_lock_file"
flock -n 9 || fail "another formal workload owns the runner"
printf '%s\n' "$formal_lock_owner" >"$formal_lock_file"
chmod 0600 "$formal_lock_file"

actual_kernel=$(uname -r)

umask 077
build_directory=$(mktemp -d /tmp/flowersec-transport-release-build.XXXXXX)
export TMPDIR="$build_directory"
base_source_root=$build_directory/base-source

race_low_level_runner=$build_directory/transport-release-runner-race
base_low_level_runner=$build_directory/base-transport-release-runner
bpf_object=$build_directory/packet_fault.o
rust_target_directory=$build_directory/rust-target

prepared_root=${FLOWERSEC_RELEASE_PREPARED_ROOT:-}
if [[ -n $prepared_root ]]; then
  [[ $prepared_root == /* && -d $prepared_root && ! -L $prepared_root ]]
  prepared_metadata=$prepared_root/metadata.json
  low_level_runner=$prepared_root/transport-release-runner
  transportcheck=$prepared_root/transportcheck
  rust_release_runner=$prepared_root/transport-release-runner-rust
  [[ -f $prepared_metadata && ! -L $prepared_metadata && -x $low_level_runner && ! -L $low_level_runner && -x $rust_release_runner && ! -L $rust_release_runner && -x $transportcheck && ! -L $transportcheck ]] || fail "prepared exact-SHA runner is unavailable"
  jq -e --arg sha "$final_sha" '.schema == "flowersec-prepared-runner-v1" and .source_sha == $sha' "$prepared_metadata" >/dev/null || fail "prepared runner metadata drifted"
  [[ $(sha256sum "$low_level_runner" | awk '{print $1}') == "$(jq -r '.runner_sha256' "$prepared_metadata")" ]] || fail "prepared low-level runner digest drifted"
  [[ $(sha256sum "$rust_release_runner" | awk '{print $1}') == "$(jq -r '.rust_runner_sha256' "$prepared_metadata")" ]] || fail "prepared Rust release runner digest drifted"
  [[ $(sha256sum "$transportcheck" | awk '{print $1}') == "$(jq -r '.transportcheck_sha256' "$prepared_metadata")" ]] || fail "prepared transportcheck digest drifted"
else
  low_level_runner=$build_directory/transport-release-runner
  transportcheck=$build_directory/transportcheck
  rust_release_runner=$rust_target_directory/release/examples/transport_release_runner
  (
    cd "$source_root/flowersec-ts"
    npm run build
  )
  (
    cd "$source_root/flowersec-go"
    go build -trimpath -buildvcs=false -o "$low_level_runner" ./internal/cmd/transport-release-runner
  )
  (
    cd "$source_root/tools/transportcheck"
    go build -trimpath -buildvcs=true -o "$transportcheck" .
  )
fi

verify_clean_vcs_stamp() {
  local executable=$1
  local expected_sha=$2
  local metadata revision modified
  metadata=$(go version -m "$executable")
  revision=$(sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.revision=//p' <<<"$metadata")
  modified=$(sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.modified=//p' <<<"$metadata")
  [[ $revision == "$expected_sha" && $modified == false ]] || fail "Go executable lacks the clean expected-SHA VCS stamp: $executable"
}
verify_clean_vcs_stamp "$transportcheck" "$final_sha"

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

expected_toolchain_sha256=$(toolchain_digest)
expected_dist_sha256=$(typescript_dist_digest)
if [[ -n $prepared_root ]]; then
  expected_toolchain_sha256=$(jq -r '.toolchain_sha256' "$prepared_metadata")
  expected_dist_sha256=$(jq -r '.dist_sha256' "$prepared_metadata")
fi

preflight_urls=${FLOWERSEC_RELEASE_PREFLIGHT_URLS:-}
[[ -n $preflight_urls ]] || fail "FLOWERSEC_RELEASE_PREFLIGHT_URLS is required"
preflight_proxy=${FLOWERSEC_RELEASE_PREFLIGHT_PROXY:-}
read -r -a preflight_url_list <<<"$preflight_urls"
preflight_url_args=()
for preflight_url in "${preflight_url_list[@]}"; do
  preflight_url_args+=(-dependency-url "$preflight_url")
done
preflight_directory=/evidence/.runner-preflight/$final_sha
preflight_report=$preflight_directory/$target.json
install -d -o root -g root -m 0700 "$preflight_directory"
set +e
FLOWERSEC_RUNNER_CONTEXT=formal \
FLOWERSEC_RUNNER_CONTEXT_SHA="$final_sha" \
FLOWERSEC_RUNNER_LOCK_OWNER="$formal_lock_owner" \
FLOWERSEC_RUNNER_LAUNCHER_VERIFIED=1 \
HTTP_PROXY="$preflight_proxy" \
HTTPS_PROXY="$preflight_proxy" \
http_proxy="$preflight_proxy" \
https_proxy="$preflight_proxy" \
ALL_PROXY= \
all_proxy= \
NO_PROXY= \
no_proxy= \
timeout --signal=TERM --kill-after=1s 30s "$transportcheck" runner-preflight \
  -mode formal \
  -repo "$source_root" \
  -sha "$final_sha" \
  -base-sha "$base_sha" \
  -runner-config "$runner_config_path" \
  -output "$preflight_report" \
  -artifact-path "$report_directory" \
  -runner-executable "$low_level_runner" \
  -runner-sha256 "$(sha256sum "$low_level_runner" | awk '{print $1}')" \
  -host-bpftool "$host_bpftool" \
  -toolchain-sha256 "$expected_toolchain_sha256" \
  -dist-sha256 "$expected_dist_sha256" \
  -lock-path "$formal_lock_file" \
  -lock-owner "$formal_lock_owner" \
  -cgroup-root /sys/fs/cgroup \
  "${preflight_url_args[@]}"
preflight_result=$?
set -e
if [[ $preflight_result != 0 ]]; then
  if [[ -f $preflight_report && ! -L $preflight_report ]]; then
    preflight_check=$(jq -er '.check_id' "$preflight_report" 2>/dev/null || true)
    preflight_message=$(jq -er '.message' "$preflight_report" 2>/dev/null || true)
    fail "runner-preflight ${preflight_check:-preflight_collection}: ${preflight_message:-missing strict report}"
  fi
  fail "runner-preflight preflight_collection: missing strict report"
fi
jq -e --arg schema "flowersec-runner-preflight-v1" --arg sha "$final_sha" --arg base "$base_sha" \
  '.schema == $schema and .status == "GREEN" and .classification == "none" and .mode == "formal" and
   .source_sha == $sha and .base_sha == $base and .workload_started == false and .check_id == "" and .message == "" and
   (.checks | length > 0 and all(.status == "GREEN"))' "$preflight_report" >/dev/null || fail "runner-preflight report is not strict GREEN"

install -d -o root -g root -m 0700 "$report_directory"

git clone --quiet --no-local --no-checkout "$source_root" "$base_source_root"
git -C "$base_source_root" checkout --quiet --detach "$base_sha"
if [[ -z $prepared_root ]]; then
  (
    cd "$source_root/flowersec-rust"
    CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$rust_target_directory" \
      rustup run 1.88.0 cargo build --locked --release --example transport_release_runner
  )
fi
[[ -f $rust_release_runner && ! -L $rust_release_runner && -x $rust_release_runner ]] || fail "Rust release runner build is unavailable"
(
  cd "$source_root/flowersec-go"
  CGO_ENABLED=1 go build -race -trimpath -buildvcs=false -o "$race_low_level_runner" ./internal/cmd/transport-release-runner
)
(
  cd "$base_source_root/flowersec-go"
  go build -trimpath -buildvcs=false -o "$base_low_level_runner" ./internal/cmd/transport-release-runner
)
clang -O2 -g -Wall -Werror -target bpf \
  -D"__TARGET_ARCH_${bpf_target_arch}" \
  -I"$bpf_system_include" \
  -c "$bpf_source_path" -o "$bpf_object"
[[ -s $bpf_object ]] || fail "packet-fault BPF compilation produced no object"

collect_part() {
  local collect_target=$1
  local collect_report=$2
  local collect_directory=$3
  shift 3
  FLOWERSEC_RUST_RELEASE_RUNNER="$rust_release_runner" "$transportcheck" collect \
    -manifest "$manifest_path" \
    -registry "$registry_path" \
    -repo "$source_root" \
    -base-repo "$base_source_root" \
    -base-sha "$base_sha" \
    -final-sha "$final_sha" \
    -target "$collect_target" \
    -report "$collect_report" \
    -artifact-dir "$collect_directory" \
    -runner-executable "$low_level_runner" \
    -race-runner-executable "$race_low_level_runner" \
    -base-runner-executable "$base_low_level_runner" \
    -runner-wrapper "$actual_wrapper" \
    -bpf-object "$bpf_object" \
    -host-bpftool "$host_bpftool" \
    -trust-policy "$trust_policy_path" \
    -effective-config "$effective_config_path" \
    -runner-config "$runner_config_path" \
    -kernel-release "$actual_kernel" \
    "$@"
}

if [[ $target == bench-transport-capacity ]]; then
  formal_workload_started=1
  readonly capacity_batches="stream-wss stream-quic stream-direct direct-carriers tunnel-matrix webtransport-quic webtransport-wss"
  install -d -o root -g root -m 0700 "$report_directory/parts"
  part_report_args=()
  for batch in $capacity_batches; do
    part_directory=$report_directory/parts/$batch
    part_report=$part_directory/report.partial.json
    install -d -o root -g root -m 0700 "$part_directory"
    collect_part "$target" "$part_report" "$part_directory" -capacity-batch "$batch"
    part_report_args+=(-part-report "$part_report")
  done
  "$transportcheck" merge-capacity \
    -manifest "$manifest_path" \
    -registry "$registry_path" \
    -report "$report" \
    -artifact-dir "$report_directory" \
    "${part_report_args[@]}"
else
  formal_workload_started=1
  collect_part "$target" "$report" "$report_directory"
fi

[[ -z $(network_lab_namespaces) ]] || fail "runner left network namespaces"
[[ -z $(network_lab_bpf_pins) ]] || fail "runner left BPF pins"
