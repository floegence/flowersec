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
install -d -o root -g root -m 0700 "$report_directory"

build_directory=
probe_namespace=
probe_created=0
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
  cleanup_network_labs
  if [[ $build_directory == /tmp/flowersec-transport-release-build.* && -d $build_directory ]]; then
    rm -rf -- "$build_directory"
  fi
  if [[ -d $report_directory && ! -L $report_directory ]]; then
    chown -R "$release_owner_uid:$release_owner_gid" "$report_directory"
    chmod 0750 "$report_directory"
  fi
}
trap cleanup EXIT

readonly source_root=/workspace/flowersec
readonly manifest_path=$source_root/testdata/transport_v2/performance_manifest.json
readonly registry_path=$source_root/testdata/transport_v2/case_registry.json
readonly trust_policy_path=$source_root/testdata/transport_v2/evidence_trust_policy.json
readonly effective_config_path=$source_root/testdata/transport_v2/runner_effective_config.json
readonly bpf_source_path=$source_root/flowersec-go/internal/transportrelease/linuxnetlab/bpf/packet_fault.c
readonly rust_runner_source_path=$source_root/flowersec-rust/examples/transport_release_runner.rs
readonly rust_lock_path=$source_root/flowersec-rust/Cargo.lock
readonly wrapper_source_path=$source_root/scripts/transport-v2-release-runner.sh
readonly host_bpftool=/opt/host-linux-tools/bpftool

[[ $(uname -s) == Linux ]] || fail "runner requires native Linux"
case $(uname -m) in
  x86_64)
    readonly bpf_target_arch=x86
    readonly bpf_system_include=/usr/include/x86_64-linux-gnu
    ;;
  aarch64)
    readonly bpf_target_arch=arm64
    readonly bpf_system_include=/usr/include/aarch64-linux-gnu
    ;;
  *)
    fail "unsupported Linux runner architecture: $(uname -m)"
    ;;
esac
[[ $(id -u) == 0 ]] || fail "runner requires root inside the dedicated privileged container"
[[ -r /etc/os-release ]] || fail "Ubuntu userspace identity is unavailable"
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail "runner requires the pinned Ubuntu 24.04 userspace"

for path in "$manifest_path" "$registry_path" "$trust_policy_path" "$effective_config_path" "$bpf_source_path" "$rust_runner_source_path" "$rust_lock_path" "$wrapper_source_path"; do
  [[ -f $path && ! -L $path ]] || fail "required source file is missing or is a symlink: $path"
done
[[ -x $host_bpftool ]] || fail "exact-host-kernel bpftool is unavailable"
[[ -w /sys/fs/bpf ]] || fail "the privileged container cannot write the host BPF filesystem"
[[ -w /sys/fs/cgroup && -r /sys/fs/cgroup/cgroup.controllers ]] || fail "writable cgroup v2 delegation is unavailable"
[[ -z $(network_lab_namespaces) ]] || fail "runner network namespace state is not fresh"
[[ -z $(network_lab_bpf_pins) ]] || fail "runner BPF pin state is not fresh"

readonly cgroup_supervisor=/sys/fs/cgroup/flowersec-release-supervisor
mkdir -p "$cgroup_supervisor"
readonly required_cgroup_controllers="cpuset cpu memory pids"
for controller in $required_cgroup_controllers; do
  grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || fail "cgroup controller $controller is unavailable"
done

cgroup_controllers_delegated=0
for ((cgroup_attempt = 1; cgroup_attempt <= 100; cgroup_attempt++)); do
  while read -r cgroup_pid; do
    [[ -n $cgroup_pid ]] || continue
    if ! echo "$cgroup_pid" > "$cgroup_supervisor/cgroup.procs"; then
      [[ ! -d /proc/$cgroup_pid ]] || fail "failed to move live process $cgroup_pid into the release supervisor cgroup"
    fi
  done < /sys/fs/cgroup/cgroup.procs

  if [[ ! -s /sys/fs/cgroup/cgroup.procs ]] &&
    echo "+cpuset +cpu +memory +pids" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then
    cgroup_controllers_delegated=1
    break
  fi
  sleep 0.05
done
((cgroup_controllers_delegated)) || fail "could not empty the release cgroup root and delegate controllers within 5 seconds"
for controller in $required_cgroup_controllers; do
  grep -qw "$controller" /sys/fs/cgroup/cgroup.subtree_control || fail "cgroup controller $controller was not delegated"
done

actual_wrapper=$(realpath -- "$0")
cmp -s -- "$actual_wrapper" "$wrapper_source_path" || fail "installed wrapper does not match the clean source checkout"

base_sha=${TRANSPORT_V2_BASE_SHA:-}
[[ $base_sha =~ ^[0-9a-f]{40}$ ]] || fail "TRANSPORT_V2_BASE_SHA must be a full lowercase Git SHA"
[[ $(git -C "$source_root" rev-parse --show-toplevel) == "$source_root" ]] || fail "fixed source root is not the Git checkout root"
final_sha=$(git -C "$source_root" rev-parse HEAD)
[[ $final_sha =~ ^[0-9a-f]{40}$ ]] || fail "source HEAD is not a full Git SHA"
[[ $base_sha != "$final_sha" ]] || fail "base SHA and final SHA must differ"
git -C "$source_root" merge-base --is-ancestor "$base_sha" "$final_sha" || fail "base SHA is not an ancestor of final SHA"
[[ -z $(git -C "$source_root" status --porcelain --untracked-files=all) ]] || fail "source checkout must be clean"

expected_kernel=$(jq -er '.runner.kernel_release | select(type == "string" and length > 0)' "$trust_policy_path")
actual_kernel=$(uname -r)
[[ $actual_kernel == "$expected_kernel" ]] || fail "host kernel $actual_kernel does not match frozen policy $expected_kernel"

umask 077
build_directory=$(mktemp -d /tmp/flowersec-transport-release-build.XXXXXX)
base_source_root=$build_directory/base-source
probe_namespace=flowersec-release-probe-$$

ip netns add "$probe_namespace"
probe_created=1
ip netns exec "$probe_namespace" ip link set lo up
ip netns del "$probe_namespace"
probe_created=0

low_level_runner=$build_directory/transport-release-runner
race_low_level_runner=$build_directory/transport-release-runner-race
base_low_level_runner=$build_directory/base-transport-release-runner
transportcheck=$build_directory/transportcheck
bpf_object=$build_directory/packet_fault.o
rust_target_directory=$build_directory/rust-target
rust_release_runner=$rust_target_directory/release/examples/transport_release_runner

git clone --quiet --no-local --no-checkout "$source_root" "$base_source_root"
git -C "$base_source_root" checkout --quiet --detach "$base_sha"
[[ $(git -C "$base_source_root" rev-parse --show-toplevel) == "$base_source_root" ]] || fail "base source root is not an independent Git checkout"
[[ $(git -C "$base_source_root" rev-parse HEAD) == "$base_sha" ]] || fail "base source checkout does not match TRANSPORT_V2_BASE_SHA"
[[ -z $(git -C "$base_source_root" status --porcelain --untracked-files=all) ]] || fail "base source checkout must be clean"
base_manifest_path=$base_source_root/testdata/transport_v2/performance_manifest.json
[[ -f $base_manifest_path && ! -L $base_manifest_path ]] || fail "base performance manifest is unavailable"
cmp -s -- "$manifest_path" "$base_manifest_path" || fail "base and final performance manifests must be byte-identical"

(
  cd "$source_root/flowersec-ts"
  npm run build
)
(
  cd "$source_root/flowersec-go"
  go build -trimpath -buildvcs=false -o "$low_level_runner" ./internal/cmd/transport-release-runner
)
(
  cd "$source_root/flowersec-rust"
  CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$rust_target_directory" \
    cargo build --locked --release --example transport_release_runner
)
[[ -f $rust_release_runner && ! -L $rust_release_runner && -x $rust_release_runner ]] || fail "Rust release runner build is unavailable"
(
  cd "$source_root/flowersec-go"
  go build -race -trimpath -buildvcs=false -o "$race_low_level_runner" ./internal/cmd/transport-release-runner
)
(
  cd "$base_source_root/flowersec-go"
  go build -trimpath -buildvcs=false -o "$base_low_level_runner" ./internal/cmd/transport-release-runner
)
(
  cd "$source_root/tools/transportcheck"
  go build -trimpath -buildvcs=true -o "$transportcheck" .
)

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

clang -O2 -g -Wall -Werror -target bpf \
  -D"__TARGET_ARCH_${bpf_target_arch}" \
  -I"$bpf_system_include" \
  -c "$bpf_source_path" -o "$bpf_object"
[[ -s $bpf_object ]] || fail "packet-fault BPF compilation produced no object"
[[ -z $(git -C "$source_root" status --porcelain --untracked-files=all) ]] || fail "runner build changed the source checkout"
[[ -z $(git -C "$base_source_root" status --porcelain --untracked-files=all) ]] || fail "runner build changed the base source checkout"

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
    -kernel-release "$actual_kernel" \
    "$@"
}

if [[ $target == bench-transport-capacity ]]; then
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
  collect_part "$target" "$report" "$report_directory"
fi

[[ -z $(network_lab_namespaces) ]] || fail "runner left network namespaces"
[[ -z $(network_lab_bpf_pins) ]] || fail "runner left BPF pins"
