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
  all | transport-conformance-full | weaknet-full | weaknet-system | quic-native-proof | quic-native-race | bench-transport-capacity | bench-transport-soak | bench-transport-ab) ;;
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
cleanup() {
  if ((probe_created)); then
    ip netns del "$probe_namespace" >/dev/null 2>&1 || true
  fi
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
readonly wrapper_source_path=$source_root/scripts/transport-v2-release-runner.sh
readonly host_bpftool=/opt/host-linux-tools/bpftool

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail "runner requires native Linux amd64"
[[ $(id -u) == 0 ]] || fail "runner requires root inside the dedicated privileged container"
[[ -r /etc/os-release ]] || fail "Ubuntu userspace identity is unavailable"
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail "runner requires the pinned Ubuntu 24.04 userspace"

for path in "$manifest_path" "$registry_path" "$trust_policy_path" "$effective_config_path" "$bpf_source_path" "$wrapper_source_path"; do
  [[ -f $path && ! -L $path ]] || fail "required source file is missing or is a symlink: $path"
done
[[ -x $host_bpftool ]] || fail "exact-host-kernel bpftool is unavailable"
[[ -w /sys/fs/bpf ]] || fail "the privileged container cannot write the host BPF filesystem"

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
probe_namespace=flowersec-release-probe-$$

ip netns add "$probe_namespace"
probe_created=1
ip netns exec "$probe_namespace" ip link set lo up
ip netns del "$probe_namespace"
probe_created=0

low_level_runner=$build_directory/transport-release-runner
transportcheck=$build_directory/transportcheck
bpf_object=$build_directory/packet_fault.o

(
  cd "$source_root/flowersec-go"
  go build -trimpath -buildvcs=true -o "$low_level_runner" ./internal/cmd/transport-release-runner
)
(
  cd "$source_root/tools/transportcheck"
  go build -trimpath -buildvcs=true -o "$transportcheck" .
)

verify_clean_vcs_stamp() {
  local executable=$1
  local metadata revision modified
  metadata=$(go version -m "$executable")
  revision=$(sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.revision=//p' <<<"$metadata")
  modified=$(sed -n 's/^[[:space:]]*build[[:space:]]*vcs\.modified=//p' <<<"$metadata")
  [[ $revision == "$final_sha" && $modified == false ]] || fail "Go executable lacks the clean final-SHA VCS stamp: $executable"
}
verify_clean_vcs_stamp "$low_level_runner"
verify_clean_vcs_stamp "$transportcheck"

clang -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/x86_64-linux-gnu \
  -c "$bpf_source_path" -o "$bpf_object"
[[ -s $bpf_object ]] || fail "packet-fault BPF compilation produced no object"
[[ -z $(git -C "$source_root" status --porcelain --untracked-files=all) ]] || fail "runner build changed the source checkout"

"$transportcheck" collect \
  -manifest "$manifest_path" \
  -registry "$registry_path" \
  -repo "$source_root" \
  -base-sha "$base_sha" \
  -final-sha "$final_sha" \
  -target "$target" \
  -report "$report" \
  -artifact-dir "$report_directory" \
  -runner-executable "$low_level_runner" \
  -runner-wrapper "$actual_wrapper" \
  -bpf-object "$bpf_object" \
  -host-bpftool "$host_bpftool" \
  -trust-policy "$trust_policy_path" \
  -effective-config "$effective_config_path" \
  -kernel-release "$actual_kernel"
