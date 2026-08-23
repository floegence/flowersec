#!/usr/bin/env bash
set -Eeuo pipefail

readonly host_root=/var/lib/flowersec-test
readonly host_home=$host_root/home
readonly host_workspace=$host_root/workspace
readonly host_state=$host_root/state
readonly host_tmp=$host_root/tmp
readonly host_cache=$host_root/cache
readonly host_lock=$host_root/test-host.lock
readonly host_lock_wait=30
readonly host_go_root=$host_cache/toolchains/go
readonly host_swift_toolchains=$host_cache/toolchains/swift
readonly host_path="$host_go_root/bin:$host_cache/toolchains/node/bin:$host_home/.cargo/bin:$host_home/.local/bin:$host_home/.swiftly/bin:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly host_open_file_limit=65536

usage() {
  echo "usage: test-host.sh <init|run|resume|status> [--suite NAME] [--report ABSOLUTE.md] [--budget DURATION] [--debug]" >&2
  exit 2
}

normalize_origin() {
  case "$1" in
    git@github.com:*) printf 'https://github.com/%s\n' "${1#git@github.com:}" ;;
    ssh://git@github.com/*) printf 'https://github.com/%s\n' "${1#ssh://git@github.com/}" ;;
    https://ghfast.top/https://github.com/*) printf '%s\n' "$1" ;;
    https://github.com/*) printf '%s\n' "$1" ;;
    *) echo "test host source must use a GitHub origin" >&2; exit 1 ;;
  esac
}

configure_open_file_limit() {
  local hard_limit soft_limit
  hard_limit=$(ulimit -Hn)
  if [[ $hard_limit != unlimited ]] && { [[ ! $hard_limit =~ ^[0-9]+$ ]] || ((hard_limit < host_open_file_limit)); }; then
    echo "unsupported test host: hard file descriptor limit must be at least $host_open_file_limit" >&2
    exit 1
  fi
  ulimit -Sn "$host_open_file_limit" || {
    echo "unsupported test host: cannot set soft file descriptor limit to $host_open_file_limit" >&2
    exit 1
  }
  soft_limit=$(ulimit -Sn)
  [[ $soft_limit == "$host_open_file_limit" ]] || {
    echo "root test environment has file descriptor limit $soft_limit, expected $host_open_file_limit" >&2
    exit 1
  }
}

acquire_host_lock() {
  if ! flock -w "$host_lock_wait" -x "$host_lock_fd"; then
    echo "test-host lock timeout after ${host_lock_wait}s: $host_lock" >&2
    exit 124
  fi
}

enter_root() {
  local script=$1 source_sha=$2 source_url=$3
  shift 3
  if ((EUID == 0)); then
    exec env -i \
      HOME="$host_home" PATH="$host_path" TMPDIR="$host_tmp" \
      FLOWERSEC_TEST_STATE_DIR="$host_state" XDG_CACHE_HOME="$host_cache/xdg" \
      GOROOT="$host_go_root" GOCACHE="$host_cache/go-build" GOMODCACHE="$host_cache/go-mod" \
      CARGO_HOME="$host_home/.cargo" RUSTUP_HOME="$host_home/.rustup" \
      SWIFTLY_HOME_DIR="$host_home/.swiftly" SWIFTLY_BIN_DIR="$host_home/.local/bin" SWIFTLY_TOOLCHAINS_DIR="$host_swift_toolchains" \
      PLAYWRIGHT_BROWSERS_PATH="$host_cache/playwright" npm_config_cache="$host_cache/npm" \
      FLOWERSEC_CHROMIUM_EXECUTABLE="$host_cache/chromium" \
      npm_config_registry=https://registry.npmmirror.com \
      GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn \
      CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
      CARGO_REGISTRIES_CRATES_IO_INDEX=sparse+https://rsproxy.cn/index/ \
      /bin/bash "$script" --root "$source_sha" "$source_url" "$@"
  fi
  command -v sudo >/dev/null 2>&1 || { echo "unsupported test host: non-interactive root access is required" >&2; exit 1; }
  sudo -n true >/dev/null 2>&1 || { echo "unsupported test host: direct root or sudo -n access is required" >&2; exit 1; }
  exec sudo -n env -i \
    HOME="$host_home" PATH="$host_path" TMPDIR="$host_tmp" \
    FLOWERSEC_TEST_STATE_DIR="$host_state" XDG_CACHE_HOME="$host_cache/xdg" \
    GOROOT="$host_go_root" GOCACHE="$host_cache/go-build" GOMODCACHE="$host_cache/go-mod" \
    CARGO_HOME="$host_home/.cargo" RUSTUP_HOME="$host_home/.rustup" \
    SWIFTLY_HOME_DIR="$host_home/.swiftly" SWIFTLY_BIN_DIR="$host_home/.local/bin" SWIFTLY_TOOLCHAINS_DIR="$host_swift_toolchains" \
    PLAYWRIGHT_BROWSERS_PATH="$host_cache/playwright" npm_config_cache="$host_cache/npm" \
    FLOWERSEC_CHROMIUM_EXECUTABLE="$host_cache/chromium" \
    npm_config_registry=https://registry.npmmirror.com \
    GOPROXY=https://goproxy.cn,direct GOSUMDB=sum.golang.google.cn \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_REGISTRIES_CRATES_IO_INDEX=sparse+https://rsproxy.cn/index/ \
    /bin/bash "$script" --root "$source_sha" "$source_url" "$@"
}

sync_workspace() {
  local source_sha=$1 source_url=$2
  local workspace_created=0
  install -d -m 0700 "$host_root" "$host_home" "$host_state" "$host_tmp" "$host_cache" "$host_cache/toolchains"
  if [[ ! -d $host_workspace/.git ]]; then
    [[ ! -e $host_workspace ]] || { echo "root workspace exists but is not a Git checkout" >&2; exit 1; }
    git clone --no-checkout "$source_url" "$host_workspace"
    workspace_created=1
  fi
  [[ $(stat -c %u "$host_workspace") == 0 ]] || { echo "root workspace must be root-owned" >&2; exit 1; }
  git -C "$host_workspace" remote set-url origin "$source_url"
  if ((workspace_created == 0)); then
    [[ -z $(git -C "$host_workspace" status --porcelain --untracked-files=all) ]] || {
      echo "root workspace is not clean before sync" >&2
      exit 1
    }
  fi
  if ((workspace_created == 1)) || [[ $(git -C "$host_workspace" rev-parse HEAD 2>/dev/null || true) != "$source_sha" ]]; then
    git -C "$host_workspace" fetch --force origin "$source_sha"
    git -C "$host_workspace" checkout --detach "$source_sha"
  fi
  [[ $(git -C "$host_workspace" rev-parse HEAD) == "$source_sha" ]] || { echo "root workspace SHA mismatch" >&2; exit 1; }
  [[ -z $(git -C "$host_workspace" status --porcelain --untracked-files=all) ]] || { echo "root workspace is not clean" >&2; exit 1; }
}

if [[ ${1:-} == --root ]]; then
  ((EUID == 0)) || { echo "internal root entry requires EUID 0" >&2; exit 1; }
  (($# >= 4)) || usage
  source_sha=$2
  source_url=$3
  action=$4
  shift 4
  [[ $source_sha =~ ^[0-9a-f]{40}$ ]] || { echo "source SHA must be a full Git object ID" >&2; exit 1; }
  [[ $HOME == "$host_home" && $PATH == "$host_path" && $TMPDIR == "$host_tmp" && ${GOROOT:-} == "$host_go_root" && ${SWIFTLY_TOOLCHAINS_DIR:-} == "$host_swift_toolchains" && ${FLOWERSEC_TEST_STATE_DIR:-} == "$host_state" ]] || {
    echo "root test environment is not canonical" >&2
    exit 1
  }
  configure_open_file_limit
  case "$action" in
    init) (($# == 0)) || usage ;;
    run|resume|status) ;;
    *) usage ;;
  esac
  install -d -m 0700 "$host_root"
  exec {host_lock_fd}>"$host_lock"
  acquire_host_lock
  sync_workspace "$source_sha" "$source_url"
  cd "$host_workspace"
  if [[ $action == init ]]; then
    init_tmp_baseline=$(mktemp "$host_tmp/init-wrapper-baseline.XXXXXX")
    find "$host_tmp" -maxdepth 1 -type d -name 'TemporaryDirectory.*' -printf '%f\n' | sort >"$init_tmp_baseline"
    cleanup_init_wrapper_temps() {
      while IFS= read -r residual; do
        [[ -n $residual ]] || continue
        find "$host_tmp/$residual" -depth -delete >/dev/null 2>&1 || true
      done < <(comm -13 "$init_tmp_baseline" <(find "$host_tmp" -maxdepth 1 -type d -name 'TemporaryDirectory.*' -printf '%f\n' | sort))
    }
    trap 'cleanup_init_wrapper_temps; rm -f -- "$init_tmp_baseline"' EXIT
    init_status=0
    ./scripts/test-host-init.sh || init_status=$?
    for _ in {1..50}; do
      cleanup_init_wrapper_temps
      residual_count=$(comm -13 "$init_tmp_baseline" <(find "$host_tmp" -maxdepth 1 -type d -name 'TemporaryDirectory.*' -printf '%f\n' | sort) | wc -l)
      ((residual_count == 0)) && break
      sleep 0.1
    done
    trap - EXIT
    cleanup_init_wrapper_temps
    rm -f -- "$init_tmp_baseline"
    exit "$init_status"
  fi
  runner_directory=$host_cache/bin
  runner=$runner_directory/flowersec-test-$source_sha
  install -d -m 0700 "$runner_directory"
  if [[ ! -x $runner ]]; then
    temporary_runner=$(mktemp "$runner_directory/.flowersec-test.XXXXXX")
    if ! go -C flowersec-go build -o "$temporary_runner" ./internal/cmd/flowersec-test; then
      rm -f -- "$temporary_runner"
      exit 1
    fi
    chmod 0700 "$temporary_runner"
    mv -f -- "$temporary_runner" "$runner"
  fi
  exec "$runner" "$action" "$@"
fi

action=${1:-}
case "$action" in
  init) (($# == 1)) || usage ;;
  run|resume|status) ;;
  *) usage ;;
esac
if ((EUID != 0)); then
  command -v sudo >/dev/null 2>&1 || { echo "unsupported test host: non-interactive root access is required" >&2; exit 1; }
  sudo -n true >/dev/null 2>&1 || { echo "unsupported test host: direct root or sudo -n access is required" >&2; exit 1; }
fi
source_root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "run test-host.sh from a Flowersec checkout" >&2; exit 1; }
[[ -z $(git -C "$source_root" status --porcelain --untracked-files=all) ]] || { echo "source checkout is not clean" >&2; exit 1; }
source_sha=$(git -C "$source_root" rev-parse HEAD)
[[ $source_sha =~ ^[0-9a-f]{40}$ ]] || { echo "source SHA must be a full Git object ID" >&2; exit 1; }
source_url=$(normalize_origin "$(git -C "$source_root" remote get-url origin)")
enter_root "$source_root/scripts/test-host.sh" "$source_sha" "$source_url" "$@"
