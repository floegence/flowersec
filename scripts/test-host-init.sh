#!/usr/bin/env bash
set -Eeuo pipefail

readonly host_root=/var/lib/flowersec-test
readonly host_home=$host_root/home
readonly host_workspace=$host_root/workspace
readonly host_tmp=$host_root/tmp
readonly host_cache=$host_root/cache
readonly host_go_root=$host_cache/toolchains/go
readonly host_path="$host_go_root/bin:$host_cache/toolchains/node/bin:$host_home/.cargo/bin:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$host_home/.local/bin:$host_home/.swiftly/bin"
readonly playwright_download_host=https://npmmirror.com/mirrors/playwright
readonly playwright_download_timeout=120000

(($# == 0)) || { echo "usage: test-host-init.sh" >&2; exit 2; }
((EUID == 0)) || { echo "test-host-init requires EUID 0" >&2; exit 1; }
[[ $HOME == "$host_home" && $PATH == "$host_path" && $TMPDIR == "$host_tmp" && ${GOROOT:-} == "$host_go_root" && ${FLOWERSEC_TEST_STATE_DIR:-} == "$host_root/state" ]] || {
  echo "test-host-init requires the canonical root environment" >&2
  exit 1
}
[[ ${PLAYWRIGHT_DOWNLOAD_HOST:-} == "$playwright_download_host" && ${PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT:-} == "$playwright_download_timeout" ]] || {
  echo "test-host-init requires the canonical Playwright download environment" >&2
  exit 1
}
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $source_root == "$host_workspace" && $(git -C "$source_root" rev-parse --show-toplevel) == "$host_workspace" ]] || {
  echo "test-host-init must run from the root-owned workspace" >&2
  exit 1
}
[[ $(stat -c %u "$source_root") == 0 ]] || { echo "test-host workspace must be root-owned" >&2; exit 1; }

source /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo "missing host capability: Ubuntu 22.04 or later" >&2; exit 1; }
dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04 || { echo "missing host capability: Ubuntu 22.04 or later" >&2; exit 1; }
case $(uname -m) in
  x86_64|amd64)
    architecture=amd64
    go_arch=amd64
    node_arch=x64
    rustup_target=x86_64-unknown-linux-gnu
    rustup_sha256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
    swiftly_arch=x86_64
    ports_suffix=
    ;;
  aarch64|arm64)
    architecture=arm64
    go_arch=arm64
    node_arch=arm64
    rustup_target=aarch64-unknown-linux-gnu
    rustup_sha256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
    swiftly_arch=aarch64
    ports_suffix=-ports
    ;;
  *) echo "missing host capability: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

install -d -m 0700 "$host_home" "$host_root/state" "$host_tmp" "$host_cache" "$host_cache/toolchains" \
  "$host_cache/go-build" "$host_cache/go-mod" "$host_cache/npm" "$host_cache/playwright" "$host_home/.local/bin"

temporary_paths=()
cleanup_temporary_paths() {
  local path
  for path in "${temporary_paths[@]}"; do
    [[ -n $path ]] || continue
    rm -rf -- "$path" >/dev/null 2>&1 || true
  done
}
init_tmp_baseline=
trap cleanup_temporary_paths EXIT

install -d -m 0755 /etc/apt/sources.list.d
source_file=/etc/apt/sources.list.d/flowersec-ubuntu.sources
source_uri="https://mirrors.tuna.tsinghua.edu.cn/ubuntu${ports_suffix}"
rm -f -- /etc/profile.d/flowersec-mainland-sources.sh
temporary=$(mktemp /etc/apt/sources.list.d/.flowersec-ubuntu.sources.XXXXXX)
temporary_paths+=("$temporary")
cat >"$temporary" <<EOF
Types: deb
URIs: ${source_uri}
Suites: ${VERSION_CODENAME} ${VERSION_CODENAME}-updates ${VERSION_CODENAME}-backports ${VERSION_CODENAME}-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
chmod 0644 "$temporary"
equivalent_source=
for candidate in /etc/apt/sources.list.d/*.sources; do
  [[ $candidate != "$source_file" && -f $candidate ]] || continue
  candidate_uri=$(sed -n 's/^URIs:[[:space:]]*//p' "$candidate" | head -1)
  candidate_uri=${candidate_uri%/}
  if [[ $candidate_uri == "$source_uri" ]] && grep -Fq "Suites: ${VERSION_CODENAME}" "$candidate"; then
    equivalent_source=$candidate
    break
  fi
done
if [[ -n $equivalent_source ]]; then
  rm -f -- "$source_file"
elif [[ ! -f $source_file ]] || ! cmp -s "$temporary" "$source_file"; then
  mv -f -- "$temporary" "$source_file"
fi
apt-get update
packages=(ca-certificates curl git jq xz-utils gnupg openssl build-essential clang gcc g++ g++-12 libstdc++-12-dev pkg-config libbpf-dev ethtool iproute2 iptables nftables libatomic1 libcurl4 libedit2 libicu-dev libncurses6 libpython3-dev libsqlite3-0 libxml2-dev tzdata zlib1g)
readonly go_version=1.26.6
if ! command -v bpftool >/dev/null 2>&1; then
  kernel_tools="linux-tools-$(uname -r)"
  if apt-cache show "$kernel_tools" >/dev/null 2>&1; then
    packages+=("$kernel_tools")
  elif apt-cache show bpftool >/dev/null 2>&1; then
    packages+=(bpftool)
  else
    echo "missing host capability: bpftool for kernel $(uname -r)" >&2
    exit 1
  fi
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
if ! command -v chromium >/dev/null 2>&1 && ! command -v chromium-browser >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends chromium || \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends chromium-browser
fi

install_go() {
  local destination=$host_go_root archive
  if [[ -x $destination/bin/go ]] && "$destination/bin/go" version | grep -Fq "go${go_version}"; then return; fi
  archive=$(mktemp "$host_tmp/go.XXXXXX.tar.gz")
  temporary_paths+=("$archive")
  curl -fL --retry 3 -o "$archive" "https://mirrors.aliyun.com/golang/go${go_version}.linux-${go_arch}.tar.gz"
  rm -rf -- "$destination"
  tar -C "$host_cache/toolchains" -xzf "$archive"
  rm -f -- "$archive"
}

install_node() {
  local destination=$host_cache/toolchains/node extracted=$host_cache/toolchains/node-v24.14.1-linux-${node_arch} archive
  if [[ -x $destination/bin/node ]] && [[ $($destination/bin/node --version) == v24.14.1 ]]; then return; fi
  archive=$(mktemp "$host_tmp/node.XXXXXX.tar.xz")
  temporary_paths+=("$archive")
  curl -fL --retry 3 -o "$archive" "https://npmmirror.com/mirrors/node/v24.14.1/node-v24.14.1-linux-${node_arch}.tar.xz"
  rm -rf -- "$destination" "$extracted"
  tar -C "$host_cache/toolchains" -xJf "$archive"
  mv -- "$extracted" "$destination"
  rm -f -- "$archive"
}

install_rust() {
  local installer
  if [[ -x $host_home/.cargo/bin/rustc ]] && "$host_home/.cargo/bin/rustc" --version | grep -Eq 'rustc 1\.88\.0([[:space:]]|$)'; then return; fi
  installer=$(mktemp "$host_tmp/rustup-init.XXXXXX")
  temporary_paths+=("$installer")
  curl -fL --retry 3 -o "$installer" "https://static.rust-lang.org/rustup/archive/1.28.2/${rustup_target}/rustup-init"
  if ! printf '%s  %s\n' "$rustup_sha256" "$installer" | sha256sum --check --status; then
    rm -f -- "$installer"
    echo "rustup-init checksum mismatch" >&2
    exit 1
  fi
  chmod 0755 "$installer"
  "$installer" -y --profile minimal --default-toolchain 1.88.0
  rm -f -- "$installer"
}

install_swift() {
  local swiftly=$host_home/.local/bin/swiftly archive bootstrap post_install
  if [[ ! -x $swiftly ]]; then
    archive=$(mktemp "$host_tmp/swiftly.XXXXXX.tar.gz")
    bootstrap=$(mktemp -d "$host_tmp/swiftly-bootstrap.XXXXXX")
    temporary_paths+=("$archive" "$bootstrap")
    curl -fL --retry 3 -o "$archive" "https://download.swift.org/swiftly/linux/swiftly-${swiftly_arch}.tar.gz"
    tar -C "$bootstrap" -xzf "$archive" swiftly
    chmod 0755 "$bootstrap/swiftly"
    "$bootstrap/swiftly" init --assume-yes --skip-install --no-modify-profile --quiet-shell-followup
    rm -f -- "$archive"
    rm -rf -- "$bootstrap"
  fi
  if ! command -v swift >/dev/null 2>&1 || ! swift --version | grep -Eq 'Swift version 6\.1(\.[0-9]+)?([[:space:]]|$)'; then
    post_install=$(mktemp "$host_tmp/swift-post-install.XXXXXX")
    temporary_paths+=("$post_install")
    (cd "$host_home" && "$swiftly" install 6.1 --use --assume-yes --post-install-file="$post_install")
    [[ ! -s $post_install ]] || /bin/bash "$post_install"
    rm -f -- "$post_install"
  fi
}

configure_cargo_source() {
  local cargo_config=$host_home/.cargo/config.toml
  install -d -m 0700 "$host_home/.cargo"
  if [[ ! -f $cargo_config ]] ||
     ! grep -Fqx 'replace-with = "rsproxy"' "$cargo_config" 2>/dev/null ||
     ! grep -Fqx 'registry = "sparse+https://rsproxy.cn/index/"' "$cargo_config" 2>/dev/null; then
    cat >"$cargo_config" <<'EOF'
[source.crates-io]
replace-with = "rsproxy"

[source.rsproxy]
registry = "sparse+https://rsproxy.cn/index/"
EOF
    chmod 0600 "$cargo_config"
  fi
}

install_go
install_node
install_rust
install_swift
configure_cargo_source

init_tmp_baseline=$(mktemp "$host_tmp/init-tmp-baseline.XXXXXX")
find "$host_tmp" -maxdepth 1 -type d -name 'TemporaryDirectory.*' -printf '%f\n' | sort >"$init_tmp_baseline"
cleanup_init_temps() {
  while IFS= read -r residual; do
    [[ -n $residual ]] || continue
    find "$host_tmp/$residual" -depth -delete >/dev/null 2>&1 || true
  done < <(comm -13 "$init_tmp_baseline" <(find "$host_tmp" -maxdepth 1 -type d -name 'TemporaryDirectory.*' -printf '%f\n' | sort))
}
finalize_init_temps() {
  if [[ -z ${init_tmp_baseline:-} ]]; then
    cleanup_temporary_paths
    return
  fi
  for _ in {1..20}; do
    cleanup_init_temps
    residual_count=$(comm -13 "$init_tmp_baseline" <(find "$host_tmp" -maxdepth 1 -type d -name 'TemporaryDirectory.*' -printf '%f\n' | sort) | wc -l)
    ((residual_count == 0)) && break
    sleep 0.1
  done
  rm -f -- "$init_tmp_baseline"
  init_tmp_baseline=
  cleanup_temporary_paths
}
trap finalize_init_temps EXIT

# Swiftly may leave a project-local selector when invoked from a checkout. It
# is not part of the exact-SHA workspace and must never become test state.
if [[ -e "$source_root/.swift-version" ]] && ! git -C "$source_root" ls-files --error-unmatch .swift-version >/dev/null 2>&1; then
  rm -f -- "$source_root/.swift-version"
fi

required_commands=(go make node npm rustup cargo rustc swift swiftc git curl jq tar xz gcc g++ clang clang++ openssl pkg-config python3 sh realpath ip nsenter tc nft iptables ethtool bpftool sysctl mount mountpoint umount flock)
for required in "${required_commands[@]}"; do
  resolved=$(type -P "$required" || true)
  [[ -n $resolved && $resolved == /* && -x $resolved ]] || { echo "missing host capability: $required" >&2; exit 1; }
done
go version | grep -F "go${go_version}" >/dev/null || { echo "missing host capability: Go ${go_version}" >&2; exit 1; }
[[ $(go env GOROOT) == "$host_go_root" ]] || { echo "non-canonical root environment: Go root is $(go env GOROOT), expected $host_go_root" >&2; exit 1; }
[[ $(node --version) == v24.14.1 ]] || { echo "missing host capability: Node 24.14.1" >&2; exit 1; }
rustc --version | grep -Eq 'rustc 1\.88\.0([[:space:]]|$)' || { echo "missing host capability: Rust 1.88.0" >&2; exit 1; }
swift --version | grep -Eq 'Swift version 6\.1(\.[0-9]+)?([[:space:]]|$)' || { echo "missing host capability: Swift 6.1" >&2; exit 1; }
make --version | grep -F 'GNU Make' >/dev/null || { echo "missing host capability: make" >&2; exit 1; }
python3 --version >/dev/null || { echo "missing host capability: python3" >&2; exit 1; }
rustup run 1.88.0 rustc --version | grep -Eq 'rustc 1\.88\.0([[:space:]]|$)' || { echo "missing host capability: rustup toolchain 1.88.0" >&2; exit 1; }
if ! printf '#include <memory>\nint main() { return 0; }\n' | clang++ -std=c++17 -x c++ -fsyntax-only -; then
  echo "missing host capability: C++ standard headers for Swift" >&2
  exit 1
fi
bpf_probe=$(mktemp "$host_tmp/bpf-probe.XXXXXX.o")
if ! printf 'int flowersec_bpf_probe;\n' | clang -target bpf -O2 -x c -c -o "$bpf_probe" -; then
  rm -f -- "$bpf_probe"
  echo "missing host capability: clang BPF target" >&2
  exit 1
fi
rm -f -- "$bpf_probe"

[[ -r /sys/kernel/btf/vmlinux ]] || { echo "missing host capability: kernel BTF" >&2; exit 1; }
bpftool feature probe kernel >/dev/null || { echo "missing host capability: kernel eBPF" >&2; exit 1; }
[[ -e /sys/fs/cgroup/cgroup.controllers ]] || { echo "missing host capability: cgroup v2" >&2; exit 1; }
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf || { echo "missing host capability: BPF filesystem" >&2; exit 1; }

# Network namespaces, veth/IFB links, qdiscs, firewall rules, and project BPF
# objects are diagnostic-test resources. The self-contained linuxnetlab tests
# create and clean them; host initialization only verifies host-wide tooling
# and kernel support so it remains side-effect free for test resources.
ip netns list >/dev/null
tc qdisc help >/dev/null 2>&1
nft --version >/dev/null
iptables --version >/dev/null
ethtool --version >/dev/null 2>&1
sysctl -q net.ipv4.ip_forward
df -Pk "$host_root" | awk 'NR == 2 && $4 >= 10485760 { ok=1 } END { exit(ok ? 0 : 1) }' || { echo "missing host capacity: 10 GiB free disk" >&2; exit 1; }
free -m | awk 'NR == 2 && $7 >= 2048 { ok=1 } END { exit(ok ? 0 : 1) }' || { echo "missing host capacity: 2 GiB available memory" >&2; exit 1; }
fd_hard=$(ulimit -Hn)
[[ $fd_hard =~ ^[0-9]+$ && $fd_hard -ge 65536 ]] || { echo "missing host capacity: 65536 file descriptors" >&2; exit 1; }
fd_soft=$(ulimit -Sn)
[[ $fd_soft == 65536 ]] || { echo "non-canonical root environment: soft file descriptor limit is $fd_soft, expected 65536" >&2; exit 1; }

git -C "$source_root" status --porcelain --untracked-files=all >/dev/null
go -C "$source_root/flowersec-go" mod download
npm --prefix "$source_root/flowersec-ts" ci --audit=false
cargo fetch --manifest-path "$source_root/flowersec-rust/Cargo.toml" --locked

playwright_version=$(cd "$source_root/flowersec-ts" && node --input-type=module -e '
import fs from "node:fs";
const browsers = JSON.parse(fs.readFileSync("node_modules/playwright-core/browsers.json", "utf8"));
const chromium = browsers.browsers.find((browser) => browser.name === "chromium");
if (!chromium?.browserVersion) process.exit(1);
process.stdout.write(chromium.browserVersion);
') || { echo "missing host capability: Playwright Chromium version metadata" >&2; exit 1; }
playwright_download_url="$playwright_download_host/builds/cft/$playwright_version/linux64/chrome-linux64.zip"
playwright_headers=$(curl -fILsS --max-time 30 "$playwright_download_url") || {
  echo "missing host capability: Playwright Chromium mirror is unreachable ($playwright_download_url)" >&2
  exit 1
}
grep -Eq '^HTTP/[0-9.]+ 2[0-9][0-9]([[:space:]]|$)' <<<"$playwright_headers" || {
  echo "missing host capability: Playwright Chromium mirror returned no successful response" >&2
  exit 1
}

# The system Chromium package may be too old for WebTransport. Install only
# the pinned Playwright Chromium into the task cache and use that exact
# executable for both capability validation and the browser workload.
npm --prefix "$source_root/flowersec-ts" run ensure:browser
playwright_chromium=$(cd "$source_root/flowersec-ts" && node --input-type=module -e 'import { chromium } from "@playwright/test"; process.stdout.write(chromium.executablePath())')
[[ -x $playwright_chromium ]] || { echo "missing host capability: Playwright Chromium executable" >&2; exit 1; }
FLOWERSEC_CHROMIUM_EXECUTABLE="$playwright_chromium" node "$source_root/flowersec-ts/scripts/browser-test-runner.mjs" --runtime-canary "$playwright_chromium"
ln -sfn -- "$playwright_chromium" "$host_cache/chromium"

swift_canary=$(mktemp -d "$host_tmp/swift-canary.XXXXXX")
printf 'print("flowersec-swift-canary")\n' >"$swift_canary/main.swift"
if ! TMPDIR="$swift_canary" swiftc "$swift_canary/main.swift" -o "$swift_canary/canary" ||
   ! "$swift_canary/canary" | grep -Fx 'flowersec-swift-canary' >/dev/null; then
  echo "missing host capability: Swift compile and run" >&2
  exit 1
fi
find "$swift_canary" -depth -delete >/dev/null 2>&1 || true

finalize_init_temps
trap - EXIT

echo "GREEN test-host-init distro=${VERSION_ID} architecture=${architecture} kernel=$(uname -r) sha=$(git -C "$source_root" rev-parse HEAD)"
