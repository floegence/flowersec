#!/usr/bin/env bash
set -Eeuo pipefail

readonly host_root=/var/lib/flowersec-test
readonly host_home=$host_root/home
readonly host_workspace=$host_root/workspace
readonly host_tmp=$host_root/tmp
readonly host_cache=$host_root/cache
readonly host_go_root=$host_cache/toolchains/go
readonly host_swift_toolchains=$host_cache/toolchains/swift
readonly host_path="$host_go_root/bin:$host_cache/toolchains/node/bin:$host_home/.cargo/bin:$host_home/.local/bin:$host_home/.swiftly/bin:/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly playwright_download_host=https://npmmirror.com/mirrors/playwright
readonly go_version=1.26.6
readonly node_version=24.14.1
readonly rust_version=1.88.0
readonly swiftly_version=1.1.3
readonly swift_version=6.1.3
# SHA-256 of the Swift version, Swiftly version, PGP verification, and the
# canonical root-owned toolchain directory.
readonly swift_verification_marker=2cfe642c07bc6b03dcdcf6673440891654cf063b916fae3686bb33728f7dd29f
readonly playwright_version=1.62.1
readonly playwright_chromium_revision=1234
readonly playwright_chromium_version=151.0.7922.34
readonly playwright_ffmpeg_revision=1011

(($# == 0)) || { echo "usage: test-host-init.sh" >&2; exit 2; }
((EUID == 0)) || { echo "test-host-init requires EUID 0" >&2; exit 1; }
[[ $HOME == "$host_home" && $PATH == "$host_path" && $TMPDIR == "$host_tmp" && ${GOROOT:-} == "$host_go_root" && ${SWIFTLY_TOOLCHAINS_DIR:-} == "$host_swift_toolchains" && ${FLOWERSEC_TEST_STATE_DIR:-} == "$host_root/state" ]] || {
  echo "test-host-init requires the canonical root environment" >&2
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
    go_sha256=708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89
    node_arch=x64
    node_sha256=84d38715d449447117d05c3e71acd78daa49d5b1bfa8aacf610303920c3322be
    rustup_target=x86_64-unknown-linux-gnu
    rustup_sha256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
    rust_archive_sha256=7b5437c1d18a174faae253a18eac22c32288dccfc09ff78d5ee99b7467e21bca
    swiftly_arch=x86_64
    swiftly_sha256=4c4adb7b7ad7910f38c52b94a938c309586fe395e1fe1538c397384ee36bfff0
    swiftly_binary_sha256=e7ce91d07b4419ea779da6b575721c17eb7c44f932e63b6e2d03a9afe75cce61
    playwright_chromium_archive=builds/cft/${playwright_chromium_version}/linux64/chrome-linux64.zip
    playwright_chromium_sha256=ae8736ac28bc69278551500f219fc749575648263c43ec5990749eff43b9fcf8
    playwright_chromium_executable=chrome-linux64/chrome
    playwright_headless_archive=builds/cft/${playwright_chromium_version}/linux64/chrome-headless-shell-linux64.zip
    playwright_headless_sha256=3cfc2bd00d1bafcf8a68dc74c9c92bb7150ddc8d26ade948a776316e1cec4f14
    playwright_headless_executable=chrome-headless-shell-linux64/chrome-headless-shell
    playwright_ffmpeg_archive=builds/ffmpeg/${playwright_ffmpeg_revision}/ffmpeg-linux.zip
    playwright_ffmpeg_sha256=ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc
    ports_suffix=
    ;;
  aarch64|arm64)
    architecture=arm64
    go_arch=arm64
    go_sha256=d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e
    node_arch=arm64
    node_sha256=71e427e28b78846f201d4d5ecc30cb13d1508ca099ef3871889a1256c7d6f67e
    rustup_target=aarch64-unknown-linux-gnu
    rustup_sha256=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c
    rust_archive_sha256=d5decc46123eb888f809f2ee3b118d13586a37ffad38afaefe56aa7139481d34
    swiftly_arch=aarch64
    swiftly_sha256=cc4f912fff6c7f53704fc6d22f9e8ee7fdf6bd574ad276998f7502418bf5a45a
    swiftly_binary_sha256=6531421eeb80eb69db21e41b1ed94bac1467548972eb82861fc4beb6664bd6aa
    playwright_chromium_archive=builds/chromium/${playwright_chromium_revision}/chromium-linux-arm64.zip
    playwright_chromium_sha256=b5ad7d8fe70f230b34198ddb5626d717c016db2f627cb44b922babbcaf3479b9
    playwright_chromium_executable=chrome-linux/chrome
    playwright_headless_archive=builds/chromium/${playwright_chromium_revision}/chromium-headless-shell-linux-arm64.zip
    playwright_headless_sha256=b03443e1e1a60d06e07b6cdfe650b8c2bfcbb3db497d2b652f73dc6912f4ae15
    playwright_headless_executable=chrome-linux/headless_shell
    playwright_ffmpeg_archive=builds/ffmpeg/${playwright_ffmpeg_revision}/ffmpeg-linux-arm64.zip
    playwright_ffmpeg_sha256=2628c03f05318ff812c8c9baaf207dea2ddf53e818c0dc936714b0fbe3afb009
    ports_suffix=-ports
    ;;
  *) echo "missing host capability: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

install -d -m 0700 "$host_home" "$host_root/state" "$host_tmp" "$host_cache" "$host_cache/toolchains" \
  "$host_cache/go-build" "$host_cache/go-mod" "$host_cache/npm" "$host_cache/playwright" "$host_home/.local/bin" \
  "$host_swift_toolchains"

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
packages=(ca-certificates curl git jq unzip xz-utils gnupg openssl build-essential clang gcc g++ g++-12 libstdc++-12-dev pkg-config libbpf-dev ethtool iproute2 iptables nftables libatomic1 libcurl4 libedit2 libicu-dev libncurses6 libpython3-dev libsqlite3-0 libxml2-dev tzdata zlib1g)

download_file() {
  local label=$1 url=$2 destination=$3
  if ! curl -fL --retry 3 --retry-all-errors --connect-timeout 20 --max-time 900 -o "$destination" "$url"; then
    echo "$label download failed (connect timeout 20s, total timeout 900s): $url" >&2
    exit 1
  fi
}

verify_download() {
  local expected=$1 path=$2 label=$3
  if ! printf '%s  %s\n' "$expected" "$path" | sha256sum -c - >/dev/null 2>&1; then
    echo "$label checksum mismatch" >&2
    exit 1
  fi
}

checksum_matches() {
  local expected=$1 path=$2
  printf '%s  %s\n' "$expected" "$path" | sha256sum -c - >/dev/null 2>&1
}

authentication_marker_matches() {
  local expected=$1 marker=$2
  [[ -f $marker && ! -L $marker && $(<"$marker") == "$expected" ]]
}
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
  if [[ -x $destination/bin/go && -f $destination/.flowersec-archive.sha256 ]] &&
     "$destination/bin/go" version | grep -Fq "go${go_version}" &&
     [[ $(<"$destination/.flowersec-archive.sha256") == "$go_sha256" ]]; then return; fi
  archive=$(mktemp "$host_tmp/go.XXXXXX.tar.gz")
  temporary_paths+=("$archive")
  download_file "Go archive" "https://mirrors.aliyun.com/golang/go${go_version}.linux-${go_arch}.tar.gz" "$archive"
  verify_download "$go_sha256" "$archive" "Go archive"
  rm -rf -- "$destination"
  tar -C "$host_cache/toolchains" -xzf "$archive"
  printf '%s\n' "$go_sha256" >"$destination/.flowersec-archive.sha256"
  rm -f -- "$archive"
}

install_node() {
  local destination=$host_cache/toolchains/node extracted=$host_cache/toolchains/node-v${node_version}-linux-${node_arch} archive
  if [[ -x $destination/bin/node && -f $destination/.flowersec-archive.sha256 ]] &&
     [[ $($destination/bin/node --version) == v${node_version} ]] &&
     [[ $(<"$destination/.flowersec-archive.sha256") == "$node_sha256" ]]; then return; fi
  archive=$(mktemp "$host_tmp/node.XXXXXX.tar.xz")
  temporary_paths+=("$archive")
  download_file "Node archive" "https://npmmirror.com/mirrors/node/v${node_version}/node-v${node_version}-linux-${node_arch}.tar.xz" "$archive"
  verify_download "$node_sha256" "$archive" "Node archive"
  rm -rf -- "$destination" "$extracted"
  tar -C "$host_cache/toolchains" -xJf "$archive"
  mv -- "$extracted" "$destination"
  printf '%s\n' "$node_sha256" >"$destination/.flowersec-archive.sha256"
  rm -f -- "$archive"
}

install_rustup() {
  local installer marker=$host_home/.rustup/.flowersec-rustup-init.sha256
  if [[ -x $host_home/.cargo/bin/rustup ]] &&
     authentication_marker_matches "$rustup_sha256" "$marker" &&
     [[ $($host_home/.cargo/bin/rustup --version) == rustup\ 1.28.2* ]]; then return; fi
  installer=$(mktemp "$host_tmp/rustup-init.XXXXXX")
  temporary_paths+=("$installer")
  download_file "Rustup installer" "https://static.rust-lang.org/rustup/archive/1.28.2/${rustup_target}/rustup-init" "$installer"
  verify_download "$rustup_sha256" "$installer" "Rustup installer"
  chmod 0755 "$installer"
  "$installer" -y --profile minimal --default-toolchain none
  install -d -m 0700 "$host_home/.rustup"
  printf '%s\n' "$rustup_sha256" >"$marker"
  rm -f -- "$installer"
}

install_rust() {
  local destination=$host_home/.rustup/toolchains/${rust_version}-${rustup_target} marker archive extracted installer
  marker=$destination/.flowersec-archive.sha256
  if [[ -x $destination/bin/rustc && -x $destination/bin/cargo && -x $destination/bin/clippy-driver && -x $destination/bin/rustfmt ]] &&
     authentication_marker_matches "$rust_archive_sha256" "$marker" &&
     "$destination/bin/rustc" --version | grep -Eq "rustc ${rust_version}([[:space:]]|$)"; then
    rustup default "$rust_version" >/dev/null
    return
  fi
  archive=$(mktemp "$host_tmp/rust.XXXXXX.tar.xz")
  extracted=$(mktemp -d "$host_tmp/rust-extract.XXXXXX")
  temporary_paths+=("$archive" "$extracted")
  download_file "Rust distribution archive" "https://rsproxy.cn/dist/rust-${rust_version}-${rustup_target}.tar.xz" "$archive"
  verify_download "$rust_archive_sha256" "$archive" "Rust distribution archive"
  tar -C "$extracted" -xJf "$archive"
  installer=$extracted/rust-${rust_version}-${rustup_target}/install.sh
  [[ -x $installer ]] || { echo "Rust distribution installer is missing" >&2; exit 1; }
  rm -rf -- "$destination"
  install -d -m 0700 "$destination"
  "$installer" --prefix="$destination" --disable-ldconfig
  [[ -x $destination/bin/rustc && -x $destination/bin/cargo && -x $destination/bin/clippy-driver && -x $destination/bin/rustfmt ]] || {
    echo "Rust distribution is incomplete" >&2
    exit 1
  }
  printf '%s\n' "$rust_archive_sha256" >"$marker"
  rustup default "$rust_version" >/dev/null
  rm -f -- "$archive"
  rm -rf -- "$extracted"
}

initialize_swiftly_binary() {
  local bootstrap_swiftly=$1 swiftly=$2
  verify_download "$swiftly_binary_sha256" "$bootstrap_swiftly" "Swiftly extracted binary"
  if [[ ! -f $host_home/.swiftly/config.json ]]; then
    "$bootstrap_swiftly" init --assume-yes --skip-install --no-modify-profile --quiet-shell-followup
  else
    install -m 0755 "$bootstrap_swiftly" "$swiftly"
  fi
  verify_download "$swiftly_binary_sha256" "$swiftly" "Swiftly binary"
  [[ $("$swiftly" --version) == "$swiftly_version" ]] || { echo "Swiftly version mismatch" >&2; return 1; }
}

swift_toolchain_is_canonical() {
  local swift_proxy=$host_home/.local/bin/swift swiftc_proxy=$host_home/.local/bin/swiftc toolchain_bin=$host_swift_toolchains/$swift_version/usr/bin
  [[ $(type -P swift) == "$swift_proxy" && $(type -P swiftc) == "$swiftc_proxy" ]] || return 1
  "$swift_proxy" --version | grep -Fq "Swift version ${swift_version}" || return 1
  "$swiftc_proxy" --version | grep -Fq "Swift version ${swift_version}" || return 1
  [[ -x $toolchain_bin/swift && -x $toolchain_bin/swiftc ]] || return 1
  "$toolchain_bin/swift" --version | grep -Fq "Swift version ${swift_version}" || return 1
  "$toolchain_bin/swiftc" --version | grep -Fq "Swift version ${swift_version}" || return 1
}

install_swift() {
  local swiftly=$host_home/.local/bin/swiftly marker=$host_home/.swiftly/.flowersec-${swift_version}-pgp-verified archive bootstrap post_install
  if [[ ! -x $swiftly ]] || ! checksum_matches "$swiftly_binary_sha256" "$swiftly"; then
    archive=$(mktemp "$host_tmp/swiftly.XXXXXX.tar.gz")
    bootstrap=$(mktemp -d "$host_tmp/swiftly-bootstrap.XXXXXX")
    temporary_paths+=("$archive" "$bootstrap")
    download_file "Swiftly archive" "https://download.swift.org/swiftly/linux/swiftly-${swiftly_arch}.tar.gz" "$archive"
    verify_download "$swiftly_sha256" "$archive" "Swiftly archive"
    tar -C "$bootstrap" -xzf "$archive" swiftly
    chmod 0755 "$bootstrap/swiftly"
    initialize_swiftly_binary "$bootstrap/swiftly" "$swiftly"
    rm -f -- "$archive"
    rm -rf -- "$bootstrap"
  fi
  if swift_toolchain_is_canonical && authentication_marker_matches "$swift_verification_marker" "$marker"; then return; fi
  rm -f -- "$marker"
  rm -rf -- "$host_swift_toolchains"
  install -d -m 0700 "$host_swift_toolchains"
  "$swiftly" init --overwrite --assume-yes --skip-install --no-modify-profile --quiet-shell-followup
  verify_download "$swiftly_binary_sha256" "$swiftly" "Swiftly binary"
  post_install=$(mktemp "$host_tmp/swift-post-install.XXXXXX")
  temporary_paths+=("$post_install")
  (cd "$host_home" && "$swiftly" install "$swift_version" --use --verify --assume-yes --post-install-file="$post_install")
  [[ ! -s $post_install ]] || /bin/bash "$post_install"
  swift_toolchain_is_canonical || { echo "Swift toolchain is not canonical" >&2; exit 1; }
  printf '%s\n' "$swift_verification_marker" >"$marker"
  rm -f -- "$post_install"
}

install_verified_playwright_archive() {
  local label=$1 archive_path=$2 expected=$3 destination=$4 executable_path=$5 archive extracted marker
  marker=$destination/.flowersec-archive.sha256
  if [[ -x $destination/$executable_path ]] && authentication_marker_matches "$expected" "$marker"; then return; fi
  archive=$(mktemp "$host_tmp/playwright.XXXXXX.zip")
  extracted=$(mktemp -d "$host_tmp/playwright-extract.XXXXXX")
  temporary_paths+=("$archive" "$extracted")
  download_file "$label" "$playwright_download_host/$archive_path" "$archive"
  verify_download "$expected" "$archive" "$label"
  unzip -q "$archive" -d "$extracted"
  [[ -x $extracted/$executable_path ]] || { echo "$label executable is missing" >&2; exit 1; }
  printf '%s\n' "$expected" >"$extracted/.flowersec-archive.sha256"
  rm -rf -- "$destination"
  mv -- "$extracted" "$destination"
  rm -f -- "$archive"
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
install_rustup
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

required_commands=(go make node npm rustup cargo rustc swift swiftc git curl jq tar unzip xz gcc g++ clang clang++ openssl pkg-config python3 sh realpath ip nsenter tc nft iptables ethtool bpftool sysctl mount mountpoint umount flock sha256sum)
for required in "${required_commands[@]}"; do
  resolved=$(type -P "$required" || true)
  [[ -n $resolved && $resolved == /* && -x $resolved ]] || { echo "missing host capability: $required" >&2; exit 1; }
done
go version | grep -F "go${go_version}" >/dev/null || { echo "missing host capability: Go ${go_version}" >&2; exit 1; }
[[ $(go env GOROOT) == "$host_go_root" ]] || { echo "non-canonical root environment: Go root is $(go env GOROOT), expected $host_go_root" >&2; exit 1; }
[[ $(node --version) == v${node_version} ]] || { echo "missing host capability: Node ${node_version}" >&2; exit 1; }
rustc --version | grep -Eq "rustc ${rust_version}([[:space:]]|$)" || { echo "missing host capability: Rust ${rust_version}" >&2; exit 1; }
swift --version | grep -F "Swift version ${swift_version}" >/dev/null || { echo "missing host capability: Swift ${swift_version}" >&2; exit 1; }
make --version | grep -F 'GNU Make' >/dev/null || { echo "missing host capability: make" >&2; exit 1; }
python3 --version >/dev/null || { echo "missing host capability: python3" >&2; exit 1; }
rustup run "$rust_version" rustc --version | grep -Eq "rustc ${rust_version}([[:space:]]|$)" || { echo "missing host capability: rustup toolchain ${rust_version}" >&2; exit 1; }
if ! printf '#include <memory>\nint main() { return 0; }\n' | clang++ -std=c++17 -x c++ -fsyntax-only -; then
  echo "missing host capability: C++ standard headers for Swift" >&2
  exit 1
fi
bpf_probe=$(mktemp "$host_tmp/bpf-probe.XXXXXX.o")
temporary_paths+=("$bpf_probe")
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

playwright_metadata=$(cd "$source_root/flowersec-ts" && node --input-type=module -e '
import fs from "node:fs";
const packageManifest = JSON.parse(fs.readFileSync("node_modules/@playwright/test/package.json", "utf8"));
const browsers = JSON.parse(fs.readFileSync("node_modules/playwright-core/browsers.json", "utf8"));
const chromium = browsers.browsers.find((browser) => browser.name === "chromium");
const headless = browsers.browsers.find((browser) => browser.name === "chromium-headless-shell");
const ffmpeg = browsers.browsers.find((browser) => browser.name === "ffmpeg");
if (!packageManifest.version || !chromium?.revision || !chromium?.browserVersion || !headless?.revision || !ffmpeg?.revision) process.exit(1);
process.stdout.write([packageManifest.version, chromium.revision, chromium.browserVersion, headless.revision, ffmpeg.revision].join("\t"));
') || { echo "missing host capability: Playwright browser metadata" >&2; exit 1; }
expected_playwright_metadata=$(printf '%s\t%s\t%s\t%s\t%s' "$playwright_version" "$playwright_chromium_revision" "$playwright_chromium_version" "$playwright_chromium_revision" "$playwright_ffmpeg_revision")
[[ $playwright_metadata == "$expected_playwright_metadata" ]] || {
  echo "Playwright browser metadata does not match the authenticated archive set" >&2
  exit 1
}

# Never let Playwright fetch or extract root-executed browser binaries. Install
# the exact archives only after their per-architecture digests match.
playwright_chromium_root=$host_cache/playwright/chromium-$playwright_chromium_revision
playwright_headless_root=$host_cache/playwright/chromium_headless_shell-$playwright_chromium_revision
playwright_ffmpeg_root=$host_cache/playwright/ffmpeg-$playwright_ffmpeg_revision
install_verified_playwright_archive "Playwright Chromium archive" "$playwright_chromium_archive" "$playwright_chromium_sha256" "$playwright_chromium_root" "$playwright_chromium_executable"
install_verified_playwright_archive "Playwright Chromium headless archive" "$playwright_headless_archive" "$playwright_headless_sha256" "$playwright_headless_root" "$playwright_headless_executable"
install_verified_playwright_archive "Playwright FFmpeg archive" "$playwright_ffmpeg_archive" "$playwright_ffmpeg_sha256" "$playwright_ffmpeg_root" ffmpeg-linux
playwright_chromium=$playwright_chromium_root/$playwright_chromium_executable
resolved_playwright_chromium=$(cd "$source_root/flowersec-ts" && node --input-type=module -e 'import { chromium } from "@playwright/test"; process.stdout.write(chromium.executablePath())')
[[ $resolved_playwright_chromium == "$playwright_chromium" ]] || { echo "Playwright Chromium path does not match the authenticated archive" >&2; exit 1; }
[[ -x $playwright_chromium ]] || { echo "missing host capability: Playwright Chromium executable" >&2; exit 1; }
FLOWERSEC_CHROMIUM_EXECUTABLE="$playwright_chromium" node "$source_root/flowersec-ts/scripts/browser-test-runner.mjs" --runtime-canary "$playwright_chromium"
ln -sfn -- "$playwright_chromium" "$host_cache/chromium"

swift_canary=$(mktemp -d "$host_tmp/swift-canary.XXXXXX")
temporary_paths+=("$swift_canary")
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
