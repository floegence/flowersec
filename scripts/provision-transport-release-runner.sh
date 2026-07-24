#!/usr/bin/env bash

set -euo pipefail

container_name=flowersec-release-ubuntu24
image_name=flowersec-release-runner:ubuntu24
runner_root=${FLOWERSEC_RELEASE_RUNNER_ROOT:-$HOME/flowersec-release}
repository_root=${FLOWERSEC_RELEASE_REPOSITORY_ROOT:-$runner_root/workspace/flowersec}
host_bpftool=/usr/lib/linux-tools/$(uname -r)/bpftool
host_linux_tools=$(dirname "$(readlink -f "$host_bpftool")")

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo "transport release runner requires a native Linux x86_64 host" >&2
  exit 1
fi
if [[ ! -d $repository_root/.git ]]; then
  echo "Flowersec checkout not found: $repository_root" >&2
  exit 1
fi
if ! sudo -n true 2>/dev/null; then
  echo "transport release runner requires non-interactive sudo for netns/tc/eBPF" >&2
  exit 1
fi
if [[ ! -x $host_bpftool ]]; then
  echo "exact-kernel bpftool not found: $host_bpftool" >&2
  exit 1
fi

install -d -m 0750 \
  "$runner_root/cache" \
  "$runner_root/evidence" \
  "$runner_root/workspace"

docker build \
  --file "$repository_root/tools/transportrelease/Containerfile" \
  --tag "$image_name" \
  "$repository_root"

if docker container inspect "$container_name" >/dev/null 2>&1; then
  docker rm --force "$container_name" >/dev/null
fi

docker run --detach \
  --name "$container_name" \
  --hostname flowersec-linux-release-v1 \
  --privileged \
  --network host \
  --restart unless-stopped \
  --env "GOPROXY=${FLOWERSEC_RELEASE_GOPROXY:-https://goproxy.cn,direct}" \
  --volume "$runner_root/workspace:/workspace" \
  --volume "$runner_root/evidence:/evidence" \
  --volume "$runner_root/cache:/cache" \
  --volume /sys/fs/bpf:/sys/fs/bpf \
  --volume /lib/modules:/lib/modules:ro \
  --volume "$host_linux_tools:/opt/host-linux-tools:ro" \
  "$image_name" >/dev/null

docker exec "$container_name" bash -euo pipefail -c '
  test "$(uname -m)" = x86_64
  test -w /sys/fs/bpf
  namespace=flowersec-provision-probe
  ip netns add "$namespace"
  trap '\''ip netns del "$namespace" 2>/dev/null || true'\'' EXIT
  ip netns exec "$namespace" ip link set lo up
  ip netns del "$namespace"
  trap - EXIT
  go version
  node --version
  npm --version
  rustc --version
  cargo --version
  /opt/host-linux-tools/bpftool version
  tc -V
'

docker exec "$container_name" bash -euo pipefail -c '
  cd /workspace/flowersec/flowersec-ts
  npm ci --audit=false
  npx playwright install chromium
  npx playwright --version
'
