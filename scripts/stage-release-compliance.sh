#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null && pwd -P)
kind=${1:-}
destination=${2:-}

case "$kind" in
  tunnel|tools|gateway|demos) ;;
  *)
    echo "usage: scripts/stage-release-compliance.sh <tunnel|tools|gateway|demos> <destination>" >&2
    exit 2
    ;;
esac

if [[ -z "$destination" || ! -d "$destination" || -L "$destination" ]]; then
  echo "release compliance destination must be an existing, non-symlink directory" >&2
  exit 2
fi

destination=$(cd -- "$destination" >/dev/null && pwd -P)
if [[ "$destination" == / || "$destination" == "$repo_root" ]]; then
  echo "refusing unsafe release compliance destination: $destination" >&2
  exit 2
fi

source_root="$repo_root/release-compliance/$kind"
for relative in THIRD_PARTY_NOTICES.md SBOM_SCOPE.md sbom/spdx.json sbom/cyclonedx.json; do
  source_file="$source_root/$relative"
  if [[ ! -f "$source_file" || -L "$source_file" ]]; then
    echo "missing regular generated release compliance file: $source_file" >&2
    exit 1
  fi
done

rm -f -- "$destination/THIRD_PARTY_NOTICES.md" "$destination/SBOM_SCOPE.md"
rm -rf -- "$destination/sbom"
mkdir -p -- "$destination/sbom"
install -m 0644 "$source_root/THIRD_PARTY_NOTICES.md" "$destination/THIRD_PARTY_NOTICES.md"
install -m 0644 "$source_root/SBOM_SCOPE.md" "$destination/SBOM_SCOPE.md"
install -m 0644 "$source_root/sbom/spdx.json" "$destination/sbom/spdx.json"
install -m 0644 "$source_root/sbom/cyclonedx.json" "$destination/sbom/cyclonedx.json"
