#!/usr/bin/env bash
set -Eeuo pipefail

go list ./... | while IFS= read -r package; do
  case "$package" in
    # Diagnostic runners and Linux tunnel workloads are explicit consumers.
    */internal/transporttest/performance|*/internal/transporttest/tunnelworkload) ;;
    *) printf '%s\n' "$package" ;;
  esac
done
