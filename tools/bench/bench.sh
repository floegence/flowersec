#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_DIR="${ROOT_DIR}/flowersec-go"
TS_DIR="${ROOT_DIR}/flowersec-ts"
OUT_FILE="${ROOT_DIR}/BENCH_RESULTS.md"

GOMAXPROCS="${GOMAXPROCS:-2}"
GOMEMLIMIT="${GOMEMLIMIT:-1024MiB}"
NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=768}"

LOADGEN_CHANNELS="${LOADGEN_CHANNELS:-1000}"
LOADGEN_RATE="${LOADGEN_RATE:-400}"
LOADGEN_RAMP_STEP="${LOADGEN_RAMP_STEP:-200}"
LOADGEN_RAMP_INTERVAL="${LOADGEN_RAMP_INTERVAL:-2s}"
LOADGEN_STEADY="${LOADGEN_STEADY:-30s}"
LOADGEN_REPORT_INTERVAL="${LOADGEN_REPORT_INTERVAL:-1s}"

GO_BENCH_CMD="GOMAXPROCS=${GOMAXPROCS} GOMEMLIMIT=${GOMEMLIMIT} go test -bench . -benchmem ./crypto/e2ee ./tunnel/server"
TS_BENCH_CMD="NODE_OPTIONS=${NODE_OPTIONS} npm run bench"
LOADGEN_CMD="GOMAXPROCS=${GOMAXPROCS} GOMEMLIMIT=${GOMEMLIMIT} go run ./internal/cmd/flowersec-loadgen --mode=full --channels=${LOADGEN_CHANNELS} --rate=${LOADGEN_RATE} --ramp-step=${LOADGEN_RAMP_STEP} --ramp-interval=${LOADGEN_RAMP_INTERVAL} --steady=${LOADGEN_STEADY} --report-interval=${LOADGEN_REPORT_INTERVAL}"

GO_OUT="$(mktemp)"
TS_OUT="$(mktemp)"
LOADGEN_OUT="$(mktemp)"

cleanup() {
  rm -f "${GO_OUT}" "${TS_OUT}" "${LOADGEN_OUT}"
}
trap cleanup EXIT

echo "[bench] running go benchmarks..."
(cd "${GO_DIR}" && GOMAXPROCS="${GOMAXPROCS}" GOMEMLIMIT="${GOMEMLIMIT}" go test -bench . -benchmem ./crypto/e2ee ./tunnel/server) | tee "${GO_OUT}"

echo "[bench] running ts benchmarks..."
(cd "${TS_DIR}" && NODE_OPTIONS="${NODE_OPTIONS}" NO_COLOR=1 FORCE_COLOR=0 npm run bench) | tee "${TS_OUT}"

echo "[bench] running load generator..."
(cd "${GO_DIR}" && GOMAXPROCS="${GOMAXPROCS}" GOMEMLIMIT="${GOMEMLIMIT}" go run ./internal/cmd/flowersec-loadgen \
  --mode=full \
  --channels="${LOADGEN_CHANNELS}" \
  --rate="${LOADGEN_RATE}" \
  --ramp-step="${LOADGEN_RAMP_STEP}" \
  --ramp-interval="${LOADGEN_RAMP_INTERVAL}" \
  --steady="${LOADGEN_STEADY}" \
  --report-interval="${LOADGEN_REPORT_INTERVAL}") > "${LOADGEN_OUT}"

RUN_DATE="$(LC_ALL=C date)"
OS_VERSION="$(sw_vers -productVersion)"
CPU_MODEL="$(sysctl -n machdep.cpu.brand_string)"
RAM_BYTES="$(sysctl -n hw.memsize)"
GO_VERSION="$(cd "${GO_DIR}" && go version)"
NODE_VERSION="$(cd "${TS_DIR}" && node -v)"

python3 "${ROOT_DIR}/tools/bench/bench_report.py" \
  --go-output "${GO_OUT}" \
  --ts-output "${TS_OUT}" \
  --loadgen-output "${LOADGEN_OUT}" \
  --out "${OUT_FILE}" \
  --run-date "${RUN_DATE}" \
  --os "macOS ${OS_VERSION}" \
  --cpu "${CPU_MODEL}" \
  --ram-bytes "${RAM_BYTES}" \
  --go-version "${GO_VERSION}" \
  --node-version "${NODE_VERSION}" \
  --gomaxprocs "${GOMAXPROCS}" \
  --gomemlimit "${GOMEMLIMIT}" \
  --node-options="${NODE_OPTIONS}" \
  --go-command "${GO_BENCH_CMD}" \
  --ts-command "${TS_BENCH_CMD}" \
  --loadgen-command "${LOADGEN_CMD}"

echo "[bench] wrote ${OUT_FILE}"
echo "[bench] preview:"
sed -n '1,120p' "${OUT_FILE}"
