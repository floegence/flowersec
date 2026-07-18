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
GO_ROUNDTRIP_BASELINE_NS="${GO_ROUNDTRIP_BASELINE_NS:-40824}"
GO_ROUNDTRIP_MAX_REGRESSION_PERCENT="${GO_ROUNDTRIP_MAX_REGRESSION_PERCENT:-15}"
STREAM_THROUGHPUT_BASELINE_MIB_PER_SEC="${STREAM_THROUGHPUT_BASELINE_MIB_PER_SEC:-279.77041340449995}"
STREAM_TTFB_BASELINE_MS="${STREAM_TTFB_BASELINE_MS:-0.653583}"
STREAM_MAX_REGRESSION_PERCENT="${STREAM_MAX_REGRESSION_PERCENT:-15}"
MAX_HEAP_BYTES="${MAX_HEAP_BYTES:-536870912}"
MAX_FAIRNESS_RATIO="${MAX_FAIRNESS_RATIO:-2}"

GO_BENCH_CMD="GOMAXPROCS=${GOMAXPROCS} GOMEMLIMIT=${GOMEMLIMIT} go test -bench . -benchmem ./crypto/e2ee ./tunnel/server"
GO_ROUNDTRIP_CMD="GOMAXPROCS=${GOMAXPROCS} GOMEMLIMIT=${GOMEMLIMIT} go test -run '^$' -bench '^BenchmarkSecureChannelRoundTrip/65536B$' -benchmem -count=10 ./crypto/e2ee"
TS_BENCH_CMD="NODE_OPTIONS=${NODE_OPTIONS} npm run bench"
LOADGEN_CMD="GOMAXPROCS=${GOMAXPROCS} GOMEMLIMIT=${GOMEMLIMIT} go run ./internal/cmd/flowersec-loadgen --channels=${LOADGEN_CHANNELS} --rate=${LOADGEN_RATE} --ramp-step=${LOADGEN_RAMP_STEP} --ramp-interval=${LOADGEN_RAMP_INTERVAL} --steady=${LOADGEN_STEADY} --report-interval=${LOADGEN_REPORT_INTERVAL} --stream-benchmark-bytes=16777216 --fair-stream-bytes=2097152 --fair-streams=8"

GO_OUT="$(mktemp)"
GO_ROUNDTRIP_OUT="$(mktemp)"
TS_OUT="$(mktemp)"
LOADGEN_OUT="$(mktemp)"

cleanup() {
  rm -f "${GO_OUT}" "${GO_ROUNDTRIP_OUT}" "${TS_OUT}" "${LOADGEN_OUT}"
}
trap cleanup EXIT

echo "[bench] running go benchmarks..."
(cd "${GO_DIR}" && GOMAXPROCS="${GOMAXPROCS}" GOMEMLIMIT="${GOMEMLIMIT}" go test -bench . -benchmem ./crypto/e2ee ./tunnel/server) | tee "${GO_OUT}"

echo "[bench] running repeated go 64 KiB round-trip benchmark..."
(cd "${GO_DIR}" && GOMAXPROCS="${GOMAXPROCS}" GOMEMLIMIT="${GOMEMLIMIT}" go test -run '^$' \
  -bench '^BenchmarkSecureChannelRoundTrip/65536B$' \
  -benchmem \
  -count=10 \
  ./crypto/e2ee) | tee "${GO_ROUNDTRIP_OUT}"

echo "[bench] running ts benchmarks..."
(cd "${TS_DIR}" && NODE_OPTIONS="${NODE_OPTIONS}" NO_COLOR=1 FORCE_COLOR=0 npm run bench) | tee "${TS_OUT}"

echo "[bench] running load generator..."
(cd "${GO_DIR}" && GOMAXPROCS="${GOMAXPROCS}" GOMEMLIMIT="${GOMEMLIMIT}" go run ./internal/cmd/flowersec-loadgen \
  --channels="${LOADGEN_CHANNELS}" \
  --rate="${LOADGEN_RATE}" \
  --ramp-step="${LOADGEN_RAMP_STEP}" \
  --ramp-interval="${LOADGEN_RAMP_INTERVAL}" \
  --steady="${LOADGEN_STEADY}" \
  --report-interval="${LOADGEN_REPORT_INTERVAL}" \
  --stream-benchmark-bytes=16777216 \
  --fair-stream-bytes=2097152 \
  --fair-streams=8) > "${LOADGEN_OUT}"

python3 "${ROOT_DIR}/tools/bench/bench_check.py" \
  --go-roundtrip-output "${GO_ROUNDTRIP_OUT}" \
  --go-roundtrip-baseline-ns "${GO_ROUNDTRIP_BASELINE_NS}" \
  --go-roundtrip-max-regression-percent "${GO_ROUNDTRIP_MAX_REGRESSION_PERCENT}" \
  --ts-output "${TS_OUT}" \
  --loadgen-output "${LOADGEN_OUT}" \
  --expected-channels "${LOADGEN_CHANNELS}" \
  --stream-throughput-baseline-mib-per-sec "${STREAM_THROUGHPUT_BASELINE_MIB_PER_SEC}" \
  --stream-ttfb-baseline-ms "${STREAM_TTFB_BASELINE_MS}" \
  --stream-max-regression-percent "${STREAM_MAX_REGRESSION_PERCENT}" \
  --max-heap-bytes "${MAX_HEAP_BYTES}" \
  --max-fairness-ratio "${MAX_FAIRNESS_RATIO}"

RUN_DATE="$(LC_ALL=C date)"
OS_VERSION="$(sw_vers -productVersion)"
CPU_MODEL="$(sysctl -n machdep.cpu.brand_string)"
RAM_BYTES="$(sysctl -n hw.memsize)"
GO_VERSION="$(cd "${GO_DIR}" && go version)"
NODE_VERSION="$(cd "${TS_DIR}" && node -v)"

python3 "${ROOT_DIR}/tools/bench/bench_report.py" \
  --go-output "${GO_OUT}" \
  --go-roundtrip-output "${GO_ROUNDTRIP_OUT}" \
  --go-roundtrip-baseline-ns "${GO_ROUNDTRIP_BASELINE_NS}" \
  --go-roundtrip-max-regression-percent "${GO_ROUNDTRIP_MAX_REGRESSION_PERCENT}" \
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
  --go-roundtrip-command "${GO_ROUNDTRIP_CMD}" \
  --ts-command "${TS_BENCH_CMD}" \
  --loadgen-command "${LOADGEN_CMD}" \
  --stream-throughput-baseline-mib-per-sec "${STREAM_THROUGHPUT_BASELINE_MIB_PER_SEC}" \
  --stream-ttfb-baseline-ms "${STREAM_TTFB_BASELINE_MS}" \
  --stream-max-regression-percent "${STREAM_MAX_REGRESSION_PERCENT}" \
  --max-heap-bytes "${MAX_HEAP_BYTES}" \
  --max-fairness-ratio "${MAX_FAIRNESS_RATIO}"

echo "[bench] wrote ${OUT_FILE}"
echo "[bench] preview:"
sed -n '1,120p' "${OUT_FILE}"
