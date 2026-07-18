# Benchmark Results

Run date: Sun Jul 19 01:03:25 CST 2026

## Environment

- OS: macOS 26.5.1
- CPU: Apple M3 Pro
- RAM: 18.0 GB
- Go: go version go1.26.5 darwin/arm64
- Node: v24.14.1
- Constraints used:
  - Go: `GOMAXPROCS=2`, `GOMEMLIMIT=1024MiB`
  - Node: `NODE_OPTIONS=--max-old-space-size=768`

## Commands

```bash
# Go micro benches
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go test -bench . -benchmem ./crypto/e2ee ./tunnel/server

# Go 64 KiB round-trip throughput gate
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go test -run '^$' -bench '^BenchmarkSecureChannelRoundTrip/65536B$' -benchmem -count=10 ./crypto/e2ee

# TS micro benches
NODE_OPTIONS=--max-old-space-size=768 npm run bench

# Load generator (high-level connection, loopback)
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go run ./internal/cmd/flowersec-loadgen --channels=1000 --rate=400 --ramp-step=200 --ramp-interval=2s --steady=30s --report-interval=1s --stream-benchmark-bytes=16777216 --fair-stream-bytes=2097152 --fair-streams=8
```

## Go Benchmarks

### E2EE (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkLooksLikeRecordFrame-2 | 0.8443 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 149644 | 20811 | 249 |
| BenchmarkHandshakeSuiteP256-2 | 110062 | 22810 | 261 |
| BenchmarkEncryptRecord/256B-2 | 415.3 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 594.8 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2374 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16124 | 148776 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 296506 | 2115109 | 6 |
| BenchmarkDecryptRecord/256B-2 | 337.7 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 505.3 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1934 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 11226 | 66834 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 194697 | 1050395 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 2725 | 4560 | 21 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 3312 | 7856 | 21 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 8636 | 39984 | 21 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 42840 | 290103 | 21 |

### 64 KiB Round-Trip Throughput Gate

The baseline was measured from `origin/main` under the environment and Go constraints above.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 40824.0 | 39235.0 | -3.89% | 15.00% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 48.46 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 92.21 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.48 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| handshake_x25519 | 262.45 | 3.8102 | 6.7932 | 29.0193 |
| handshake_p256 | 121.59 | 8.2243 | 28.0948 | 28.0948 |

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| encrypt_256B | 50,915.89 | 0.0196 | 0.0905 | 6.5462 |
| decrypt_256B | 20,865.81 | 0.0479 | 0.3142 | 24.9923 |
| encrypt_1024B | 26,169.62 | 0.0382 | 0.1517 | 13.8017 |
| decrypt_1024B | 35,545.01 | 0.0281 | 0.0974 | 1.0434 |
| encrypt_8192B | 2,211.88 | 0.4521 | 4.8744 | 44.1652 |
| decrypt_8192B | 7,660.46 | 0.1305 | 0.2665 | 1.5133 |
| encrypt_65536B | 1,021.10 | 0.9793 | 1.6456 | 2.1438 |
| decrypt_65536B | 1,063.52 | 0.9403 | 1.2691 | 1.9202 |
| encrypt_1048576B | 67.8630 | 14.7356 | 16.8715 | 16.8715 |
| decrypt_1048576B | 58.1730 | 17.1901 | 20.4696 | 20.4696 |

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| discard_fragmented_chunks | 1,361.66 | 0.7344 | 1.4685 | 2.0482 |
| open_stream | 60,485.66 | 0.0165 | 0.0778 | 0.5941 |

## Load Generator

The load generator uses `client.Connect`; its RPC bootstrap stream remains open for the connection lifetime.

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.9760 |
| peak_conn_per_sec | 200 |
| active_peak | 1000 |

### Config

| Key | Value |
| --- | --- |
| channels | 1000 |
| rate_per_sec | 400 |
| ramp_step | 200 |
| ramp_interval_ms | 2000 |
| steady_duration_ms | 30000 |
| workers | 64 |
| conn_timeout_ms | 10000 |
| rpc_timeout_ms | 5000 |
| report_interval_ms | 1000 |
| max_handshake_bytes | 8192 |
| max_record_bytes | 1048576 |
| max_buffered_bytes | 4194304 |
| stream_bytes | 16777216 |
| fair_stream_bytes | 2097152 |
| fair_streams | 8 |
| max_pending_bytes | 262144 |
| idle_timeout_ms | 60000 |
| liveness_interval_ms | 30000 |
| liveness_timeout_ms | 10000 |
| connection_api | client.Connect |
| rpc_stream_residency | connection_lifetime |
| cleanup_interval_ms | 50 |
| max_conns | 0 |
| max_channels | 0 |

### Latency (ms)

| Stage | p50 | p95 | p99 | mean | min | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| connect_total | 0.792834 | 1.650250 | 2.800875 | 0.905694 | 0.505416 | 6.180125 |
| ws_open | 0.290416 | 0.541209 | 0.943375 | 0.318855 | 0.138500 | 1.385625 |
| handshake | 0.443584 | 0.935292 | 1.393875 | 0.515074 | 0.332667 | 1.608042 |
| rpc_call | 0.281000 | 0.632333 | 1.038791 | 0.343046 | 0.189292 | 2.002375 |

### Streaming Transfer and Fairness

The manual machine-sensitive gate allows at most 15.00% throughput/TTFB regression, a peak heap of 536,870,912 bytes, and a slowest/median fairness ratio of 2.00.
Each loadgen run reports the median of three 16 MiB transfers on one high-level connection and preserves all raw samples below.
Before timed transfers, an unmeasured 8 x 2 MiB concurrent probe samples heap usage and warms the streaming path.
The eight equal-size fairness streams are released from one barrier and measured from a shared start time.

| Metric | Value |
| --- | ---: |
| transfer bytes | 16,777,216 |
| background connections | 1,000 |
| transfer samples | 3 |
| throughput samples (MiB/s) | 317.951, 370.752, 236.105 |
| transfer time (ms) | 50.322 |
| throughput (MiB/s) | 317.951 |
| throughput baseline (MiB/s) | 279.770 |
| throughput regression | -13.65% |
| TTFB samples (ms) | 0.250, 1.143, 0.219 |
| TTFB (ms) | 0.250 |
| TTFB baseline (ms) | 0.654 |
| TTFB regression | -61.72% |
| concurrent equal streams | 8 |
| bytes per fairness stream | 2,097,152 |
| fairness completion times (ms) | 15.530, 18.124, 18.656, 18.914, 19.086, 19.096, 19.326, 19.371 |
| fairness median (ms) | 19.000 |
| fairness slowest (ms) | 19.371 |
| fairness slowest/median | 1.020 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 346,081,848 |
| max_heap_inuse_bytes | 369,557,504 |
| max_sys_bytes | 589,052,312 |
| max_goroutines | 48,083 |
| baseline_goroutines | 6 |
| after_close_goroutines | 7 |
