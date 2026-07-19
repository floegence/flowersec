# Benchmark Results

Run date: Sun Jul 19 16:57:31 CST 2026

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

# Go 64 KiB round-trip throughput measurement (manual)
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
| BenchmarkLooksLikeRecordFrame-2 | 0.8277 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 150720 | 20811 | 249 |
| BenchmarkHandshakeSuiteP256-2 | 119626 | 22810 | 261 |
| BenchmarkEncryptRecord/256B-2 | 431.9 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 673.7 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2592 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 17135 | 148777 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 280325 | 2115112 | 6 |
| BenchmarkDecryptRecord/256B-2 | 356.1 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 501.6 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1787 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 11448 | 66834 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 192655 | 1050389 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 3002 | 4560 | 21 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 3394 | 7856 | 21 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 8992 | 39984 | 21 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 45747 | 290105 | 21 |

### Manual 64 KiB Round-Trip Throughput Evidence

The baseline was measured from `origin/main` under the environment and Go constraints above. This machine-sensitive comparison is reviewed manually and is not a release gate.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 40824.0 | 42538.5 | 4.20% | 15.00% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 48.24 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 106.9 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 17.17 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| handshake_x25519 | 344.08 | 2.9063 | 5.3873 | 6.7256 |
| handshake_p256 | 191.86 | 5.2121 | 14.7943 | 14.7943 |

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| encrypt_256B | 80,651.43 | 0.0124 | 0.0260 | 2.9476 |
| decrypt_256B | 78,081.89 | 0.0128 | 0.0403 | 0.2872 |
| encrypt_1024B | 40,143.61 | 0.0249 | 0.0486 | 0.2734 |
| decrypt_1024B | 41,522.01 | 0.0241 | 0.0326 | 0.3679 |
| encrypt_8192B | 8,188.99 | 0.1221 | 0.1677 | 0.2579 |
| decrypt_8192B | 8,365.09 | 0.1195 | 0.1494 | 2.2894 |
| encrypt_65536B | 1,112.12 | 0.8992 | 1.0815 | 1.1192 |
| decrypt_65536B | 1,136.41 | 0.8800 | 1.0862 | 1.5234 |
| encrypt_1048576B | 77.6102 | 12.8849 | 13.6227 | 13.6227 |
| decrypt_1048576B | 68.8724 | 14.5196 | 22.1990 | 22.1990 |

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| discard_fragmented_chunks | 1,871.00 | 0.5345 | 0.6532 | 0.8282 |
| open_stream | 87,316.48 | 0.0115 | 0.0168 | 0.2530 |

## Load Generator

The load generator uses `client.Connect`; its RPC bootstrap stream remains open for the connection lifetime.

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.9407 |
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
| connect_total | 0.967208 | 1.542584 | 2.230209 | 1.036808 | 0.574458 | 4.312500 |
| ws_open | 0.350792 | 0.549000 | 0.864167 | 0.370128 | 0.186333 | 1.588375 |
| handshake | 0.600042 | 0.925833 | 1.119166 | 0.628349 | 0.365208 | 1.409125 |
| rpc_call | 0.433083 | 0.634625 | 1.026417 | 0.442156 | 0.194000 | 1.761084 |

### Streaming Transfer and Fairness

The manual machine-sensitive comparison allows at most 15.00% throughput/TTFB regression, a peak heap of 536,870,912 bytes, and a slowest/median fairness ratio of 2.00.
Each loadgen run reports the median of three 16 MiB transfers on one high-level connection and preserves all raw samples below.
Before timed transfers, an unmeasured 8 x 2 MiB concurrent probe samples heap usage and warms the streaming path.
The eight equal-size fairness streams are released from one barrier and measured from a shared start time.

| Metric | Value |
| --- | ---: |
| transfer bytes | 16,777,216 |
| background connections | 1,000 |
| transfer samples | 3 |
| throughput samples (MiB/s) | 316.083, 293.912, 329.444 |
| transfer time (ms) | 50.620 |
| throughput (MiB/s) | 316.083 |
| throughput baseline (MiB/s) | 279.770 |
| throughput regression | -12.98% |
| TTFB samples (ms) | 0.258, 0.790, 0.238 |
| TTFB (ms) | 0.258 |
| TTFB baseline (ms) | 0.654 |
| TTFB regression | -60.46% |
| concurrent equal streams | 8 |
| bytes per fairness stream | 2,097,152 |
| fairness completion times (ms) | 42.721, 43.504, 45.430, 45.445, 46.933, 47.046, 47.264, 47.325 |
| fairness median (ms) | 46.189 |
| fairness slowest (ms) | 47.325 |
| fairness slowest/median | 1.025 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 225,160,816 |
| max_heap_inuse_bytes | 238,264,320 |
| max_sys_bytes | 372,676,952 |
| max_goroutines | 16,051 |
| baseline_goroutines | 6 |
| steady_state_goroutines | 16,007 |
| after_close_goroutines | 7 |
