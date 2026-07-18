# Benchmark Results

Run date: Sat Jul 18 22:44:49 CST 2026

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
| BenchmarkLooksLikeRecordFrame-2 | 0.8087 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 161227 | 20811 | 249 |
| BenchmarkHandshakeSuiteP256-2 | 119543 | 22810 | 261 |
| BenchmarkEncryptRecord/256B-2 | 387.5 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 616.0 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2430 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16085 | 148778 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 266766 | 2115111 | 6 |
| BenchmarkDecryptRecord/256B-2 | 336.8 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 480.4 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1764 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 11131 | 66833 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 183749 | 1050398 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 2733 | 4560 | 21 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 3262 | 7856 | 21 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 8446 | 39984 | 21 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 42962 | 290103 | 21 |

### 64 KiB Round-Trip Throughput Gate

The baseline was measured from `origin/main` under the environment and Go constraints above.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 40824.0 | 41850.5 | 2.51% | 15.00% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 45.70 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 90.31 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.18 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| handshake_x25519 | 362.88 | 2.7558 | 3.2647 | 3.5374 |
| handshake_p256 | 218.54 | 4.5759 | 5.0714 | 7.0451 |

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| encrypt_256B | 85,030.72 | 0.0118 | 0.0166 | 0.2973 |
| decrypt_256B | 85,959.69 | 0.0116 | 0.0168 | 0.1587 |
| encrypt_1024B | 42,629.61 | 0.0235 | 0.0298 | 0.0992 |
| decrypt_1024B | 42,695.22 | 0.0234 | 0.0307 | 0.1564 |
| encrypt_8192B | 8,036.33 | 0.1244 | 0.2030 | 0.7829 |
| decrypt_8192B | 8,314.42 | 0.1203 | 0.1485 | 3.5780 |
| encrypt_65536B | 1,057.70 | 0.9454 | 2.3864 | 4.1268 |
| decrypt_65536B | 1,139.98 | 0.8772 | 1.0939 | 1.1348 |
| encrypt_1048576B | 76.4471 | 13.0809 | 13.9309 | 13.9309 |
| decrypt_1048576B | 76.5245 | 13.0677 | 13.5885 | 13.5885 |

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| discard_fragmented_chunks | 1,962.91 | 0.5094 | 0.5553 | 0.6215 |
| open_stream | 93,275.27 | 0.0107 | 0.0137 | 0.1277 |

## Load Generator

The load generator uses `client.Connect`; its RPC bootstrap stream remains open for the connection lifetime.

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 41.0355 |
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
| connect_total | 0.991292 | 1.543708 | 3.935333 | 1.080311 | 0.600458 | 6.143875 |
| ws_open | 0.349875 | 0.606084 | 1.224875 | 0.385751 | 0.186000 | 2.536125 |
| handshake | 0.610333 | 0.849791 | 0.925209 | 0.649978 | 0.394375 | 3.918667 |
| rpc_call | 0.502791 | 0.764750 | 1.399667 | 0.502180 | 0.199792 | 3.153541 |

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
| throughput samples (MiB/s) | 168.983, 640.729, 238.000 |
| transfer time (ms) | 67.227 |
| throughput (MiB/s) | 238.000 |
| throughput baseline (MiB/s) | 279.770 |
| throughput regression | 14.93% |
| TTFB samples (ms) | 0.379, 0.743, 0.238 |
| TTFB (ms) | 0.379 |
| TTFB baseline (ms) | 0.654 |
| TTFB regression | -42.02% |
| concurrent equal streams | 8 |
| bytes per fairness stream | 2,097,152 |
| fairness completion times (ms) | 26.470, 26.481, 26.496, 26.503, 26.513, 29.047, 29.507, 29.514 |
| fairness median (ms) | 26.508 |
| fairness slowest (ms) | 29.514 |
| fairness slowest/median | 1.113 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 371,114,856 |
| max_heap_inuse_bytes | 394,502,144 |
| max_sys_bytes | 584,628,632 |
| max_goroutines | 48,083 |
| baseline_goroutines | 6 |
| after_close_goroutines | 7 |
