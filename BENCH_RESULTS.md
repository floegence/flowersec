# Benchmark Results

Run date: Tue Jul 14 23:49:15 CST 2026

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

# Load generator (full mode, loopback)
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go run ./internal/cmd/flowersec-loadgen --mode=full --channels=1000 --rate=400 --ramp-step=200 --ramp-interval=2s --steady=30s --report-interval=1s
```

## Go Benchmarks

### E2EE (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkLooksLikeRecordFrame-2 | 0.9161 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 152131 | 20811 | 249 |
| BenchmarkHandshakeSuiteP256-2 | 116503 | 22810 | 261 |
| BenchmarkEncryptRecord/256B-2 | 451.5 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 632.2 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2553 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16971 | 148776 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 284091 | 2115113 | 6 |
| BenchmarkDecryptRecord/256B-2 | 376.3 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 505.2 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1885 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 11612 | 66834 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 185065 | 1050358 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 2801 | 4560 | 21 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 4554 | 7856 | 21 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 9267 | 39984 | 21 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 45794 | 290104 | 21 |

### 64 KiB Round-Trip Throughput Gate

The baseline was measured from `origin/main` under the environment and Go constraints above.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 40824.0 | 42160.0 | 3.27% | 10.00% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 48.08 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 99.96 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.61 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| handshake_x25519 | 320.45 | 3.1206 | 7.7535 | 8.1243 |
| handshake_p256 | 192.66 | 5.1905 | 10.8528 | 10.8528 |

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| encrypt_256B | 61,457.96 | 0.0163 | 0.0764 | 9.7379 |
| decrypt_256B | 54,366.96 | 0.0184 | 0.1016 | 13.5800 |
| encrypt_1024B | 40,230.60 | 0.0249 | 0.0322 | 0.3378 |
| decrypt_1024B | 38,970.44 | 0.0257 | 0.0390 | 0.2207 |
| encrypt_8192B | 8,266.36 | 0.1210 | 0.1664 | 0.2757 |
| decrypt_8192B | 8,268.10 | 0.1209 | 0.1778 | 1.1095 |
| encrypt_65536B | 1,119.29 | 0.8934 | 1.0504 | 1.7939 |
| decrypt_65536B | 1,115.23 | 0.8967 | 1.0914 | 1.8457 |
| encrypt_1048576B | 71.9692 | 13.8948 | 16.1205 | 16.1205 |
| decrypt_1048576B | 74.9829 | 13.3364 | 14.9592 | 14.9592 |

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| open_stream | 91,931.13 | 0.0109 | 0.0140 | 0.1722 |

## Load Generator (full mode)

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.6535 |
| peak_conn_per_sec | 200 |
| active_peak | 1000 |

### Config

| Key | Value |
| --- | --- |
| mode | full |
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
| max_pending_bytes | 262144 |
| idle_timeout_ms | 60000 |
| liveness_interval_ms | 30000 |
| liveness_timeout_ms | 10000 |
| rpc_stream_residency | closed_after_verified_call |
| cleanup_interval_ms | 50 |
| max_conns | 0 |
| max_channels | 0 |

### Latency (ms)

| Stage | p50 | p95 | p99 | mean | min | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ws_open | 0.322542 | 0.601791 | 1.090166 | 0.353209 | 0.091542 | 3.383875 |
| attach_send | 0.006875 | 0.017500 | 0.036709 | 0.008301 | 0.003334 | 0.075958 |
| pair_ready | 0.294250 | 0.571292 | 1.152667 | 0.325478 | 0.137541 | 3.905334 |
| handshake | 0.544750 | 0.917333 | 1.871709 | 0.588162 | 0.267417 | 5.341625 |
| rpc_call | 0.350416 | 0.635125 | 1.542584 | 0.410513 | 0.108500 | 4.131750 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 111,213,736 |
| max_heap_inuse_bytes | 115,843,072 |
| max_sys_bytes | 174,401,832 |
| max_goroutines | 10,015 |
| baseline_goroutines | 6 |
| after_close_goroutines | 7 |
