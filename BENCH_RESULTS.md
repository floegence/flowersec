# Benchmark Results

Run date: Tue Jul 14 21:44:32 CST 2026

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
| BenchmarkLooksLikeRecordFrame-2 | 0.8228 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 156293 | 20813 | 249 |
| BenchmarkHandshakeSuiteP256-2 | 119878 | 22809 | 261 |
| BenchmarkEncryptRecord/256B-2 | 391.6 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 616.1 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2443 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16461 | 148777 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 261251 | 2115099 | 6 |
| BenchmarkDecryptRecord/256B-2 | 345.6 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 481.9 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1801 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 14955 | 66833 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 201362 | 1050505 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 2762 | 4560 | 21 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 3270 | 7856 | 21 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 8522 | 39984 | 21 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 43827 | 290103 | 21 |

### 64 KiB Round-Trip Throughput Gate

The baseline was measured from `origin/main` under the environment and Go constraints above.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 40824.0 | 41965.0 | 2.79% | 10.00% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 47.04 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 92.30 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.55 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| handshake_x25519 | 354.18 | 2.8234 | 3.2363 | 3.2448 |
| handshake_p256 | 229.81 | 4.3514 | 5.1975 | 7.7978 |

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| encrypt_256B | 83,200.21 | 0.0120 | 0.0169 | 0.2212 |
| decrypt_256B | 85,195.42 | 0.0117 | 0.0161 | 0.1461 |
| encrypt_1024B | 38,938.54 | 0.0257 | 0.0697 | 1.8865 |
| decrypt_1024B | 38,050.06 | 0.0263 | 0.0626 | 5.4034 |
| encrypt_8192B | 7,709.71 | 0.1297 | 0.2500 | 1.5851 |
| decrypt_8192B | 8,312.43 | 0.1203 | 0.1626 | 0.4212 |
| encrypt_65536B | 1,097.01 | 0.9116 | 1.1783 | 1.3789 |
| decrypt_65536B | 1,047.81 | 0.9544 | 2.2906 | 4.0932 |
| encrypt_1048576B | 70.4752 | 14.1894 | 18.5097 | 18.5097 |
| decrypt_1048576B | 66.7181 | 14.9884 | 20.1764 | 20.1764 |

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| open_stream | 89,935.74 | 0.0111 | 0.0220 | 1.3321 |

## Load Generator (full mode)

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.6481 |
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
| ws_open | 0.292334 | 0.552125 | 1.232792 | 0.337782 | 0.152042 | 3.743958 |
| attach_send | 0.006375 | 0.012875 | 0.030500 | 0.007394 | 0.003125 | 0.056708 |
| pair_ready | 0.271542 | 0.486792 | 1.496542 | 0.335729 | 0.174625 | 9.951041 |
| handshake | 0.492542 | 0.882833 | 4.016833 | 0.604744 | 0.338708 | 10.751459 |
| rpc_call | 0.297750 | 0.596166 | 1.233875 | 0.378136 | 0.183583 | 4.407000 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 115,733,480 |
| max_heap_inuse_bytes | 120,406,016 |
| max_sys_bytes | 174,663,976 |
| max_goroutines | 10,015 |
| baseline_goroutines | 6 |
| after_close_goroutines | 7 |
