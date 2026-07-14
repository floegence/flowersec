# Benchmark Results

Run date: Tue Jul 14 10:01:24 CST 2026

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
| BenchmarkLooksLikeRecordFrame-2 | 0.8716 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 158438 | 20813 | 249 |
| BenchmarkHandshakeSuiteP256-2 | 118401 | 22809 | 261 |
| BenchmarkEncryptRecord/256B-2 | 399.2 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 612.9 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2475 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16431 | 148776 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 319662 | 2115118 | 6 |
| BenchmarkDecryptRecord/256B-2 | 480.8 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 501.6 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1820 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 11537 | 66834 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 203960 | 1050401 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 2851 | 4560 | 21 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 3654 | 7856 | 21 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 8415 | 39984 | 21 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 48378 | 290103 | 21 |

### 64 KiB Round-Trip Throughput Gate

The baseline was measured from `origin/main` under the environment and Go constraints above.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 40824.0 | 42327.0 | 3.68% | 10.00% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 48.50 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 93.20 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.59 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| handshake_x25519 | 273.93 | 3.6506 | 6.9879 | 7.5342 |
| handshake_p256 | 191.12 | 5.2322 | 11.0747 | 11.0747 |

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| encrypt_256B | 51,871.98 | 0.0193 | 0.1112 | 12.7717 |
| decrypt_256B | 68,770.54 | 0.0145 | 0.0732 | 1.0168 |
| encrypt_1024B | 34,455.15 | 0.0290 | 0.1107 | 1.2977 |
| decrypt_1024B | 39,647.57 | 0.0252 | 0.0355 | 0.2334 |
| encrypt_8192B | 7,583.77 | 0.1319 | 0.3172 | 0.6258 |
| decrypt_8192B | 7,205.40 | 0.1388 | 0.3461 | 0.8070 |
| encrypt_65536B | 937.44 | 1.0667 | 2.4510 | 6.8562 |
| decrypt_65536B | 942.50 | 1.0610 | 2.7795 | 7.9911 |
| encrypt_1048576B | 68.8384 | 14.5268 | 16.0100 | 16.0100 |
| decrypt_1048576B | 73.8588 | 13.5393 | 15.5506 | 15.5506 |

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
| open_stream | 78,674.33 | 0.0127 | 0.0159 | 0.1717 |

## Load Generator (full mode)

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.6463 |
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
| ws_open | 0.332625 | 0.498625 | 0.785250 | 0.354486 | 0.145542 | 4.142542 |
| attach_send | 0.006375 | 0.010542 | 0.021750 | 0.007007 | 0.003083 | 0.047416 |
| pair_ready | 0.273291 | 0.429958 | 0.816458 | 0.295958 | 0.185416 | 1.412042 |
| handshake | 0.513916 | 0.794625 | 1.265084 | 0.541587 | 0.345916 | 2.621375 |
| rpc_call | 0.344167 | 0.582208 | 0.890125 | 0.393080 | 0.191958 | 5.957167 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 102,967,896 |
| max_heap_inuse_bytes | 109,928,448 |
| max_sys_bytes | 166,017,336 |
| max_goroutines | 10,015 |
| baseline_goroutines | 6 |
| after_close_goroutines | 7 |
