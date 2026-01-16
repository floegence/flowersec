# Benchmark Results

Run date: Fri Jan 16 10:09:26 CST 2026

## Environment

- OS: macOS 26.2
- CPU: Apple M3 Pro
- RAM: 18.0 GB
- Go: go version go1.25.6 darwin/arm64
- Node: v23.7.0
- Constraints used:
  - Go: `GOMAXPROCS=2`, `GOMEMLIMIT=1024MiB`
  - Node: `NODE_OPTIONS=--max-old-space-size=768`

## Commands

```bash
# Go micro benches
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go test -bench . -benchmem ./crypto/e2ee ./tunnel/server

# TS micro benches
NODE_OPTIONS=--max-old-space-size=768 npm run bench

# Load generator (full mode, loopback)
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go run ./cmd/flowersec-loadgen --mode=full --channels=1000 --rate=400 --ramp-step=200 --ramp-interval=2s --steady=30s --report-interval=1s
```

## Go Benchmarks

### E2EE (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkLooksLikeRecordFrame-2 | 0.7962 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 168416 | 16893 | 236 |
| BenchmarkHandshakeSuiteP256-2 | 100219 | 18891 | 247 |
| BenchmarkEncryptRecord/256B-2 | 355.3 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 573.0 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2309 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16059 | 148779 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 233687 | 2115112 | 7 |
| BenchmarkDecryptRecord/256B-2 | 312.7 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 447.1 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1635 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 10889 | 66834 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 171822 | 1050387 | 4 |
| BenchmarkSecureConnRoundTrip/256B-2 | 1781 | 3960 | 14 |
| BenchmarkSecureConnRoundTrip/1024B-2 | 2358 | 7256 | 14 |
| BenchmarkSecureConnRoundTrip/8192B-2 | 7187 | 39384 | 14 |
| BenchmarkSecureConnRoundTrip/65536B-2 | 38154 | 289507 | 14 |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 44.63 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 70.93 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.88 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
| handshake_x25519 | 279.36 | 3.5796 |
| handshake_p256 | 259.60 | 3.8520 |

### E2EE Record (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
| encrypt_256B | 89,413.64 | 0.0112 |
| decrypt_256B | 91,542.92 | 0.0109 |
| encrypt_1024B | 43,872.83 | 0.0228 |
| decrypt_1024B | 44,321.12 | 0.0226 |
| encrypt_8192B | 8,738.89 | 0.1144 |
| decrypt_8192B | 8,713.67 | 0.1148 |
| encrypt_65536B | 1,187.94 | 0.8418 |
| decrypt_65536B | 1,198.08 | 0.8347 |
| encrypt_1048576B | 79.1926 | 12.6274 |
| decrypt_1048576B | 79.6513 | 12.5547 |

### Yamux (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
| open_stream | 92,461.62 | 0.0108 |

## Load Generator (full mode)

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.6470 |
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
| cleanup_interval_ms | 50 |
| max_conns | 0 |
| max_channels | 0 |

### Latency (ms)

| Stage | p50 | p95 | p99 | mean | min | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ws_open | 0.372125 | 0.856083 | 2.787792 | 0.463333 | 0.170334 | 7.410666 |
| attach_send | 0.006375 | 0.012292 | 0.040000 | 0.007735 | 0.002875 | 0.248459 |
| pair_ready | 0.349791 | 0.593583 | 3.237667 | 0.456963 | 0.194959 | 9.166542 |
| handshake | 0.411209 | 0.693375 | 3.382042 | 0.525801 | 0.238583 | 9.267958 |
| rpc_call | 0.563416 | 0.837167 | 2.767292 | 0.588668 | 0.209083 | 8.523500 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 78,909,840 |
| max_heap_inuse_bytes | 86,458,368 |
| max_sys_bytes | 158,704,688 |
| max_goroutines | 14,007 |

## Load Generator Sweep (limit search)

All runs: `GOMAXPROCS=2`, `GOMEMLIMIT=1024MiB`, `mode=full`, `workers=256`, `max_channels=20000`, `max_conns=40000`, `steady=30s`, `ramp_interval=2s`.

| channels | rate_per_sec | ramp_step | success_rate | active_peak | peak_conn_per_sec | failures | failure_stage | max_heap_inuse_bytes | max_goroutines |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: |
| 4000 | 1000 | 1000 | 1.000 | 4000 | 970 | 0 | - | 366,895,104 | 56,007 |
| 6000 | 1000 | 1000 | 0.883 | 5298 | 875 | 702 | ws_open | 489,996,288 | 74,291 |
| 8000 | 1000 | 1000 | 0.973 | 7787 | 780 | 213 | ws_open | 610,238,464 | 109,028 |
| 6000 | 600 | 1000 | 1.000 | 6000 | 564 | 0 | - | 612,073,472 | 84,007 |
| 7000 | 600 | 1000 | 0.813 | 5692 | 566 | 1308 | ws_open | 569,409,536 | 79,762 |

## Load Generator Sweep (peak rate, no ramp)

All runs: `GOMAXPROCS=2`, `GOMEMLIMIT=1024MiB`, `mode=full`, `workers=256`, `max_channels=20000`, `max_conns=40000`, `steady=30s`, `ramp_step=0`.

| channels | rate_per_sec | ramp_step | success_rate | active_peak | peak_conn_per_sec | failures | failure_stage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 4000 | 2000 | 0 | 1.000 | 4000 | 1913 | 0 | - |
| 4000 | 4000 | 0 | 1.000 | 4000 | 2208 | 0 | - |
