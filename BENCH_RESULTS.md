# Benchmark Results

Run date: Mon Jan 19 15:01:20 CST 2026

## Environment

- OS: macOS 26.2
- CPU: Apple M3 Pro
- RAM: 18.0 GB
- Go: go version go1.25.6 darwin/arm64
- Node: v25.3.0
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
GOMAXPROCS=2 GOMEMLIMIT=1024MiB go run ./internal/cmd/flowersec-loadgen --mode=full --channels=1000 --rate=400 --ramp-step=200 --ramp-interval=2s --steady=30s --report-interval=1s
```

## Go Benchmarks

### E2EE (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkLooksLikeRecordFrame-2 | 0.7836 | 0 | 0 |
| BenchmarkHandshakeSuiteX25519-2 | 140901 | 20687 | 252 |
| BenchmarkHandshakeSuiteP256-2 | 106851 | 22681 | 263 |
| BenchmarkEncryptRecord/256B-2 | 365.1 | 1928 | 6 |
| BenchmarkEncryptRecord/1024B-2 | 575.2 | 3624 | 6 |
| BenchmarkEncryptRecord/8192B-2 | 2401 | 20264 | 6 |
| BenchmarkEncryptRecord/65536B-2 | 16321 | 148777 | 6 |
| BenchmarkEncryptRecord/1048576B-2 | 264556 | 2115092 | 6 |
| BenchmarkDecryptRecord/256B-2 | 321.5 | 1552 | 4 |
| BenchmarkDecryptRecord/1024B-2 | 453.2 | 2320 | 4 |
| BenchmarkDecryptRecord/8192B-2 | 1697 | 9488 | 4 |
| BenchmarkDecryptRecord/65536B-2 | 10977 | 66833 | 4 |
| BenchmarkDecryptRecord/1048576B-2 | 177680 | 1050354 | 4 |
| BenchmarkSecureChannelRoundTrip/256B-2 | 1906 | 4072 | 15 |
| BenchmarkSecureChannelRoundTrip/1024B-2 | 2455 | 7368 | 15 |
| BenchmarkSecureChannelRoundTrip/8192B-2 | 7115 | 39496 | 15 |
| BenchmarkSecureChannelRoundTrip/65536B-2 | 41569 | 289615 | 15 |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| BenchmarkRouteOrBufferPaired-2 | 46.16 | 0 | 0 |
| BenchmarkRouteOrBufferPending-2 | 70.05 | 320 | 1 |
| BenchmarkAllowReplaceLocked-2 | 14.63 | 0 | 0 |

## TypeScript Benchmarks

### E2EE Handshake (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
| handshake_x25519 | 386.63 | 2.5864 |
| handshake_p256 | 253.68 | 3.9420 |

### E2EE Record (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
| encrypt_256B | 85,853.99 | 0.0116 |
| decrypt_256B | 86,172.15 | 0.0116 |
| encrypt_1024B | 42,280.62 | 0.0237 |
| decrypt_1024B | 42,593.16 | 0.0235 |
| encrypt_8192B | 7,986.79 | 0.1252 |
| decrypt_8192B | 8,251.84 | 0.1212 |
| encrypt_65536B | 1,175.73 | 0.8505 |
| decrypt_65536B | 1,163.73 | 0.8593 |
| encrypt_1048576B | 77.2916 | 12.9380 |
| decrypt_1048576B | 77.2961 | 12.9373 |

### Yamux (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
| open_stream | 82,969.85 | 0.0121 |

## Load Generator (full mode)

### Summary

| Metric | Value |
| --- | ---: |
| attempts | 1000 |
| success | 1000 |
| failure | 0 |
| success_rate | 1 |
| duration_seconds | 40.6300 |
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
| ws_open | 0.280959 | 0.438250 | 0.654500 | 0.296458 | 0.160708 | 1.262875 |
| attach_send | 0.005917 | 0.009209 | 0.012917 | 0.006167 | 0.003208 | 0.025667 |
| pair_ready | 0.285250 | 0.397041 | 0.478750 | 0.296619 | 0.189833 | 0.990041 |
| handshake | 0.530958 | 0.737750 | 0.997209 | 0.553735 | 0.365750 | 1.660375 |
| rpc_call | 0.415000 | 0.637458 | 0.753292 | 0.435818 | 0.206541 | 1.410375 |

### Resources (peak)

| Metric | Value |
| --- | ---: |
| max_heap_alloc_bytes | 104,990,632 |
| max_heap_inuse_bytes | 107,159,552 |
| max_sys_bytes | 178,170,152 |
| max_goroutines | 14,007 |
