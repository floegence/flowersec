#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import re
import statistics


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(s: str) -> str:
    return ANSI_ESCAPE_RE.sub("", s)


def parse_go(path: str):
    pkg = ""
    out = {"e2ee": [], "tunnel": []}
    bench_re = re.compile(
        r"^(Benchmark\S+)\s+\d+\s+([0-9.]+) ns/op\s+([0-9.]+) B/op\s+(\d+) allocs/op$"
    )
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = strip_ansi(line).strip()
            if line.startswith("pkg:"):
                parts = line.split()
                if len(parts) >= 2:
                    pkg = parts[1]
                continue
            m = bench_re.match(line)
            if not m:
                continue
            name, ns_op, b_op, allocs = m.groups()
            item = {
                "name": name,
                "ns_op": ns_op,
                "b_op": b_op,
                "allocs": allocs,
            }
            if pkg.endswith("/crypto/e2ee"):
                out["e2ee"].append(item)
            elif pkg.endswith("/tunnel/server"):
                out["tunnel"].append(item)
    return out


def parse_go_roundtrip_samples(path: str):
    benchmark = re.compile(
        r"^BenchmarkSecureChannelRoundTrip/65536B-\d+\s+\d+\s+([0-9.]+) ns/op(?:\s|$)"
    )
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = benchmark.match(strip_ansi(line).strip())
            if match is not None:
                samples.append(float(match.group(1)))
    if len(samples) != 10:
        raise ValueError(f"expected 10 Go round-trip samples, got {len(samples)}")
    return samples


def parse_ts(path: str):
    section = None
    out = {"handshake": [], "record": [], "yamux": []}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = strip_ansi(line)
            if "> e2ee handshake" in line:
                section = "handshake"
                continue
            if "> e2ee record" in line:
                section = "record"
                continue
            if "> yamux" in line:
                section = "yamux"
                continue
            line = line.strip()
            if not line.startswith("·") or section is None:
                continue
            parts = line.replace("·", "").split()
            if len(parts) < 8:
                continue
            name = parts[0]
            hz = parts[1]
            mean = parts[4]
            p99 = parts[6]
            maximum = parts[3]
            out[section].append({"name": name, "hz": hz, "mean_ms": mean, "p99_ms": p99, "max_ms": maximum})
    return out


def fmt_int(v):
    return f"{int(v):,}"


def fmt_float(v, places=6):
    return f"{float(v):.{places}f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-output", required=True)
    parser.add_argument("--go-roundtrip-output", required=True)
    parser.add_argument("--go-roundtrip-baseline-ns", type=float, required=True)
    parser.add_argument("--go-roundtrip-max-regression-percent", type=float, required=True)
    parser.add_argument("--ts-output", required=True)
    parser.add_argument("--loadgen-output", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--run-date", default="")
    parser.add_argument("--os", required=True)
    parser.add_argument("--cpu", required=True)
    parser.add_argument("--ram-bytes", required=True)
    parser.add_argument("--go-version", required=True)
    parser.add_argument("--node-version", required=True)
    parser.add_argument("--gomaxprocs", required=True)
    parser.add_argument("--gomemlimit", required=True)
    parser.add_argument("--node-options", required=True)
    parser.add_argument("--go-command", required=True)
    parser.add_argument("--go-roundtrip-command", required=True)
    parser.add_argument("--ts-command", required=True)
    parser.add_argument("--loadgen-command", required=True)
    parser.add_argument("--stream-throughput-baseline-mib-per-sec", type=float, required=True)
    parser.add_argument("--stream-ttfb-baseline-ms", type=float, required=True)
    parser.add_argument("--stream-max-regression-percent", type=float, required=True)
    parser.add_argument("--max-heap-bytes", type=int, required=True)
    parser.add_argument("--max-fairness-ratio", type=float, required=True)
    args = parser.parse_args()

    run_date = args.run_date or dt.datetime.now().strftime("%c")

    go_bench = parse_go(args.go_output)
    go_roundtrip_samples = parse_go_roundtrip_samples(args.go_roundtrip_output)
    go_roundtrip_median = statistics.median(go_roundtrip_samples)
    go_roundtrip_regression = (
        go_roundtrip_median / args.go_roundtrip_baseline_ns - 1
    ) * 100
    ts_bench = parse_ts(args.ts_output)

    with open(args.loadgen_output, "r", encoding="utf-8") as f:
        loadgen = json.load(f)

    ram_gb = float(args.ram_bytes) / (1024 ** 3)
    env_lines = [
        f"- OS: {args.os}",
        f"- CPU: {args.cpu}",
        f"- RAM: {ram_gb:.1f} GB",
        f"- Go: {args.go_version}",
        f"- Node: {args.node_version}",
        "- Constraints used:",
        f"  - Go: `GOMAXPROCS={args.gomaxprocs}`, `GOMEMLIMIT={args.gomemlimit}`",
        f"  - Node: `NODE_OPTIONS={args.node_options}`",
    ]

    go_table = "\n".join(
        f"| {r['name']} | {r['ns_op']} | {r['b_op']} | {r['allocs']} |"
        for r in go_bench["e2ee"]
    )
    tunnel_table = "\n".join(
        f"| {r['name']} | {r['ns_op']} | {r['b_op']} | {r['allocs']} |"
        for r in go_bench["tunnel"]
    )

    handshake_table = "\n".join(
        f"| {r['name']} | {r['hz']} | {r['mean_ms']} | {r['p99_ms']} | {r['max_ms']} |"
        for r in ts_bench["handshake"]
    )
    record_table = "\n".join(
        f"| {r['name']} | {r['hz']} | {r['mean_ms']} | {r['p99_ms']} | {r['max_ms']} |"
        for r in ts_bench["record"]
    )
    yamux_table = "\n".join(
        f"| {r['name']} | {r['hz']} | {r['mean_ms']} | {r['p99_ms']} | {r['max_ms']} |"
        for r in ts_bench["yamux"]
    )

    summary = loadgen.get("summary", {})
    config = loadgen.get("config", {})
    latency = loadgen.get("latency", {})
    resources = loadgen.get("resources", {})
    streaming = loadgen.get("streaming", {})

    latency_rows = []
    for stage in ["connect_total", "ws_open", "handshake", "rpc_call"]:
        item = latency.get(stage, {})
        latency_rows.append(
            "| {stage} | {p50} | {p95} | {p99} | {mean} | {min} | {max} |".format(
                stage=stage,
                p50=fmt_float(item.get("p50_ms", 0)),
                p95=fmt_float(item.get("p95_ms", 0)),
                p99=fmt_float(item.get("p99_ms", 0)),
                mean=fmt_float(item.get("mean_ms", 0)),
                min=fmt_float(item.get("min_ms", 0)),
                max=fmt_float(item.get("max_ms", 0)),
            )
        )
    latency_table = "\n".join(latency_rows)

    config_rows = []
    config_order = [
        "channels",
        "rate_per_sec",
        "ramp_step",
        "ramp_interval_ms",
        "steady_duration_ms",
        "workers",
        "conn_timeout_ms",
        "rpc_timeout_ms",
        "report_interval_ms",
        "max_handshake_bytes",
        "max_record_bytes",
        "max_buffered_bytes",
        "stream_bytes",
        "fair_stream_bytes",
        "fair_streams",
        "max_pending_bytes",
        "idle_timeout_ms",
        "liveness_interval_ms",
        "liveness_timeout_ms",
        "connection_api",
        "rpc_stream_residency",
        "cleanup_interval_ms",
        "max_conns",
        "max_channels",
    ]
    for key in config_order:
        if key in config:
            config_rows.append(f"| {key} | {config[key]} |")
    config_table = "\n".join(config_rows)

    resources_table = "\n".join(
        [
            f"| max_heap_alloc_bytes | {fmt_int(resources.get('max_heap_alloc_bytes', 0))} |",
            f"| max_heap_inuse_bytes | {fmt_int(resources.get('max_heap_inuse_bytes', 0))} |",
            f"| max_sys_bytes | {fmt_int(resources.get('max_sys_bytes', 0))} |",
            f"| max_goroutines | {fmt_int(resources.get('max_goroutines', 0))} |",
            f"| baseline_goroutines | {fmt_int(resources.get('baseline_goroutines', 0))} |",
            f"| steady_state_goroutines | {fmt_int(resources.get('steady_state_goroutines', 0))} |",
            f"| after_close_goroutines | {fmt_int(resources.get('after_close_goroutines', 0))} |",
        ]
    )

    summary_table = "\n".join(
        [
            f"| attempts | {summary.get('attempts', 0)} |",
            f"| success | {summary.get('success', 0)} |",
            f"| failure | {summary.get('failure', 0)} |",
            f"| success_rate | {summary.get('success_rate', 0)} |",
            f"| duration_seconds | {fmt_float(summary.get('duration_seconds', 0), 4)} |",
            f"| peak_conn_per_sec | {summary.get('peak_conn_per_sec', 0)} |",
            f"| active_peak | {summary.get('active_peak', 0)} |",
        ]
    )

    throughput = float(streaming.get("throughput_mib_per_sec", 0))
    ttfb_ms = float(streaming.get("ttfb_ms", 0))
    throughput_regression = (
        (args.stream_throughput_baseline_mib_per_sec - throughput)
        / args.stream_throughput_baseline_mib_per_sec
        * 100
    )
    ttfb_regression = (
        ttfb_ms / args.stream_ttfb_baseline_ms - 1
    ) * 100
    fairness_completions = streaming.get("fairness_completion_ms", [])
    throughput_samples = streaming.get("throughput_samples_mib_per_sec", [])
    ttfb_samples = streaming.get("ttfb_samples_ms", [])
    streaming_table = "\n".join(
        [
            f"| transfer bytes | {fmt_int(streaming.get('bytes', 0))} |",
            f"| background connections | {fmt_int(streaming.get('background_connections', 0))} |",
            f"| transfer samples | {len(throughput_samples)} |",
            f"| throughput samples (MiB/s) | {', '.join(fmt_float(v, 3) for v in throughput_samples)} |",
            f"| transfer time (ms) | {fmt_float(streaming.get('transfer_ms', 0), 3)} |",
            f"| throughput (MiB/s) | {fmt_float(throughput, 3)} |",
            f"| throughput baseline (MiB/s) | {fmt_float(args.stream_throughput_baseline_mib_per_sec, 3)} |",
            f"| throughput regression | {fmt_float(throughput_regression, 2)}% |",
            f"| TTFB samples (ms) | {', '.join(fmt_float(v, 3) for v in ttfb_samples)} |",
            f"| TTFB (ms) | {fmt_float(ttfb_ms, 3)} |",
            f"| TTFB baseline (ms) | {fmt_float(args.stream_ttfb_baseline_ms, 3)} |",
            f"| TTFB regression | {fmt_float(ttfb_regression, 2)}% |",
            f"| concurrent equal streams | {streaming.get('concurrent_streams', 0)} |",
            f"| bytes per fairness stream | {fmt_int(streaming.get('fair_stream_bytes', 0))} |",
            f"| fairness completion times (ms) | {', '.join(fmt_float(v, 3) for v in fairness_completions)} |",
            f"| fairness median (ms) | {fmt_float(streaming.get('fairness_median_ms', 0), 3)} |",
            f"| fairness slowest (ms) | {fmt_float(streaming.get('fairness_slowest_ms', 0), 3)} |",
            f"| fairness slowest/median | {fmt_float(streaming.get('fairness_slowest_to_median_ratio', 0), 3)} |",
        ]
    )

    content = f"""# Benchmark Results

Run date: {run_date}

## Environment

{chr(10).join(env_lines)}

## Commands

```bash
# Go micro benches
{args.go_command}

# Go 64 KiB round-trip throughput gate
{args.go_roundtrip_command}

# TS micro benches
{args.ts_command}

# Load generator (high-level connection, loopback)
{args.loadgen_command}
```

## Go Benchmarks

### E2EE (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
{go_table}

### 64 KiB Round-Trip Throughput Gate

The baseline was measured from `origin/main` under the environment and Go constraints above.

| Samples | Baseline ns/op | Median ns/op | Regression | Allowed regression |
| ---: | ---: | ---: | ---: | ---: |
| {len(go_roundtrip_samples)} | {args.go_roundtrip_baseline_ns:.1f} | {go_roundtrip_median:.1f} | {go_roundtrip_regression:.2f}% | {args.go_roundtrip_max_regression_percent:.2f}% |

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
{tunnel_table}

## TypeScript Benchmarks

### E2EE Handshake (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
{handshake_table}

### E2EE Record (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
{record_table}

### Yamux (ms)

| Benchmark | ops/s (hz) | mean (ms) | p99 (ms) | max (ms) |
| --- | ---: | ---: | ---: | ---: |
{yamux_table}

## Load Generator

The load generator uses `client.Connect`; its RPC bootstrap stream remains open for the connection lifetime.

### Summary

| Metric | Value |
| --- | ---: |
{summary_table}

### Config

| Key | Value |
| --- | --- |
{config_table}

### Latency (ms)

| Stage | p50 | p95 | p99 | mean | min | max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
{latency_table}

### Streaming Transfer and Fairness

The manual machine-sensitive gate allows at most {args.stream_max_regression_percent:.2f}% throughput/TTFB regression, a peak heap of {fmt_int(args.max_heap_bytes)} bytes, and a slowest/median fairness ratio of {args.max_fairness_ratio:.2f}.
Each loadgen run reports the median of three 16 MiB transfers on one high-level connection and preserves all raw samples below.
Before timed transfers, an unmeasured 8 x 2 MiB concurrent probe samples heap usage and warms the streaming path.
The eight equal-size fairness streams are released from one barrier and measured from a shared start time.

| Metric | Value |
| --- | ---: |
{streaming_table}

### Resources (peak)

| Metric | Value |
| --- | ---: |
{resources_table}
"""

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    main()
