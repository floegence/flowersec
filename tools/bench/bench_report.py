#!/usr/bin/env python3
import argparse
import datetime as dt
import json
import re


def parse_go(path: str):
    pkg = ""
    out = {"e2ee": [], "tunnel": []}
    bench_re = re.compile(
        r"^(Benchmark\S+)\s+\d+\s+([0-9.]+) ns/op\s+([0-9.]+) B/op\s+(\d+) allocs/op$"
    )
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
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


def parse_ts(path: str):
    section = None
    out = {"handshake": [], "record": [], "yamux": []}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
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
            if len(parts) < 5:
                continue
            name = parts[0]
            hz = parts[1]
            mean = parts[4]
            out[section].append({"name": name, "hz": hz, "mean_ms": mean})
    return out


def fmt_int(v):
    return f"{int(v):,}"


def fmt_float(v, places=6):
    return f"{float(v):.{places}f}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-output", required=True)
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
    parser.add_argument("--ts-command", required=True)
    parser.add_argument("--loadgen-command", required=True)
    args = parser.parse_args()

    run_date = args.run_date or dt.datetime.now().strftime("%c")

    go_bench = parse_go(args.go_output)
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
        f"| {r['name']} | {r['hz']} | {r['mean_ms']} |"
        for r in ts_bench["handshake"]
    )
    record_table = "\n".join(
        f"| {r['name']} | {r['hz']} | {r['mean_ms']} |"
        for r in ts_bench["record"]
    )
    yamux_table = "\n".join(
        f"| {r['name']} | {r['hz']} | {r['mean_ms']} |"
        for r in ts_bench["yamux"]
    )

    summary = loadgen.get("summary", {})
    config = loadgen.get("config", {})
    latency = loadgen.get("latency", {})
    resources = loadgen.get("resources", {})

    latency_rows = []
    for stage in ["ws_open", "attach_send", "pair_ready", "handshake", "rpc_call"]:
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
        "mode",
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
        "max_pending_bytes",
        "idle_timeout_ms",
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

    content = f"""# Benchmark Results

Run date: {run_date}

## Environment

{chr(10).join(env_lines)}

## Commands

```bash
# Go micro benches
{args.go_command}

# TS micro benches
{args.ts_command}

# Load generator (full mode, loopback)
{args.loadgen_command}
```

## Go Benchmarks

### E2EE (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
{go_table}

### Tunnel Server Hot Path (ns/op, B/op, allocs/op)

| Benchmark | ns/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
{tunnel_table}

## TypeScript Benchmarks

### E2EE Handshake (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
{handshake_table}

### E2EE Record (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
{record_table}

### Yamux (ops/s, mean ms)

| Benchmark | ops/s (hz) | mean (ms) |
| --- | ---: | ---: |
{yamux_table}

## Load Generator (full mode)

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

### Resources (peak)

| Metric | Value |
| --- | ---: |
{resources_table}
"""

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(content)


if __name__ == "__main__":
    main()
