#!/usr/bin/env python3
import argparse
import json
import re
import statistics
import sys


def fail(message: str) -> None:
    print(f"benchmark gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_go_roundtrip_samples(path: str) -> list[float]:
    benchmark = re.compile(
        r"^BenchmarkSecureChannelRoundTrip/65536B-\d+\s+\d+\s+([0-9.]+) ns/op(?:\s|$)"
    )
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = benchmark.match(line.strip())
            if match is not None:
                samples.append(float(match.group(1)))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-roundtrip-output", required=True)
    parser.add_argument("--go-roundtrip-baseline-ns", type=float, required=True)
    parser.add_argument("--go-roundtrip-max-regression-percent", type=float, required=True)
    parser.add_argument("--ts-output", required=True)
    parser.add_argument("--loadgen-output", required=True)
    parser.add_argument("--expected-channels", type=int, required=True)
    args = parser.parse_args()

    roundtrip_samples = parse_go_roundtrip_samples(args.go_roundtrip_output)
    if len(roundtrip_samples) != 10:
        fail(f"go 64 KiB round-trip sample count={len(roundtrip_samples)}, want 10")
    roundtrip_median = statistics.median(roundtrip_samples)
    roundtrip_limit = args.go_roundtrip_baseline_ns * (
        1 + args.go_roundtrip_max_regression_percent / 100
    )
    if roundtrip_median > roundtrip_limit:
        regression = (roundtrip_median / args.go_roundtrip_baseline_ns - 1) * 100
        fail(
            "go 64 KiB round-trip median="
            f"{roundtrip_median:.1f}ns, baseline={args.go_roundtrip_baseline_ns:.1f}ns, "
            f"regression={regression:.2f}%, want <= {args.go_roundtrip_max_regression_percent:.2f}%"
        )

    with open(args.loadgen_output, "r", encoding="utf-8") as f:
        loadgen = json.load(f)
    summary = loadgen.get("summary", {})
    resources = loadgen.get("resources", {})

    if summary.get("success") != args.expected_channels or summary.get("failure") != 0:
        fail(f"loadgen success/failure={summary.get('success')}/{summary.get('failure')}")
    if args.expected_channels >= 1000 and resources.get("max_goroutines", 0) > 10500:
        fail(f"max goroutines={resources.get('max_goroutines')}, want <= 10500")
    baseline = resources.get("baseline_goroutines", 0)
    after_close = resources.get("after_close_goroutines", 0)
    if after_close > baseline + 16:
        fail(f"goroutines after close={after_close}, baseline={baseline}")
    config = loadgen.get("config", {})
    if args.expected_channels >= 1000:
        if config.get("liveness_interval_ms", 0) <= 0 or config.get("liveness_timeout_ms", 0) <= 0:
            fail("loadgen did not enable default tunnel liveness")
        if config.get("rpc_stream_residency") != "closed_after_verified_call":
            fail("loadgen RPC residency contract is missing")

    with open(args.ts_output, "r", encoding="utf-8") as f:
        ts_output = f.read()
    for operation in ("encrypt_65536B", "decrypt_65536B"):
        match = re.search(rf"^\s*·\s+{operation}\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(\S+)", ts_output, re.MULTILINE)
        if match is None:
            fail(f"missing TypeScript benchmark {operation}")
        maximum_ms = float(match.group(1))
        p99_ms = float(match.group(2))
        if p99_ms >= 5:
            fail(f"{operation} p99={p99_ms}ms, want <5ms")
        if maximum_ms > 50:
            fail(f"{operation} max={maximum_ms}ms, want <=50ms")

    print("benchmark gate OK")


if __name__ == "__main__":
    main()
