#!/usr/bin/env python3
import argparse
import json
import math
import re
import statistics
import sys


def fail(message: str) -> None:
    print(f"benchmark gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def positive_finite_number(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError(f"{label} must be positive and finite")
    return float(value)


def regression_percent(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or value >= 100
    ):
        raise ValueError(f"{label} regression percent must be finite and in [0, 100)")
    return float(value)


def validate_peak_heap(peak_heap_bytes: int, max_heap_bytes: int) -> None:
    peak_heap_bytes = positive_finite_number(peak_heap_bytes, "peak heap")
    max_heap_bytes = positive_finite_number(max_heap_bytes, "maximum peak heap")
    if peak_heap_bytes > max_heap_bytes:
        raise ValueError(
            f"peak heap={peak_heap_bytes} bytes, want <= {max_heap_bytes} bytes"
        )


def validate_background_connections(metrics: dict, expected: int) -> None:
    value = metrics.get("background_connections")
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ValueError(
            f"streaming background connections={value}, want {expected}"
        )


def validate_streaming_metrics(
    metrics: dict,
    *,
    throughput_baseline: float,
    ttfb_baseline: float,
    max_regression_percent: float,
    max_fairness_ratio: float,
) -> None:
    throughput_baseline = positive_finite_number(
        throughput_baseline, "streaming throughput baseline"
    )
    ttfb_baseline = positive_finite_number(ttfb_baseline, "streaming TTFB baseline")
    max_regression_percent = regression_percent(
        max_regression_percent, "streaming gate"
    )
    max_fairness_ratio = positive_finite_number(
        max_fairness_ratio, "streaming fairness limit"
    )
    required = (
        "bytes",
        "throughput_mib_per_sec",
        "throughput_samples_mib_per_sec",
        "ttfb_ms",
        "ttfb_samples_ms",
        "concurrent_streams",
        "fair_stream_bytes",
        "fairness_completion_ms",
        "fairness_slowest_to_median_ratio",
    )
    for key in required:
        value = metrics.get(key)
        if value is None:
            raise ValueError(f"missing streaming metric {key.replace('_', ' ')}")

    scalar_keys = (
        "bytes",
        "throughput_mib_per_sec",
        "ttfb_ms",
        "concurrent_streams",
        "fair_stream_bytes",
        "fairness_slowest_to_median_ratio",
    )
    for key in scalar_keys:
        value = metrics[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"streaming metric {key} must be positive and finite")

    throughput_samples = validated_samples(
        metrics["throughput_samples_mib_per_sec"], 3, "throughput"
    )
    ttfb_samples = validated_samples(metrics["ttfb_samples_ms"], 3, "TTFB")
    fairness_samples = validated_samples(
        metrics["fairness_completion_ms"], 8, "fairness completion"
    )
    throughput = statistics.median(throughput_samples)
    ttfb = statistics.median(ttfb_samples)
    fairness_ratio = max(fairness_samples) / statistics.median(fairness_samples)
    derived = (
        ("throughput_mib_per_sec", throughput),
        ("ttfb_ms", ttfb),
        ("fairness_slowest_to_median_ratio", fairness_ratio),
    )
    for key, expected in derived:
        if not math.isclose(metrics[key], expected, rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError(f"streaming metric {key} does not match raw samples")

    if metrics["bytes"] != 16 * 1024 * 1024:
        raise ValueError(
            f"streaming transfer bytes={metrics['bytes']}, want {16 * 1024 * 1024}"
        )
    if metrics["concurrent_streams"] != 8:
        raise ValueError(
            f"concurrent streams={metrics['concurrent_streams']}, want 8"
        )
    if metrics["fair_stream_bytes"] != 2 * 1024 * 1024:
        raise ValueError(
            f"fair stream bytes={metrics['fair_stream_bytes']}, want {2 * 1024 * 1024}"
        )

    throughput_limit = throughput_baseline * (1 - max_regression_percent / 100)
    if throughput < throughput_limit:
        raise ValueError(
            "streaming throughput="
            f"{throughput:.2f} MiB/s, "
            f"baseline={throughput_baseline:.2f} MiB/s, "
            f"want >= {throughput_limit:.2f} MiB/s"
        )

    ttfb_limit = ttfb_baseline * (1 + max_regression_percent / 100)
    if ttfb > ttfb_limit:
        raise ValueError(
            f"streaming TTFB={ttfb:.2f}ms, "
            f"baseline={ttfb_baseline:.2f}ms, want <= {ttfb_limit:.2f}ms"
        )

    if fairness_ratio > max_fairness_ratio:
        raise ValueError(
            "stream fairness slowest/median="
            f"{fairness_ratio:.3f}, "
            f"want <= {max_fairness_ratio:.3f}"
        )


def validated_samples(value: object, count: int, label: str) -> list[float]:
    if not isinstance(value, list) or len(value) != count:
        raise ValueError(f"streaming {label} sample count must be {count}")
    if any(
        isinstance(sample, bool)
        or not isinstance(sample, (int, float))
        or not math.isfinite(sample)
        or sample <= 0
        for sample in value
    ):
        raise ValueError(f"streaming {label} samples must be positive finite numbers")
    return [float(sample) for sample in value]


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


def validate_roundtrip_samples(
    samples: object, *, baseline: float, max_regression_percent: float
) -> None:
    if not isinstance(samples, list) or len(samples) != 10:
        count = len(samples) if isinstance(samples, list) else 0
        raise ValueError(f"go 64 KiB round-trip sample count={count}, want 10")
    validated = [
        positive_finite_number(sample, "go 64 KiB round-trip sample")
        for sample in samples
    ]
    baseline = positive_finite_number(baseline, "go 64 KiB round-trip baseline")
    max_regression_percent = regression_percent(
        max_regression_percent, "go 64 KiB round-trip gate"
    )
    median = statistics.median(validated)
    limit = baseline * (1 + max_regression_percent / 100)
    if median > limit:
        regression = (median / baseline - 1) * 100
        raise ValueError(
            "go 64 KiB round-trip median="
            f"{median:.1f}ns, baseline={baseline:.1f}ns, "
            f"regression={regression:.2f}%, want <= {max_regression_percent:.2f}%"
        )


def validate_typescript_benchmarks(output: str) -> None:
    for operation in ("encrypt_65536B", "decrypt_65536B"):
        match = re.search(
            rf"^\s*·\s+{operation}\s+\S+\s+\S+\s+(\S+)\s+\S+\s+\S+\s+(\S+)",
            output,
            re.MULTILINE,
        )
        if match is None:
            raise ValueError(f"missing TypeScript benchmark {operation}")
        maximum_ms = positive_finite_number(
            float(match.group(1)), f"TypeScript benchmark {operation} maximum"
        )
        p99_ms = positive_finite_number(
            float(match.group(2)), f"TypeScript benchmark {operation} p99"
        )
        if p99_ms >= 5:
            raise ValueError(f"{operation} p99={p99_ms}ms, want <5ms")
        if maximum_ms > 50:
            raise ValueError(f"{operation} max={maximum_ms}ms, want <=50ms")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-roundtrip-output", required=True)
    parser.add_argument("--go-roundtrip-baseline-ns", type=float, required=True)
    parser.add_argument("--go-roundtrip-max-regression-percent", type=float, required=True)
    parser.add_argument("--ts-output", required=True)
    parser.add_argument("--loadgen-output", required=True)
    parser.add_argument("--expected-channels", type=int, required=True)
    parser.add_argument("--stream-throughput-baseline-mib-per-sec", type=float, required=True)
    parser.add_argument("--stream-ttfb-baseline-ms", type=float, required=True)
    parser.add_argument("--stream-max-regression-percent", type=float, required=True)
    parser.add_argument("--max-heap-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--max-fairness-ratio", type=float, default=2.0)
    args = parser.parse_args()

    roundtrip_samples = parse_go_roundtrip_samples(args.go_roundtrip_output)
    try:
        validate_roundtrip_samples(
            roundtrip_samples,
            baseline=args.go_roundtrip_baseline_ns,
            max_regression_percent=args.go_roundtrip_max_regression_percent,
        )
    except ValueError as err:
        fail(str(err))

    with open(args.loadgen_output, "r", encoding="utf-8") as f:
        loadgen = json.load(f)
    summary = loadgen.get("summary", {})
    resources = loadgen.get("resources", {})

    if summary.get("success") != args.expected_channels or summary.get("failure") != 0:
        fail(f"loadgen success/failure={summary.get('success')}/{summary.get('failure')}")
    baseline = resources.get("baseline_goroutines", 0)
    after_close = resources.get("after_close_goroutines", 0)
    if after_close > baseline + 16:
        fail(f"goroutines after close={after_close}, baseline={baseline}")
    config = loadgen.get("config", {})
    if args.expected_channels >= 1000:
        if config.get("liveness_interval_ms", 0) <= 0 or config.get("liveness_timeout_ms", 0) <= 0:
            fail("loadgen did not enable default tunnel liveness")
        if config.get("connection_api") != "client.Connect":
            fail("loadgen did not use the high-level client.Connect API")
        if config.get("rpc_stream_residency") != "connection_lifetime":
            fail("loadgen RPC residency contract is missing")

    streaming = loadgen.get("streaming", {})
    try:
        validate_peak_heap(resources.get("max_heap_alloc_bytes", 0), args.max_heap_bytes)
        validate_background_connections(streaming, args.expected_channels)
        validate_streaming_metrics(
            streaming,
            throughput_baseline=args.stream_throughput_baseline_mib_per_sec,
            ttfb_baseline=args.stream_ttfb_baseline_ms,
            max_regression_percent=args.stream_max_regression_percent,
            max_fairness_ratio=args.max_fairness_ratio,
        )
    except ValueError as err:
        fail(str(err))

    with open(args.ts_output, "r", encoding="utf-8") as f:
        ts_output = f.read()
    try:
        validate_typescript_benchmarks(ts_output)
    except ValueError as err:
        fail(str(err))

    print("benchmark gate OK")


if __name__ == "__main__":
    main()
