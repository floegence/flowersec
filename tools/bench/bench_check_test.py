import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_check


class StreamingGateTests(unittest.TestCase):
    def valid_metrics(self):
        return {
            "bytes": 16 * 1024 * 1024,
            "background_connections": 1000,
            "throughput_mib_per_sec": 100.0,
            "throughput_samples_mib_per_sec": [98.0, 100.0, 102.0],
            "ttfb_ms": 10.0,
            "ttfb_samples_ms": [9.5, 10.0, 10.5],
            "concurrent_streams": 8,
            "fair_stream_bytes": 2 * 1024 * 1024,
            "fairness_completion_ms": [8.0, 9.0, 10.0, 10.0, 10.0, 10.0, 11.0, 12.5],
            "fairness_slowest_to_median_ratio": 1.25,
        }

    def test_accepts_metrics_within_limits(self):
        bench_check.validate_background_connections(self.valid_metrics(), 1000)
        bench_check.validate_streaming_metrics(
            self.valid_metrics(),
            throughput_baseline=95.0,
            ttfb_baseline=9.0,
            max_regression_percent=15.0,
            max_fairness_ratio=2.0,
        )

    def test_rejects_missing_or_wrong_background_connection_count(self):
        for value in (None, 999):
            with self.subTest(value=value):
                metrics = self.valid_metrics()
                if value is None:
                    del metrics["background_connections"]
                else:
                    metrics["background_connections"] = value
                with self.assertRaisesRegex(ValueError, "background connections"):
                    bench_check.validate_background_connections(metrics, 1000)

    def test_rejects_missing_metrics(self):
        with self.assertRaisesRegex(ValueError, "missing streaming metric"):
            bench_check.validate_streaming_metrics(
                {},
                throughput_baseline=95.0,
                ttfb_baseline=9.0,
                max_regression_percent=15.0,
                max_fairness_ratio=2.0,
            )

    def test_rejects_throughput_and_ttfb_regression_over_fifteen_percent(self):
        metrics = self.valid_metrics()
        metrics["throughput_mib_per_sec"] = 84.9
        metrics["throughput_samples_mib_per_sec"] = [84.0, 84.9, 85.0]
        with self.assertRaisesRegex(ValueError, "throughput"):
            bench_check.validate_streaming_metrics(
                metrics,
                throughput_baseline=100.0,
                ttfb_baseline=10.0,
                max_regression_percent=15.0,
                max_fairness_ratio=2.0,
            )

        metrics = self.valid_metrics()
        metrics["ttfb_ms"] = 11.51
        metrics["ttfb_samples_ms"] = [11.4, 11.51, 11.6]
        with self.assertRaisesRegex(ValueError, "TTFB"):
            bench_check.validate_streaming_metrics(
                metrics,
                throughput_baseline=100.0,
                ttfb_baseline=10.0,
                max_regression_percent=15.0,
                max_fairness_ratio=2.0,
            )

    def test_rejects_heap_and_fairness_over_limits(self):
        with self.assertRaisesRegex(ValueError, "heap"):
            bench_check.validate_peak_heap(512 * 1024 * 1024 + 1, 512 * 1024 * 1024)

        metrics = self.valid_metrics()
        metrics["fairness_slowest_to_median_ratio"] = 2.01
        metrics["fairness_completion_ms"] = [1.0] * 7 + [2.01]
        with self.assertRaisesRegex(ValueError, "fairness"):
            bench_check.validate_streaming_metrics(
                metrics,
                throughput_baseline=100.0,
                ttfb_baseline=10.0,
                max_regression_percent=15.0,
                max_fairness_ratio=2.0,
            )

    def test_rejects_aggregates_that_do_not_match_raw_samples(self):
        mismatches = (
            ("throughput_mib_per_sec", 101.0),
            ("ttfb_ms", 10.1),
            ("fairness_slowest_to_median_ratio", 1.2),
        )
        for key, value in mismatches:
            with self.subTest(key=key):
                metrics = self.valid_metrics()
                metrics[key] = value
                with self.assertRaisesRegex(ValueError, "does not match raw samples"):
                    bench_check.validate_streaming_metrics(
                        metrics,
                        throughput_baseline=95.0,
                        ttfb_baseline=9.0,
                        max_regression_percent=15.0,
                        max_fairness_ratio=2.0,
                    )

    def test_rejects_invalid_or_incomplete_raw_samples(self):
        metrics = self.valid_metrics()
        metrics["throughput_samples_mib_per_sec"][0] = float("nan")
        with self.assertRaisesRegex(ValueError, "positive finite"):
            bench_check.validate_streaming_metrics(
                metrics,
                throughput_baseline=95.0,
                ttfb_baseline=9.0,
                max_regression_percent=15.0,
                max_fairness_ratio=2.0,
            )

        metrics = self.valid_metrics()
        metrics["fairness_completion_ms"].pop()
        with self.assertRaisesRegex(ValueError, "fairness completion sample count"):
            bench_check.validate_streaming_metrics(
                metrics,
                throughput_baseline=95.0,
                ttfb_baseline=9.0,
                max_regression_percent=15.0,
                max_fairness_ratio=2.0,
            )

    def test_rejects_nonfinite_or_boolean_gate_values(self):
        invalid_heap_values = (float("nan"), float("inf"), True)
        for value in invalid_heap_values:
            with self.subTest(heap=value):
                with self.assertRaisesRegex(ValueError, "heap"):
                    bench_check.validate_peak_heap(value, 512 * 1024 * 1024)

        invalid_gate_values = (float("nan"), float("inf"), True)
        for value in invalid_gate_values:
            for key in (
                "throughput_baseline",
                "ttfb_baseline",
                "max_regression_percent",
                "max_fairness_ratio",
            ):
                with self.subTest(key=key, value=value):
                    arguments = {
                        "throughput_baseline": 95.0,
                        "ttfb_baseline": 9.0,
                        "max_regression_percent": 15.0,
                        "max_fairness_ratio": 2.0,
                    }
                    arguments[key] = value
                    with self.assertRaisesRegex(ValueError, "gate|baseline|limit"):
                        bench_check.validate_streaming_metrics(self.valid_metrics(), **arguments)

    def test_rejects_invalid_regression_range(self):
        for value in (-0.01, 100.0):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "regression"):
                    bench_check.validate_streaming_metrics(
                        self.valid_metrics(),
                        throughput_baseline=95.0,
                        ttfb_baseline=9.0,
                        max_regression_percent=value,
                        max_fairness_ratio=2.0,
                    )

    def test_rejects_missing_or_wrong_fair_stream_size(self):
        for value in (None, 1):
            with self.subTest(value=value):
                metrics = self.valid_metrics()
                if value is None:
                    del metrics["fair_stream_bytes"]
                else:
                    metrics["fair_stream_bytes"] = value
                with self.assertRaisesRegex(ValueError, "fair stream bytes"):
                    bench_check.validate_streaming_metrics(
                        metrics,
                        throughput_baseline=95.0,
                        ttfb_baseline=9.0,
                        max_regression_percent=15.0,
                        max_fairness_ratio=2.0,
                    )


class BenchmarkInputTests(unittest.TestCase):
    def test_rejects_nonfinite_roundtrip_gate_values(self):
        for key in ("baseline", "max_regression_percent"):
            with self.subTest(key=key):
                arguments = {"baseline": 40_000.0, "max_regression_percent": 15.0}
                arguments[key] = float("nan")
                with self.assertRaisesRegex(ValueError, "round-trip"):
                    bench_check.validate_roundtrip_samples([40_000.0] * 10, **arguments)

    def test_rejects_nonfinite_typescript_measurements(self):
        output = "\n".join(
            (
                "· encrypt_65536B a b nan c d 1.0",
                "· decrypt_65536B a b 1.0 c d 1.0",
            )
        )
        with self.assertRaisesRegex(ValueError, "TypeScript benchmark"):
            bench_check.validate_typescript_benchmarks(output)


class LoadgenContractTests(unittest.TestCase):
    def test_accepts_peak_resources_within_limits(self):
        bench_check.validate_peak_resources(
            {
                "max_goroutines": 20_000,
                "max_sys_bytes": 384 * 1024 * 1024,
                "baseline_goroutines": 6,
                "steady_state_goroutines": 17_006,
                "after_close_goroutines": 7,
            },
            expected_channels=1_000,
            max_goroutines=20_000,
            max_sys_bytes=384 * 1024 * 1024,
            max_steady_goroutines_per_channel=17,
        )

    def test_rejects_peak_resources_over_limits(self):
        with self.assertRaisesRegex(ValueError, "goroutines"):
            bench_check.validate_peak_resources(
                {
                    "max_goroutines": 20_001,
                    "max_sys_bytes": 384 * 1024 * 1024,
                    "baseline_goroutines": 6,
                    "steady_state_goroutines": 17_006,
                    "after_close_goroutines": 7,
                },
                expected_channels=1_000,
                max_goroutines=20_000,
                max_sys_bytes=384 * 1024 * 1024,
                max_steady_goroutines_per_channel=17,
            )
        with self.assertRaisesRegex(ValueError, "system memory"):
            bench_check.validate_peak_resources(
                {
                    "max_goroutines": 20_000,
                    "max_sys_bytes": 384 * 1024 * 1024 + 1,
                    "baseline_goroutines": 6,
                    "steady_state_goroutines": 17_006,
                    "after_close_goroutines": 7,
                },
                expected_channels=1_000,
                max_goroutines=20_000,
                max_sys_bytes=384 * 1024 * 1024,
                max_steady_goroutines_per_channel=17,
            )
        with self.assertRaisesRegex(ValueError, "steady goroutines per channel"):
            bench_check.validate_peak_resources(
                {
                    "max_goroutines": 20_000,
                    "max_sys_bytes": 384 * 1024 * 1024,
                    "baseline_goroutines": 6,
                    "steady_state_goroutines": 17_007,
                    "after_close_goroutines": 7,
                },
                expected_channels=1_000,
                max_goroutines=20_000,
                max_sys_bytes=384 * 1024 * 1024,
                max_steady_goroutines_per_channel=17,
            )

    def test_rejects_missing_or_invalid_peak_resources(self):
        invalid_values = (None, 0, -1, True, float("nan"), float("inf"))
        for key in (
            "max_goroutines",
            "max_sys_bytes",
            "baseline_goroutines",
            "steady_state_goroutines",
            "after_close_goroutines",
        ):
            for value in invalid_values:
                with self.subTest(key=key, value=value):
                    resources = {
                        "max_goroutines": 20_000,
                        "max_sys_bytes": 384 * 1024 * 1024,
                        "baseline_goroutines": 6,
                        "steady_state_goroutines": 17_006,
                        "after_close_goroutines": 7,
                    }
                    if value is None:
                        del resources[key]
                    else:
                        resources[key] = value
                    with self.assertRaisesRegex(ValueError, "resource"):
                        bench_check.validate_peak_resources(
                            resources,
                            expected_channels=1_000,
                            max_goroutines=20_000,
                            max_sys_bytes=384 * 1024 * 1024,
                            max_steady_goroutines_per_channel=17,
                        )

    def test_rejects_invalid_peak_resource_gate_values(self):
        resources = {
            "max_goroutines": 20_000,
            "max_sys_bytes": 384 * 1024 * 1024,
            "baseline_goroutines": 6,
            "steady_state_goroutines": 16_006,
            "after_close_goroutines": 7,
        }
        for expected_channels in (0, -1, True, 1.5):
            with self.subTest(expected_channels=expected_channels):
                with self.assertRaisesRegex(ValueError, "resource channels"):
                    bench_check.validate_peak_resources(
                        resources,
                        expected_channels=expected_channels,
                        max_goroutines=20_000,
                        max_sys_bytes=384 * 1024 * 1024,
                        max_steady_goroutines_per_channel=17,
                    )
        for limit in (0, -1, True, float("nan"), float("inf")):
            with self.subTest(max_steady_goroutines_per_channel=limit):
                with self.assertRaisesRegex(ValueError, "steady goroutines"):
                    bench_check.validate_peak_resources(
                        resources,
                        expected_channels=1_000,
                        max_goroutines=20_000,
                        max_sys_bytes=384 * 1024 * 1024,
                        max_steady_goroutines_per_channel=limit,
                    )

    def test_rejects_inconsistent_goroutine_resources(self):
        valid = {
            "max_goroutines": 20_000,
            "max_sys_bytes": 384 * 1024 * 1024,
            "baseline_goroutines": 6,
            "steady_state_goroutines": 16_006,
            "after_close_goroutines": 7,
        }
        for key in ("baseline_goroutines", "steady_state_goroutines"):
            with self.subTest(key=key):
                resources = dict(valid)
                resources["max_goroutines"] = resources[key] - 1
                with self.assertRaisesRegex(ValueError, "peak goroutines"):
                    bench_check.validate_peak_resources(
                        resources,
                        expected_channels=1_000,
                        max_goroutines=20_000,
                        max_sys_bytes=384 * 1024 * 1024,
                        max_steady_goroutines_per_channel=17,
                    )

        resources = dict(valid)
        resources["after_close_goroutines"] = 23
        with self.assertRaisesRegex(ValueError, "after close"):
            bench_check.validate_peak_resources(
                resources,
                expected_channels=1_000,
                max_goroutines=20_000,
                max_sys_bytes=384 * 1024 * 1024,
                max_steady_goroutines_per_channel=17,
            )

    def test_removed_loadgen_modes_do_not_return(self):
        root = Path(__file__).resolve().parents[2]
        maintained_sources = [
            root / "flowersec-go/internal/cmd/flowersec-loadgen/main.go",
            root / "tools/bench/bench.sh",
            root / "tools/bench/bench_report.py",
        ]
        removed_terms = ("--mode", "attach-only", "handshake-only", "full mode")
        for path in maintained_sources:
            content = path.read_text(encoding="utf-8")
            for term in removed_terms:
                self.assertNotIn(term, content, f"{term!r} returned in {path.relative_to(root)}")

    def test_release_check_always_runs_the_full_interop_matrix(self):
        root = Path(__file__).resolve().parents[2]
        makefile = (root / "Makefile").read_text(encoding="utf-8")
        self.assertIn("\t$(MAKE) interop-stress-full\n", makefile)
        self.assertIn(
            'INTEROP_CELLS="go_to_go,typescript_to_go,swift_to_go,rust_to_go,go_to_typescript,go_to_swift,go_to_rust"',
            makefile,
        )

    def test_committed_benchmark_report_matches_streaming_workload(self):
        root = Path(__file__).resolve().parents[2]
        report = (root / "BENCH_RESULTS.md").read_text(encoding="utf-8")
        required_facts = (
            "| transfer bytes | 16,777,216 |",
            "| background connections | 1,000 |",
            "| transfer samples | 3 |",
            "| throughput baseline (MiB/s) | 279.770 |",
            "| concurrent equal streams | 8 |",
            "| bytes per fairness stream | 2,097,152 |",
            "--stream-benchmark-bytes=16777216",
            "--fair-stream-bytes=2097152",
            "--fair-streams=8",
            "| steady_state_goroutines |",
        )
        for fact in required_facts:
            self.assertIn(fact, report)
        self.assertNotIn("--mode", report)


if __name__ == "__main__":
    unittest.main()
