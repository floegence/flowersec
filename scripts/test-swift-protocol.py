"""Run an exact XCTest class and require a result for every discovered method."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


def main(suite):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", suite):
        sys.exit("expected one XCTest class name")
    root = Path(__file__).resolve().parents[1]
    args = ["swift", "test", "--package-path", str(root / "flowersec-swift"), "--cache-path",
            os.environ.get("SWIFTPM_CACHE_PATH", str(root / ".flowersec/swiftpm-cache")),
            "--only-use-versions-from-resolved-file", "--disable-swift-testing"]
    qualified = "ProtocolVectorTests." + suite
    prefix = qualified + "/"
    listed = subprocess.check_output([*args, "list"], text=True)
    expected = {name[len(prefix):] for name in listed.splitlines() if name.startswith(prefix)}
    if not expected:
        sys.exit(f"No XCTest methods discovered for {qualified}")
    with tempfile.TemporaryDirectory(prefix="flowersec-xctest-") as tmp:
        report = Path(tmp) / "results.xml"
        subprocess.run([*args, "--skip-build", "--filter", "^" + re.escape(prefix), "--parallel", "--num-workers", "1",
                        "--xunit-output", str(report)], check=True)
        cases = ET.parse(report).findall(".//testcase")
        passed = [case.get("name") for case in cases if case.get("classname") == qualified
                  and all(case.find(tag) is None for tag in ("failure", "error", "skipped"))]
        if set(passed) != expected or len(cases) != len(expected) or len(passed) != len(cases):
            sys.exit(f"XCTest results for {qualified}: expected {sorted(expected)}, passed {passed}")
        print(f"{qualified}: {len(passed)} passed: {', '.join(sorted(passed))}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: test-swift-protocol.py CLASS")
    main(sys.argv[1])
