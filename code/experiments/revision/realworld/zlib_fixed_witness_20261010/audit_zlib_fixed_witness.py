"""Independent consistency audit for the zlib Z_FIXED witness artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE_ROOT = ROOT / "experiments" / "revision" / "realworld" / "projects_v0_4" / "source_trees"
MANIFEST = HERE / "runs" / "manifest_full.json"
TARGETED = HERE / "runs" / "targeted.json"
DEBUG = HERE / "runs" / "debug_targeted.json"
BOUNDARY = HERE / "runs" / "boundary_targeted.json"
DYNAMIC = HERE / "runs" / "dynamic_artifact_targeted.json"
HARNESS = HERE / "zlib_fixed_witness.c"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    failures: list[str] = []
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    rows = manifest.get("results", [])
    by_version = {v: [row for row in rows if row.get("version") == v]
                  for v in ("1.2.11", "1.2.12")}
    expected_cases = 4320
    for version, version_rows in by_version.items():
        if len(version_rows) != expected_cases:
            failures.append(f"{version}: {len(version_rows)} rows, expected {expected_cases}")
    failures_affected = [row for row in by_version["1.2.11"] if row["returncode"] != 0]
    failures_fixed = [row for row in by_version["1.2.12"] if row["returncode"] != 0]
    if len(failures_affected) != 1140:
        failures.append(f"affected failures: {len(failures_affected)}, expected 1140")
    if failures_fixed:
        failures.append(f"fixed failures: {len(failures_fixed)}")
    if manifest.get("harness_sha256") != sha256(HARNESS):
        failures.append("manifest harness hash does not match harness file")
    for version in ("1.2.11", "1.2.12"):
        source = SOURCE_ROOT / f"zlib-{version}"
        expected = manifest.get("source_root_sha256", {}).get(version, {})
        for name, recorded in expected.items():
            actual = sha256(source / name)
            if actual != recorded:
                failures.append(f"{version}/{name}: source hash mismatch")

    targeted = json.loads(TARGETED.read_text(encoding="utf-8"))["cases"]
    target_affected = [r for r in targeted if r["version"] == "1.2.11"]
    target_fixed = [r for r in targeted if r["version"] == "1.2.12"]
    if not target_affected or not all(r["returncode"] != 0 for r in target_affected):
        failures.append("targeted affected cases are not all failures")
    if not target_fixed or not all(r["returncode"] == 0 for r in target_fixed):
        failures.append("targeted fixed cases are not all clean")
    if not any("index 767 out of bounds" in line
               for row in target_affected for line in row.get("diagnostic_lines", [])):
        failures.append("targeted replay lacks the expected UBSan index diagnostic")

    debug = json.loads(DEBUG.read_text(encoding="utf-8"))
    debug_by_version = {r["version"]: r for r in debug}
    if debug_by_version.get("1.2.11", {}).get("run_rc") != 1:
        failures.append("debug affected witness did not fail")
    if not debug_by_version.get("1.2.11", {}).get("pendingBuf_overflow"):
        failures.append("debug affected witness lacks pendingBuf overflow")
    if debug_by_version.get("1.2.12", {}).get("run_rc") != 0:
        failures.append("debug fixed control did not pass")

    boundary = json.loads(BOUNDARY.read_text(encoding="utf-8"))
    boundary_map = {(row["version"], row["n"]): row for row in boundary}
    for version in ("1.2.11", "1.2.12"):
        for n in (31475, 31476):
            if (version, n) not in boundary_map:
                failures.append(f"missing threshold row {version}/{n}")
    if boundary_map[("1.2.11", 31475)]["returncode"] != 0:
        failures.append("1.2.11 clean boundary 31475 is not clean")
    if boundary_map[("1.2.11", 31476)]["returncode"] == 0:
        failures.append("1.2.11 witness boundary 31476 is clean")
    if any(boundary_map[("1.2.12", n)]["returncode"] != 0 for n in (31475, 31476)):
        failures.append("1.2.12 threshold controls are not clean")

    dynamic = json.loads(DYNAMIC.read_text(encoding="utf-8"))
    if any(row.get("build_rc") != 0 or row.get("run_rc") != 0 for row in dynamic):
        failures.append("saved stripped shared-library targeted smoke did not build/run cleanly")
    if {row.get("version") for row in dynamic} != {"1.2.11", "1.2.12"}:
        failures.append("saved stripped shared-library smoke lacks both versions")

    report = {
        "protocol": "independent-zlib-fixed-witness-audit-v1",
        "manifest_rows": len(rows),
        "rows_per_version": {version: len(version_rows) for version, version_rows in by_version.items()},
        "failures_per_version": {"1.2.11": len(failures_affected), "1.2.12": len(failures_fixed)},
        "harness_sha256": sha256(HARNESS),
        "status": "PASS" if not failures else "FAIL",
        "failures": failures,
    }
    out = HERE / "runs" / "AUDIT_ZLIB_FIXED_WITNESS_20261010.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
