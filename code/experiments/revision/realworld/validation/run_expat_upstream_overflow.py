"""Run the pinned upstream CVE-2022-23852 regression oracle serially.

This is an independent API-level confirmation of the version-specific fix. It
does not claim a concrete memory-corruption witness: the harness deliberately
does not write the huge returned buffer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def wsl_path(path: Path) -> str:
    resolved = path.resolve()
    text = resolved.as_posix()
    if len(text) < 3 or text[1] != ":":
        raise ValueError(f"expected Windows drive path: {text}")
    return "/mnt/" + text[0].lower() + text[2:]


def decode_stream(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.count(b"\x00") > max(2, len(data) // 8):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def run_one(executable: Path, library: Path) -> dict:
    started = time.monotonic()
    command = [
        "wsl", "-d", "Ubuntu-24.04", "--exec", wsl_path(executable),
        wsl_path(library),
    ]
    completed = subprocess.run(command, capture_output=True, timeout=30)
    record = {
        "library": str(library.resolve()),
        "library_sha256": sha256(library),
        "command": command,
        "returncode": completed.returncode,
        "seconds": time.monotonic() - started,
        "stdout": decode_stream(completed.stdout),
        "stderr": decode_stream(completed.stderr),
    }
    if completed.returncode == 0:
        try:
            record["observation"] = json.loads(completed.stdout.strip())
        except json.JSONDecodeError as exc:
            record["parse_error"] = str(exc)
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = args.project / "expat_upstream_overflow_test.c"
    executable = args.out / "expat_upstream_overflow_test"
    compile_command = [
        "wsl", "-d", "Ubuntu-24.04", "--exec", "gcc", "-std=c11", "-O2", "-Wall", "-Wextra",
        "-Werror", "-o", wsl_path(executable), wsl_path(source), "-ldl",
    ]
    compiled = subprocess.run(compile_command, capture_output=True, timeout=30)
    compile_record = {
        "command": compile_command,
        "returncode": compiled.returncode,
        "stdout": decode_stream(compiled.stdout),
        "stderr": decode_stream(compiled.stderr),
    }
    if compiled.returncode != 0:
        (args.out / "compile.json").write_text(json.dumps(compile_record, indent=2) + "\n", encoding="utf-8")
        raise SystemExit("harness compilation failed")

    libraries = [
        ("2.4.3", "affected", args.project / ".." / "holdout_20261008" / "builds_expat_retry" / "expat-2.4.3" / "build" / "libexpat.so.1.8.3"),
        ("2.4.4", "fixed", args.project / ".." / "holdout_20261008" / "builds_expat_retry" / "expat-2.4.4" / "build" / "libexpat.so.1.8.4"),
    ]
    results = []
    for version, label, library in libraries:
        library = library.resolve()
        result = run_one(executable, library)
        result.update({"version": version, "label": label})
        observation = result.get("observation", {})
        returned = observation.get("buffer_returned")
        result["oracle"] = {
            "expected_fixed_behavior": label == "fixed" and returned is False,
            "legacy_vulnerable_behavior": label == "affected" and returned is True,
            "independent_confirmation": (
                result.get("returncode") == 0
                and ((label == "affected" and returned is True) or (label == "fixed" and returned is False))
            ),
        }
        results.append(result)
        # The two library executions are intentionally serial to avoid loader
        # cross-talk and to satisfy the project's external-request policy.
    (args.out / "compile.json").write_text(json.dumps(compile_record, indent=2) + "\n", encoding="utf-8")
    manifest = {
        "harness_source": str(source.resolve()),
        "harness_source_sha256": sha256(source),
        "executable": str(executable.resolve()),
        "results": results,
        "claim_boundary": "independent API-level reproduction; no concrete memory-corruption witness",
    }
    (args.out / "results.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if not all(row["oracle"]["independent_confirmation"] for row in results):
        raise SystemExit("upstream oracle did not reproduce on both versions")


if __name__ == "__main__":
    main()
